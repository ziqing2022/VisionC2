package main

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// detectTracerPid parses /proc/self/status to check if TracerPid is non-zero.
// A non-zero TracerPid indicates a debugger (gdb, strace, ltrace) is attached.
func detectTracerPid() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	f, err := os.Open(procPrefix + "self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid, err := strconv.Atoi(fields[1])
				if err == nil && pid != 0 {
					deoxys("detectTracerPid: Debugger attached (TracerPid: %d)", pid)
					return true
				}
			}
		}
	}
	return false
}

// detectPtraceAttach attempts to attach ptrace to current process.
// If another process is already attached as a debugger, PtraceAttach fails (EPERM).
func detectPtraceAttach() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	pid := os.Getpid()
	err := syscall.PtraceAttach(pid)
	if err != nil {
		deoxys("detectPtraceAttach: PtraceAttach failed (debugger likely attached): %v", err)
		return true
	}
	// Detach immediately if attach succeeded
	syscall.PtraceDetach(pid)
	return false
}

// detectTimingAnomaly measures execution time of a NOP loop across multiple runs.
// Debuggers or emulators stepping through code cause severe timing anomalies.
func detectTimingAnomaly() bool {
	var times [3]int64
	for i := 0; i < 3; i++ {
		start := time.Now()
		// Simple computation loop
		acc := 0
		for j := 0; j < 1000000; j++ {
			acc += j ^ (j >> 3)
		}
		_ = acc
		times[i] = time.Since(start).Nanoseconds()
		time.Sleep(5 * time.Millisecond)
	}

	minTime := times[0]
	maxTime := times[0]
	for _, t := range times[1:] {
		if t < minTime {
			minTime = t
		}
		if t > maxTime {
			maxTime = t
		}
	}

	if minTime > 0 && (maxTime/minTime > 10 || maxTime > 500*1000*1000) {
		deoxys("detectTimingAnomaly: Timing anomaly detected (min: %dns, max: %dns)", minTime, maxTime)
		return true
	}
	return false
}

// winntiExtra aggregates all extra anti-debug and timing checks.
// Returns true if any debugger or anomaly is detected.
func winntiExtra() bool {
	if detectTracerPid() {
		return true
	}
	if detectPtraceAttach() {
		return true
	}
	if detectTimingAnomaly() {
		return true
	}
	return false
}
