//go:build !withsniffer

package main

import "net"

const hasSniffer = false

func dispatchSniffer(_ net.Conn, _ string, _ []string) error {
	return nil
}
