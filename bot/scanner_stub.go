//go:build !withscanners

package main

import "net"

const hasScanners = false

func dispatchScanners(_ net.Conn, _ string, _ []string) error {
	return nil
}
