//go:build !withrootkit

package main

import (
	"fmt"
	"net"
)

// dispatchRootkit is a stub used when the withrootkit build tag is absent.
// It informs the operator that the rootkit module was not compiled in.
func dispatchRootkit(conn net.Conn, cmd string, fields []string) error {
	msg := "rootkit module not compiled in (rebuild with -tags withrootkit)"
	conn.Write([]byte(fmt.Sprintf(protoErrFmt, msg)))
	return fmt.Errorf("%s", msg)
}

