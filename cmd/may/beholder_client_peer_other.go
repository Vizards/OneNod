//go:build !darwin

package main

import (
	"errors"
	"net"
)

func localUnixPeerPID(*net.UnixConn) (int, error) {
	return 0, errors.New("Beholder client proxy requires macOS peer credentials")
}
