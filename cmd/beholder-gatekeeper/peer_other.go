//go:build !darwin

package main

import (
	"errors"
	"net"
)

func unixPeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are unsupported on this platform")
}
