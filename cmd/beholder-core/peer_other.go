//go:build !darwin

package main

import (
	"errors"
	"net"
)

func unixPeerPID(connection *net.UnixConn) (int, error) {
	return 0, errors.New("peer pid unsupported")
}
