//go:build darwin

package main

import (
	"errors"
	"net"
	"syscall"
)

const (
	darwinSOLLocal     = 0
	darwinLocalPeerPID = 0x002
)

func unixPeerPID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	peerPID := 0
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		peerPID, socketErr = syscall.GetsockoptInt(int(descriptor), darwinSOLLocal, darwinLocalPeerPID)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || peerPID <= 1 {
		return 0, errors.New("peer pid unavailable")
	}
	return peerPID, nil
}
