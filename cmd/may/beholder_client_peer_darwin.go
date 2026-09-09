//go:build darwin

package main

import (
	"errors"
	"net"
	"syscall"
)

const (
	beholderDarwinSOLLocal     = 0
	beholderDarwinLocalPeerPID = 0x002
)

func localUnixPeerPID(connection *net.UnixConn) (int, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	peerPID := 0
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		peerPID, socketErr = syscall.GetsockoptInt(
			int(descriptor), beholderDarwinSOLLocal, beholderDarwinLocalPeerPID,
		)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || peerPID <= 1 {
		return 0, errors.New("Beholder proxy peer PID is unavailable")
	}
	return peerPID, nil
}
