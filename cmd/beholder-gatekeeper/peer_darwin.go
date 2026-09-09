//go:build darwin

package main

/*
#include <sys/types.h>
#include <unistd.h>

static int beholder_gatekeeper_peer_euid(int descriptor, uid_t *uid) {
	gid_t gid;
	return getpeereid(descriptor, uid, &gid);
}
*/
import "C"

import (
	"errors"
	"net"
)

func unixPeerUID(connection *net.UnixConn) (uint32, error) {
	if connection == nil {
		return 0, errors.New("peer connection unavailable")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid C.uid_t
	var peerErr error
	if err := raw.Control(func(descriptor uintptr) {
		if C.beholder_gatekeeper_peer_euid(C.int(descriptor), &uid) != 0 {
			peerErr = errors.New("peer credentials unavailable")
		}
	}); err != nil {
		return 0, err
	}
	if peerErr != nil {
		return 0, peerErr
	}
	return uint32(uid), nil
}
