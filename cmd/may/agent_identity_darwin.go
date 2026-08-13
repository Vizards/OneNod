//go:build darwin

package main

import (
	"errors"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func sshPeerApplicationEvidence(connection net.Conn) (applicationEvidence, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return applicationEvidence{}, errors.New("SSH agent client is not a Unix connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return applicationEvidence{}, err
	}
	duplicate := -1
	var duplicateErr error
	if err := raw.Control(func(descriptor uintptr) {
		duplicate, duplicateErr = unix.Dup(int(descriptor))
		if duplicateErr == nil {
			unix.CloseOnExec(duplicate)
		}
	}); err != nil {
		return applicationEvidence{}, err
	}
	if duplicateErr != nil || duplicate < 0 {
		return applicationEvidence{}, errors.New("duplicate SSH agent peer socket failed")
	}
	file := os.NewFile(uintptr(duplicate), "onenod-ssh-peer")
	if file == nil {
		_ = unix.Close(duplicate)
		return applicationEvidence{}, errors.New("open duplicated SSH agent peer socket failed")
	}
	return applicationEvidence{Kind: applicationEvidenceSSHPeer, PeerFile: file}, nil
}

func runtimeApplicationPlatform() string { return "macos" }

func unknownLocalClientContext() localClientContext {
	return localClientContext{Observation: clientObservation{
		Application: "Unknown local client",
		Identity:    unknownApplicationIdentity(),
		Source:      "unavailable",
	}}
}
