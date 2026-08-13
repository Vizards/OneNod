//go:build !darwin

package main

import (
	"errors"
	"net"
)

func sshPeerApplicationEvidence(net.Conn) (applicationEvidence, error) {
	return applicationEvidence{}, errors.New("verified application identity is unavailable on this platform")
}

func runtimeApplicationPlatform() string { return "unsupported" }

func unknownLocalClientContext() localClientContext {
	return localClientContext{Observation: clientObservation{
		Application: "Unknown local client",
		Identity:    unknownApplicationIdentity(),
		Source:      "unavailable",
	}}
}
