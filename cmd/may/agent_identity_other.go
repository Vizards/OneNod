//go:build !darwin

package main

import "net"

func detectLocalClient(_ net.Conn) clientObservation {
	return detectLocalClientFromPID(0)
}

func detectLocalClientContext(_ net.Conn) localClientContext {
	return unknownLocalClientContext()
}

func detectLocalClientFromPID(_ int) clientObservation {
	return clientObservation{
		Application: "Unknown local client",
		Source:      "unavailable",
	}
}

func unknownLocalClientContext() localClientContext {
	return localClientContext{Observation: detectLocalClientFromPID(0)}
}
