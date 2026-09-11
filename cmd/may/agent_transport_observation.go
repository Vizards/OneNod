package main

import (
	"io"
	"net"
)

func transportPeerPID(connection net.Conn) int {
	if unix, ok := connection.(*net.UnixConn); ok {
		pid, _ := localUnixPeerPID(unix)
		return pid
	}
	return 0
}

// Observe the actual frame writes performed by sshagent.ServeAgent. Returning
// success from Extension only prepares an ACK; it does not prove delivery.
// The library writes the four-byte header and one-byte extension status in
// separate calls. No protocol contents are recorded or changed here.
type observedAgentStream struct {
	net.Conn
	owner         *approvalAgentConnection
	ack           *transportSpan
	headerWritten bool
}

func (stream *observedAgentStream) Write(value []byte) (int, error) {
	observing := stream.owner.pendingACK != ""
	if observing && !stream.headerWritten {
		stream.ack = stream.owner.observation.begin(stream.owner.pendingACK+"-ack-write", 0)
	}
	written, err := stream.Conn.Write(value)
	if observing {
		observedErr := err
		if observedErr == nil && written != len(value) {
			observedErr = io.ErrShortWrite
		}
		if observedErr != nil || stream.headerWritten {
			stream.finishACK(observedErr)
		} else {
			stream.headerWritten = true
		}
	}
	return written, err
}

func (stream *observedAgentStream) finishACK(err error) {
	if stream.owner.pendingACK != "" {
		stream.ack.finishResult(transportErrorClass(err), &stream.owner.pendingACKAccepted)
		stream.ack = nil
		stream.headerWritten = false
		stream.owner.pendingACK = ""
	}
}
