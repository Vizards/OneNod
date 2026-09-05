//go:build !darwin

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientHostedProxyRejectsUnsupportedPeerCredentials(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "beholder-unsupported-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	t.Setenv("HOME", root)
	agentRoot := filepath.Join(root, userAgentDirectoryName)
	if err := os.Mkdir(agentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	upstream, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: filepath.Join(agentRoot, "agent.sock"), Net: "unix",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	proxy, err := startBeholderClientProxy(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	proxy.expectPeer(os.Getpid())
	connection, err := net.Dial("unix", proxy.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := readBeholderAgentFrame(connection); err == nil {
		t.Fatal("proxy accepted a connection without supported peer credentials")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("proxy did not promptly reject unsupported peer credentials")
	}
	select {
	case <-proxy.done:
	case <-time.After(time.Second):
		t.Fatal("proxy did not stop after rejecting unsupported peer credentials")
	}
	if err := upstream.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if unexpected, err := upstream.Accept(); err == nil {
		_ = unexpected.Close()
		t.Fatal("proxy contacted OneNod without supported peer credentials")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatalf("check for unexpected upstream connection: %v", err)
	}
}
