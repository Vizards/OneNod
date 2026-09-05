//go:build darwin

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientHostedProxyBindsAndForwardsOnTheOriginalUserProcess(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "beholder-client-proxy-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	t.Setenv("HOME", root)
	agentRoot := filepath.Join(root, userAgentDirectoryName)
	if err := os.Mkdir(agentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Listen("unix", filepath.Join(agentRoot, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	serverResult := make(chan error, 1)
	go func() {
		connection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer connection.Close()
		extension, readErr := readBeholderAgentFrame(connection)
		if readErr != nil || len(extension) < 2 || extension[0] != 27 {
			serverResult <- errors.New("binding extension was not first")
			return
		}
		reader := wireReader{value: extension[1:]}
		name, nameErr := reader.string()
		contents := append([]byte(nil), reader.value[reader.offset:]...)
		decoded, decodeErr := parseBeholderBindingExtension(contents)
		clear(contents)
		if nameErr != nil || string(name) != beholderBindingExtensionName || decodeErr != nil ||
			!bytes.Equal(decoded, nonce) {
			serverResult <- errors.New("binding extension was invalid")
			return
		}
		clear(decoded)
		if writeBeholderAgentFrame(connection, []byte{sshAgentSuccessResponse}) != nil {
			serverResult <- errors.New("binding acknowledgement failed")
			return
		}
		standard, standardErr := readBeholderAgentFrame(connection)
		if standardErr != nil || !bytes.Equal(standard, []byte{11}) {
			serverResult <- errors.New("standard request was not forwarded")
			return
		}
		serverResult <- writeBeholderAgentFrame(connection, []byte{12})
	}()
	proxy, err := startBeholderClientProxy(nonce)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	proxy.expectPeer(os.Getpid())
	connection, err := net.Dial("unix", proxy.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBeholderAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	response, err := readBeholderAgentFrame(connection)
	_ = connection.Close()
	if err != nil || !bytes.Equal(response, []byte{12}) {
		t.Fatalf("proxy response=%x err=%v", response, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestClientHostedProxyRejectsAConnectionFromTheWrongChildProcess(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "beholder-client-proxy-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	t.Setenv("HOME", root)
	agentRoot := filepath.Join(root, userAgentDirectoryName)
	if err := os.Mkdir(agentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Listen("unix", filepath.Join(agentRoot, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()

	proxy, err := startBeholderClientProxy(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	proxy.expectPeer(os.Getpid() + 1)
	connection, err := net.Dial("unix", proxy.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if err := writeBeholderAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	if _, err := readBeholderAgentFrame(connection); err == nil {
		t.Fatal("proxy forwarded a connection from an unexpected child process")
	}
	if unixListener, ok := upstream.(*net.UnixListener); ok {
		_ = unixListener.SetDeadline(time.Now().Add(50 * time.Millisecond))
	}
	if unexpected, err := upstream.Accept(); err == nil {
		_ = unexpected.Close()
		t.Fatal("proxy contacted OneNod after rejecting the downstream peer")
	}
}

func TestClientHostedProxyFallsBackToTheHumanControlledAgentPath(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "beholder-client-proxy-fallback-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	t.Setenv("HOME", root)
	agentRoot := filepath.Join(root, userAgentDirectoryName)
	if err := os.Mkdir(agentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Listen("unix", filepath.Join(agentRoot, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverResult := make(chan error, 1)
	go func() {
		bindingConnection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		bindingFrame, readErr := readBeholderAgentFrame(bindingConnection)
		if readErr != nil || len(bindingFrame) == 0 || bindingFrame[0] != 27 {
			_ = bindingConnection.Close()
			serverResult <- errors.New("binding extension was not attempted")
			return
		}
		if writeBeholderAgentFrame(bindingConnection, []byte{5}) != nil {
			_ = bindingConnection.Close()
			serverResult <- errors.New("binding rejection failed")
			return
		}
		_ = bindingConnection.Close()

		fallbackConnection, acceptErr := upstream.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer fallbackConnection.Close()
		standard, readErr := readBeholderAgentFrame(fallbackConnection)
		if readErr != nil || !bytes.Equal(standard, []byte{11}) {
			serverResult <- errors.New("standard request did not use the fallback connection")
			return
		}
		serverResult <- writeBeholderAgentFrame(fallbackConnection, []byte{12})
	}()

	proxy, err := startBeholderClientProxy(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.close()
	proxy.expectPeer(os.Getpid())
	connection, err := net.Dial("unix", proxy.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBeholderAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	response, err := readBeholderAgentFrame(connection)
	_ = connection.Close()
	if err != nil || !bytes.Equal(response, []byte{12}) {
		t.Fatalf("fallback response=%x err=%v", response, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
