package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonStopsOnCancellationAndRemovesItsSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-daemon-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerWithKey(
		root, "fixture", "", "", time.Minute, bytes.Repeat([]byte{9}, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	socketPath := filepath.Join(root, "core.sock")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- serveBrokerDaemon(ctx, socketPath, core, nil) }()
	deadline := time.Now().Add(time.Second)
	for {
		connection, dialErr := net.DialTimeout("unix", socketPath, 20*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon socket did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop after cancellation")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("daemon left its socket behind")
	}
}

func TestBrokerRecoversOnlyAStaleSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-stale-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerWithKey(
		root, "fixture", "", "", time.Minute, bytes.Repeat([]byte{7}, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	socketPath := filepath.Join(root, "core.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	listener, cleanup, err := openBrokerListener(socketPath, core)
	if err != nil {
		t.Fatalf("stale socket was not recovered: %v", err)
	}
	cleanup()
	if listener == nil {
		t.Fatal("stale socket recovery did not create a listener")
	}
}

func TestBrokerDoesNotReplaceALiveSocket(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-live-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerWithKey(
		root, "fixture", "", "", time.Minute, bytes.Repeat([]byte{8}, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	socketPath := filepath.Join(root, "core.sock")
	live, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	if _, _, err := openBrokerListener(socketPath, core); err == nil {
		t.Fatal("live broker socket was replaced")
	}
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("live broker socket was removed: %v", err)
	}
}
