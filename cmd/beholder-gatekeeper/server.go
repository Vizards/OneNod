package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

func serveGatekeeper(
	ctx context.Context,
	socketPath string,
	service *gatekeeperService,
	allowedPeerUID uint32,
) error {
	if ctx == nil || service == nil || !filepath.IsAbs(socketPath) {
		return errors.New("invalid Gatekeeper server configuration")
	}
	parent := filepath.Dir(socketPath)
	if err := os.MkdirAll(parent, 0o700); err != nil || os.Chmod(parent, 0o700) != nil {
		return errors.New("create private Gatekeeper socket parent failed")
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("Gatekeeper socket path is occupied")
		}
		connection, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if dialErr == nil {
			connection.Close()
			return errors.New("another Gatekeeper is already running")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) || os.Remove(socketPath) != nil {
			return errors.New("remove stale Gatekeeper socket failed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect Gatekeeper socket failed")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if os.Chmod(socketPath, 0o600) != nil {
		return errors.New("set Gatekeeper socket mode failed")
	}
	var connections sync.Map
	var group sync.WaitGroup
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
			connections.Range(func(key, _ any) bool {
				key.(*net.UnixConn).Close()
				return true
			})
		case <-done:
		}
	}()
	defer func() {
		close(done)
		listener.Close()
		connections.Range(func(key, _ any) bool {
			key.(*net.UnixConn).Close()
			return true
		})
		group.Wait()
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		connections.Store(connection, struct{}{})
		group.Add(1)
		go func() {
			defer group.Done()
			defer connections.Delete(connection)
			defer connection.Close()
			peerUID, peerErr := unixPeerUID(connection)
			if peerErr != nil || peerUID != allowedPeerUID {
				return
			}
			handleGatekeeperConnection(connection, service)
		}()
	}
}

func handleGatekeeperConnection(connection *net.UnixConn, service *gatekeeperService) {
	localDeadline := time.Duration(service.config.Invocation.TimeoutMS)*time.Millisecond + 5*time.Second
	if comparisonDeadline := time.Duration(service.config.Comparison.TimeoutMS)*time.Millisecond + 5*time.Second; comparisonDeadline > localDeadline {
		localDeadline = comparisonDeadline
	}
	_ = connection.SetDeadline(time.Now().Add(localDeadline))
	decoder := json.NewDecoder(io.LimitReader(connection, maximumLocalWireSize+1))
	var request localDecisionRequest
	if decoder.Decode(&request) != nil {
		_ = json.NewEncoder(connection).Encode(localDecisionResponse{
			SchemaVersion: gatekeeperWireSchemaVersion,
			Decision:      "escalate", Reason: "The local Gatekeeper request was invalid.",
			ErrorCode: stringPointer("invalid-local-wire-request"),
		})
		clearLocalDecisionRequest(&request)
		return
	}
	response := service.decide(request)
	_ = json.NewEncoder(connection).Encode(response)
}
