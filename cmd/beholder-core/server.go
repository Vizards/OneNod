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

func serveBroker(socketPath string, broker *broker, maximumConnections int, idleTimeout time.Duration) (brokerSummary, error) {
	return serveBrokerWithTransport(socketPath, broker, nil, maximumConnections, idleTimeout)
}

func serveBrokerWithTransport(
	socketPath string,
	broker *broker,
	transport *transportCoordinator,
	maximumConnections int,
	idleTimeout time.Duration,
) (brokerSummary, error) {
	summary := brokerSummary{SchemaVersion: protocolSchemaVersion, ConnectionErrors: make(map[string]int)}
	if !filepath.IsAbs(socketPath) || broker == nil || maximumConnections <= 0 || maximumConnections > 1000 ||
		idleTimeout <= 0 || idleTimeout > 10*time.Minute {
		return summary, errors.New("invalid server configuration")
	}
	listener, cleanup, err := openBrokerListener(socketPath, broker)
	if err != nil {
		return summary, err
	}
	defer cleanup()

	for summary.Connections < maximumConnections {
		if err := listener.SetDeadline(time.Now().Add(idleTimeout)); err != nil {
			return summary, err
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				summary.ErrorCode = stringPointer("idle-timeout")
				return summary, nil
			}
			return summary, err
		}
		summary.Connections++
		kind, handleErr := handleBrokerConnectionWithTransport(connection, broker, transport)
		_ = connection.Close()
		if handleErr != nil {
			summary.ConnectionErrors[brokerConnectionErrorCode(handleErr)]++
			continue
		}
		switch kind {
		case "prompt-observation":
			summary.PromptRegistrations++
		case "host-observation":
			summary.HostRegistrations++
		case "execution-root":
			summary.ExecutionRegistrations++
		case "request-observation":
			summary.RequestChecks++
		case "ssh-proxy-lease", "ssh-client-lease", "agent-binding-consume", "agent-operation", "direct-operation":
			summary.RequestChecks++
		}
	}
	return summary, nil
}

func serveBrokerDaemon(
	ctx context.Context,
	socketPath string,
	broker *broker,
	transport *transportCoordinator,
) error {
	if ctx == nil || !filepath.IsAbs(socketPath) || broker == nil {
		return errors.New("invalid daemon server configuration")
	}
	listener, cleanup, err := openBrokerListener(socketPath, broker)
	if err != nil {
		return err
	}
	defer cleanup()
	var connections sync.Map
	var group sync.WaitGroup
	shutdownComplete := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			connections.Range(func(key, _ any) bool {
				_ = key.(*net.UnixConn).Close()
				return true
			})
		case <-shutdownComplete:
		}
	}()
	defer func() {
		close(shutdownComplete)
		_ = listener.Close()
		connections.Range(func(key, _ any) bool {
			_ = key.(*net.UnixConn).Close()
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
			_, _ = handleBrokerConnectionWithTransport(connection, broker, transport)
		}()
	}
}

func openBrokerListener(
	socketPath string,
	broker *broker,
) (*net.UnixListener, func(), error) {
	if !filepath.IsAbs(socketPath) || broker == nil {
		return nil, nil, errors.New("invalid broker listener configuration")
	}
	parentInfo, err := os.Lstat(filepath.Dir(socketPath))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("socket parent is invalid")
	}
	if broker.trustMode == "production" {
		stat, ok := parentInfo.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
			return nil, nil, errors.New("production socket parent is not root-controlled")
		}
	} else if parentInfo.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.New("socket parent is not private")
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, errors.New("socket path already exists")
		}
		if broker.trustMode == "production" {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || broker.socketOwnerUID < 0 || stat.Uid != uint32(broker.socketOwnerUID) ||
				info.Mode().Perm() != 0o600 {
				return nil, nil, errors.New("existing production socket identity is invalid")
			}
		}
		connection, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, nil, errors.New("another broker is already listening")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) || os.Remove(socketPath) != nil {
			return nil, nil, errors.New("remove stale broker socket failed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.New("inspect socket path failed")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() {
		_ = listener.Close()
		if info, statErr := os.Lstat(socketPath); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(socketPath)
		}
	}
	if broker.socketOwnerUID >= 0 {
		if os.Geteuid() != 0 || os.Chown(socketPath, broker.socketOwnerUID, -1) != nil {
			cleanup()
			return nil, nil, errors.New("production socket ownership failed")
		}
	}
	if os.Chmod(socketPath, 0o600) != nil {
		cleanup()
		return nil, nil, errors.New("socket privacy failed")
	}
	return listener, cleanup, nil
}

type brokerConnectionFailure struct {
	code string
}

func (failure brokerConnectionFailure) Error() string {
	return failure.code
}

func brokerConnectionErrorCode(err error) string {
	var failure brokerConnectionFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return "broker-handler-failed"
}

func handleBrokerConnection(connection *net.UnixConn, broker *broker) (string, error) {
	return handleBrokerConnectionWithTransport(connection, broker, nil)
}

func handleBrokerConnectionWithTransport(
	connection *net.UnixConn,
	broker *broker,
	transport *transportCoordinator,
) (string, error) {
	deadline := 5 * time.Second
	if broker != nil && broker.authority != nil {
		deadline = 20 * time.Second
	}
	_ = connection.SetDeadline(time.Now().Add(deadline))
	peerPID, err := unixPeerPID(connection)
	if err != nil {
		return "", brokerConnectionFailure{code: "peer-pid-unavailable"}
	}
	peer, err := captureProcessChain(peerPID)
	if err != nil {
		return "", brokerConnectionFailure{code: "peer-process-unavailable"}
	}
	if broker.trustMode == "production" &&
		(len(peer.Nodes) == 0 || peer.Nodes[0].UID != broker.allowedUID ||
			peer.Nodes[0].RealUID != broker.allowedUID) {
		return "", brokerConnectionFailure{code: "peer-uid-mismatch"}
	}
	decoder := json.NewDecoder(io.LimitReader(connection, maximumWireSize+1))
	var request wireRequest
	if decoder.Decode(&request) != nil || request.SchemaVersion != protocolSchemaVersion {
		return "", brokerConnectionFailure{code: "invalid-wire-request"}
	}
	if request.Kind != "execution-lifecycle" && request.Lifecycle != nil {
		return "", brokerConnectionFailure{code: "invalid-wire-request"}
	}
	if request.Kind != "human-outcome" && (request.EvidenceID != "" || request.HumanOutcome != nil) {
		return "", brokerConnectionFailure{code: "invalid-wire-request"}
	}
	if request.TraceID != "" && !validDiagnosticTraceID(request.TraceID) {
		return "", brokerConnectionFailure{code: "invalid-diagnostic-trace"}
	}
	auditThreadID := request.ThreadID
	if request.Host != nil {
		auditThreadID = request.Host.SessionID
	}
	if request.Prompt != nil {
		auditThreadID = request.Prompt.SessionID
	}
	var response wireResponse
	defer response.clearTransient()
	defer func() { logCoreDiagnostic(request.Kind, request.TraceID, auditThreadID, response) }()
	switch request.Kind {
	case "execution-lifecycle":
		if request.Lifecycle == nil || request.Host != nil || request.Prompt != nil || request.Request != nil || !emptyTransportWireFields(request) {
			return "", brokerConnectionFailure{code: "invalid-lifecycle-request"}
		}
		auditThreadID = request.Lifecycle.SessionID
		response = broker.observeLifecycle(*request.Lifecycle, peer)
	case "prompt-observation":
		if request.Prompt == nil || request.Host != nil || request.Request != nil ||
			!emptyTransportWireFields(request) {
			return "", brokerConnectionFailure{code: "invalid-prompt-request"}
		}
		response = broker.registerPrompt(*request.Prompt, peer)
		clear(request.Prompt.Prompt)
	case "host-observation":
		if request.Host == nil || request.Prompt != nil || request.Request != nil ||
			!emptyTransportWireFields(request) {
			return "", brokerConnectionFailure{code: "invalid-host-request"}
		}
		response = broker.registerHost(*request.Host, peer)
		clear(request.Host.ToolInput)
	case "execution-root":
		if request.ThreadID == "" || request.ToolRef == "" || request.Prompt != nil ||
			request.Host != nil || request.Request != nil || request.Purpose != "" || request.Nonce != "" ||
			request.Binding != "" || request.RequesterDeviceID != "" || request.Operation != nil {
			return "", brokerConnectionFailure{code: "invalid-execution-root"}
		}
		response = broker.registerExecutionRoot(request.ToolRef, request.ThreadID, peer)
		request.ToolRef, request.ThreadID = "", ""
	case "request-observation":
		if request.Request == nil || request.Prompt != nil || request.Host != nil ||
			request.ThreadID != "" || request.ToolRef != "" || request.Purpose != "" || request.Nonce != "" ||
			request.Binding != "" || request.RequesterDeviceID != "" || request.Operation != nil {
			return "", brokerConnectionFailure{code: "invalid-request-observation"}
		}
		response = broker.checkRequest(*request.Request, peer)
	case "ssh-proxy-lease":
		if transport == nil || request.ThreadID == "" || request.Purpose == "" ||
			request.ToolRef != "" || request.Nonce != "" || request.Binding != "" || request.RequesterDeviceID != "" || request.Operation != nil ||
			request.Prompt != nil || request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-lease-request"}
		}
		response = transport.issueLease(request.ThreadID, request.Purpose, peer)
		request.ThreadID, request.Purpose = "", ""
	case "ssh-client-lease":
		if transport == nil || request.ThreadID == "" || request.Purpose == "" ||
			request.ToolRef != "" || request.Nonce != "" || request.Binding != "" || request.RequesterDeviceID != "" || request.Operation != nil ||
			request.Prompt != nil || request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-client-lease-request"}
		}
		response = transport.issueClientLease(request.ThreadID, request.Purpose, peer)
		request.ThreadID, request.Purpose = "", ""
	case "agent-binding-consume":
		if transport == nil || request.Nonce == "" || request.ThreadID != "" ||
			request.ToolRef != "" || request.Purpose != "" || request.Binding != "" || request.RequesterDeviceID != "" || request.Operation != nil ||
			request.Prompt != nil || request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-binding-request"}
		}
		response = transport.consumeBinding(request.Nonce, peer)
		request.Nonce = ""
	case "agent-operation":
		if transport == nil || request.Binding == "" || request.Operation == nil ||
			request.ThreadID != "" || request.ToolRef != "" || request.Purpose != "" || request.Nonce != "" ||
			request.Prompt != nil || request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-agent-operation"}
		}
		response = transport.observeAgentOperation(
			request.Binding, *request.Operation, peer, request.RequesterDeviceID,
		)
		request.Binding = ""
		request.RequesterDeviceID = ""
	case "direct-operation":
		if transport == nil || request.ThreadID == "" || request.Nonce == "" || request.Operation == nil ||
			request.ToolRef != "" || request.Purpose != "" || request.Binding != "" || request.Prompt != nil ||
			request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-direct-operation"}
		}
		response = transport.checkDirectOperation(
			request.ThreadID, request.Nonce, *request.Operation, peer, request.RequesterDeviceID,
		)
		request.ThreadID, request.Nonce = "", ""
		request.RequesterDeviceID = ""
	case "human-outcome":
		if transport == nil || request.EvidenceID == "" || request.Operation == nil || request.HumanOutcome == nil ||
			request.ThreadID != "" || request.ToolRef != "" || request.Purpose != "" || request.Nonce != "" ||
			request.Binding != "" || request.RequesterDeviceID != "" || request.Prompt != nil || request.Host != nil || request.Request != nil {
			return "", brokerConnectionFailure{code: "invalid-human-outcome"}
		}
		response = transport.recordHumanOutcome(
			request.EvidenceID, *request.Operation, *request.HumanOutcome, peer,
		)
		request.EvidenceID = ""
		request.HumanOutcome = nil
	default:
		return "", brokerConnectionFailure{code: "unsupported-wire-request"}
	}
	if err := json.NewEncoder(connection).Encode(response); err != nil {
		return "", brokerConnectionFailure{code: "response-write-failed"}
	}
	return request.Kind, nil
}

func emptyTransportWireFields(request wireRequest) bool {
	return request.ThreadID == "" && request.ToolRef == "" && request.Purpose == "" && request.Nonce == "" &&
		request.Binding == "" && request.RequesterDeviceID == "" && request.Operation == nil &&
		request.EvidenceID == "" && request.HumanOutcome == nil
}
