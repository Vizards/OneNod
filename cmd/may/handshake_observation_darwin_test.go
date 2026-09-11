//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandshakeObservationDistinguishesLateACKAndConcurrentSuccess(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-observe-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	t.Setenv("HOME", root)
	if err := os.Mkdir(filepath.Join(root, userAgentDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", defaultAgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	lateACKWritten := make(chan struct{})
	var lateACKOnce sync.Once
	log := newTransportLog(tapTransportWriter{output: &output, onEvent: func(event transportLogEvent) {
		if event.TraceID == strings.Repeat("a", 32) && event.Component == "ssh-agent" && event.Phase == "binding-ack-write" && event.State == "finished" {
			lateACKOnce.Do(func() { close(lateACKWritten) })
		}
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls sync.Map
	agent := approvalAgent{deps: dependencies{transportLog: log, beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
		if _, replay := calls.LoadOrStore(request.TraceID, true); replay {
			return beholderWireResponse{}, errors.New("fixture nonce reused")
		}
		nonce, err := base64.RawURLEncoding.DecodeString(request.Nonce)
		if err != nil || len(nonce) != 32 {
			return beholderWireResponse{}, errors.New("fixture nonce invalid")
		}
		if nonce[0] == 1 {
			if request.TraceID != strings.Repeat("a", 32) {
				return beholderWireResponse{}, errors.New("concurrent trace swapped")
			}
			time.Sleep(2300 * time.Millisecond)
		} else if request.TraceID != strings.Repeat("b", 32) {
			return beholderWireResponse{}, errors.New("concurrent trace swapped")
		}
		return beholderWireResponse{SchemaVersion: 1, Accepted: true, Binding: strings.Repeat("fixture-binding-", 4)}, nil
	}}}
	serverDone := make(chan error, 1)
	go func() { serverDone <- agent.serveListener(ctx, listener) }()
	clientResults := make(chan error, 2)
	for index, trace := range []string{strings.Repeat("a", 32), strings.Repeat("b", 32)} {
		called := false
		diagnostic := &beholderDiagnostic{SchemaVersion: 1, TraceID: trace, Stage: "lease", Code: "lease-accepted", ModelCalled: &called}
		proxy, err := startBeholderClientProxyWithDiagnostic(bytes.Repeat([]byte{byte(index + 1)}, 32), diagnostic, log)
		if err != nil {
			t.Fatal(err)
		}
		proxy.expectPeer(os.Getpid())
		go func() {
			defer proxy.close()
			connection, err := net.Dial("unix", proxy.socketPath)
			if err != nil {
				clientResults <- err
				return
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			if err := writeBeholderAgentFrame(connection, []byte{11}); err != nil {
				clientResults <- err
				return
			}
			response, err := readBeholderAgentFrame(connection)
			if err == nil && !bytes.Equal(response, []byte{12, 0, 0, 0, 0}) {
				err = errors.New("ordinary Agent request changed")
			}
			clientResults <- err
		}()
	}
	for range 2 {
		if err := <-clientResults; err != nil {
			t.Error(err)
		}
	}
	// Wait for the accepted late result and its actual failed ACK write, before
	// stopping the Agent; cancellation must not manufacture the observed error.
	select {
	case <-lateACKWritten:
	case <-time.After(5 * time.Second):
		t.Fatal("late ACK write was never observed")
	}
	cancel()
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	events := readTransportEvents(t, log, &output)
	find := func(trace, component, phase string) transportLogEvent {
		t.Helper()
		for _, event := range events {
			if event.TraceID == trace && event.Component == component && event.Phase == phase && event.State == "finished" {
				return event
			}
		}
		t.Fatalf("missing %s/%s for trace %s", component, phase, trace)
		return transportLogEvent{}
	}
	slowTrace, fastTrace := strings.Repeat("a", 32), strings.Repeat("b", 32)
	slowRead := find(slowTrace, "ssh-client", "binding-read")
	fastRead := find(fastTrace, "ssh-client", "binding-read")
	lateACK := find(slowTrace, "ssh-agent", "binding-ack-write")
	coreResult := find(slowTrace, "ssh-agent", "core-binding-round-trip")
	if slowRead.Result != "timeout" || slowRead.ElapsedUS < 1900000 || slowRead.DeadlineAt == nil {
		t.Fatalf("missing real 2s timeout: %+v", slowRead)
	}
	if coreResult.Accepted == nil || !*coreResult.Accepted || coreResult.Result != "ok" {
		t.Fatal("Core acceptance was confused with delivery")
	}
	if lateACK.Accepted == nil || !*lateACK.Accepted || (lateACK.Result != "broken-pipe" && lateACK.Result != "connection-reset") {
		t.Fatalf("late ACK write was not recorded: %+v", lateACK)
	}
	if fastRead.Result != "ok" || !fastRead.ObservedAt.Before(slowRead.ObservedAt) {
		t.Fatal("slow handshake blocked the independent client")
	}
	if slowRead.ConnectionID == fastRead.ConnectionID || lateACK.ConnectionID != coreResult.ConnectionID {
		t.Fatal("connection identities were mixed")
	}
	clientConnections := map[string]bool{}
	for _, event := range events {
		if event.TraceID == slowTrace && event.Component == "ssh-client" {
			clientConnections[event.ConnectionID] = true
		}
	}
	if len(clientConnections) != 2 {
		t.Fatalf("fallback must have a separate connection, got %d", len(clientConnections))
	}
	if bytes.Contains(output.Bytes(), []byte("fixture-binding-")) || bytes.Contains(output.Bytes(), []byte("nonce")) {
		t.Fatal("capability data leaked to transport logs")
	}
	t.Logf("slow binding read=%s (%d us), Core accepted=%t, late ACK write=%s; concurrent fast read=%s; fallback connections=%d", slowRead.Result, slowRead.ElapsedUS, *coreResult.Accepted, lateACK.Result, fastRead.Result, len(clientConnections))
}

func TestObservedCoreRejectionRemainsUnbound(t *testing.T) {
	var output bytes.Buffer
	log := newTransportLog(&output)
	observation := newTransportObservation(log, "ssh-agent", strings.Repeat("c", 32))
	connection := approvalAgentConnection{observation: observation, agent: approvalAgent{deps: dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			return beholderWireResponse{SchemaVersion: 1, Accepted: false}, nil
		},
	}}}
	contents := []byte{0, 0, 0, 1}
	contents = appendBeholderAgentString(contents, bytes.Repeat([]byte{4}, 32))
	if _, err := connection.Extension(beholderBindingExtensionName, contents); err == nil || connection.state.beholderBinding != "" || connection.pendingACKAccepted {
		t.Fatal("Core rejection acquired a binding")
	}
	events := readTransportEvents(t, log, &output)
	if len(events) != 2 || events[1].Result != "rejected" || events[1].Accepted == nil || *events[1].Accepted {
		t.Fatal("Core rejection was recorded as a transport failure")
	}
}

func TestHandshakeResponseClassificationPreservesTheUnderlyingCause(t *testing.T) {
	for _, test := range []struct {
		response []byte
		err      error
		class    string
	}{
		{[]byte{6}, nil, "ok"}, {[]byte{5}, nil, "rejected"}, {[]byte{28}, nil, "rejected"},
		{[]byte{6, 0}, nil, "malformed-response"}, {nil, os.ErrDeadlineExceeded, "timeout"},
		{nil, errors.New("PRIVATE"), "io-error"},
	} {
		err := classifyBeholderExtensionResponse(test.response, test.err, "Beholder binding extension was rejected")
		if transportErrorClass(err) != test.class {
			t.Fatalf("wrong class: %s", transportErrorClass(err))
		}
		if test.err != nil && !errors.Is(err, test.err) {
			t.Fatal("transport cause was discarded")
		}
		if test.class == "timeout" {
			var timed net.Error
			if !errors.As(err, &timed) || !timed.Timeout() {
				t.Fatal("timeout no longer inspectable")
			}
		}
	}
}

func TestTransportObservationNeverChangesTheCoreWireRequest(t *testing.T) {
	var output bytes.Buffer
	log := newTransportLog(&output)
	defer log.close()
	request := beholderWireRequest{SchemaVersion: 1, Kind: "agent-binding-consume", TraceID: strings.Repeat("a", 32), Nonce: "fixture-nonce"}
	before, _ := json.Marshal(request)
	request.observation = newTransportObservation(log, "ssh-agent", request.TraceID)
	after, _ := json.Marshal(request)
	if !bytes.Equal(before, after) {
		t.Fatal("observation changed the authority protocol")
	}
}
