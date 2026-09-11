package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type failingCoreResponseWriter struct{}

func (failingCoreResponseWriter) Write([]byte) (int, error) { return 0, syscall.EPIPE }

func TestCoreDiagnosticsSeparateAcceptanceFromResponseWrite(t *testing.T) {
	for _, broken := range []bool{false, true} {
		var logOutput, wireOutput bytes.Buffer
		log := newTransportLog(&logOutput)
		trace := strings.Repeat("a", 32)
		observation := newTransportObservation(log, "core", trace)
		response := wireResponse{SchemaVersion: 1, Accepted: true, Binding: "PRIVATE-FIXTURE-BINDING"}
		var writer io.Writer = &wireOutput
		if broken {
			writer = failingCoreResponseWriter{}
		}
		err := writeObservedCoreResponse(writer, response, observation, 20*time.Second, time.Now().Add(20*time.Second))
		events := readTransportEvents(t, log, &logOutput)
		want := "ok"
		if broken {
			want = "broken-pipe"
		}
		if transportErrorClass(err) != want || len(events) != 2 || events[1].Result != want || events[1].Accepted == nil || !*events[1].Accepted {
			t.Fatal("acceptance and delivery became indistinguishable")
		}
		var summary bytes.Buffer
		completion := coreTransportCompletion{ConnectionID: observation.connectionID, ResponseWriteResult: want}
		if broken {
			completion.HandlerErrorCode = "response-write-failed"
		}
		writeCoreDiagnostic(&summary, "agent-binding-consume", trace, "", response, completion)
		var record struct {
			Accepted     bool
			Result       string `json:"response_write_result"`
			ConnectionID string `json:"transport_connection_id"`
		}
		if json.Unmarshal(summary.Bytes(), &record) != nil || !record.Accepted || record.Result != want || record.ConnectionID != observation.connectionID {
			t.Fatal("summary did not preserve delivery outcome")
		}
		if bytes.Contains(summary.Bytes(), []byte("PRIVATE")) || bytes.Contains(logOutput.Bytes(), []byte("PRIVATE")) {
			t.Fatal("binding leaked into diagnostics")
		}
	}
}

func TestCoreConsumeDiagnosticsMeasureLockWaitAndExecutableCheck(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeSSH, false)
	defer fixture.close()
	var output bytes.Buffer
	lockWaiting := make(chan struct{}, 1)
	log := newTransportLog(tapTransportWriter{output: &output, onEvent: func(event transportLogEvent) {
		if event.Phase == "consume-lock-wait" && event.State == "started" {
			select {
			case lockWaiting <- struct{}{}:
			default:
			}
		}
	}})
	observation := newTransportObservation(log, "core", strings.Repeat("b", 32))
	path := filepath.Join(t.TempDir(), "fixture-may")
	contents := []byte("dummy executable identity")
	if err := os.WriteFile(path, contents, 0700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	identity, err := captureTrustedExecutable(path, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	fixture.agentPeer.Nodes[0].Path = path
	fixture.transport.broker.trustMode = "production"
	fixture.transport.agentIdentity = identity
	fixture.transport.agentUID = fixture.agentPeer.Nodes[0].UID
	fixture.transport.agentInstanceRef = fixture.transport.broker.processRef(fixture.agentPeer.Nodes[0])
	nonce := bytes.Repeat([]byte{8}, 32)
	ref := fixture.transport.broker.keyedRef("transport-nonce", nonce)
	fixture.transport.mu.Lock()
	fixture.transport.pending[ref] = transportBinding{requester: fixture.agentPeer.Nodes[0], expiresAt: fixture.transport.broker.now().Add(time.Minute)}
	result := make(chan wireResponse, 1)
	go func() {
		result <- fixture.transport.consumeBinding(base64.RawURLEncoding.EncodeToString(nonce), fixture.agentPeer, observation)
	}()
	select {
	case <-lockWaiting:
	case <-time.After(time.Second):
		fixture.transport.mu.Unlock()
		t.Fatal("consume did not reach the observed lock wait")
	}
	// A bounded hold introduces actual contention at the production lock.
	time.Sleep(40 * time.Millisecond)
	fixture.transport.mu.Unlock()
	if response := <-result; !response.Accepted {
		t.Fatalf("valid fixture binding was rejected: %v", response.ErrorCode)
	}
	events := readTransportEvents(t, log, &output)
	seen := map[string]transportLogEvent{}
	for _, event := range events {
		if event.State == "finished" {
			seen[event.Phase] = event
		}
	}
	if seen["consume-lock-wait"].ElapsedUS < 20000 {
		t.Fatal("lock contention was not measured")
	}
	if seen["agent-executable-check"].Result != "ok" || seen["consume-lock-held"].Result != "ok" {
		t.Fatal("missing executable verification or lock hold")
	}
	if replay := fixture.transport.consumeBinding(base64.RawURLEncoding.EncodeToString(nonce), fixture.agentPeer); replay.Accepted || replay.ErrorCode == nil || *replay.ErrorCode != "binding-replay" {
		t.Fatal("observation changed single-use semantics")
	}
	t.Logf("lock wait=%d us; executable check=%s (%d us); accepted once and replay rejected", seen["consume-lock-wait"].ElapsedUS, seen["agent-executable-check"].Result, seen["agent-executable-check"].ElapsedUS)
}
