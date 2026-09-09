package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestShadowGatekeeperReceivesExactTransientContextAndSafeActualTarget(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "bh-gk-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(digest[:]),
	}

	prompt := []byte("use the named E2 fixture for this representative read")
	toolInput := json.RawMessage(`{"command":"may read --scenario e2a-rep-01 op://Agent/fixture/credential"}`)
	payloadDigest := strings.Repeat("a", 64)
	received := make(chan gatekeeperLocalRequest, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		received <- request
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion, RequestID: request.RequestID,
			Decision: "escalate", Reason: "The shadow decision was accepted for asynchronous evaluation.",
			EvidenceID: request.RequestID, LatencyMS: 17,
		})
	}()

	response := wireResponse{
		SchemaVersion: protocolSchemaVersion, Accepted: true,
		Envelope: &evidenceEnvelope{
			SchemaVersion: protocolSchemaVersion, FeatureSchemaVersion: featureSchemaVersion,
			Collector: "beholder-core", DecisionComponent: "gatekeeper",
			Host: hostEvidence{ToolName: "functions.exec"},
		},
		decisionContext: &transientDecisionContext{
			Prompt: append([]byte(nil), prompt...), ToolInput: append(json.RawMessage(nil), toolInput...),
		},
		decisionTranscriptPath: filepath.Join(root, "session.jsonl"), decisionCWD: root,
	}
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may",
		Operation: "credential.use", TargetKind: "onepassword-item",
		TargetID:         `{"item_id":"fixture","field_ids":["credential"]}`,
		RequestContext:   `{"client":{"application":"Codex"}}`,
		RequesterContext: `{"environment":[{"name":"PATH","value":"/usr/bin","redacted":false}]}`,
		PayloadDigest:    payloadDigest,
	}
	broker := &broker{gatekeeper: client}
	decision, evidenceID := broker.runShadowGatekeeperWithEvidence(&response, target)
	if decision != "escalate" || !strings.HasPrefix(evidenceID, "shadow-") {
		t.Fatalf("submitted shadow result = %q, %q; want fail-closed escalate with evidence handle", decision, evidenceID)
	}
	if response.Envelope.Gatekeeper.Disposition != "escalate" || response.Envelope.Gatekeeper.Executed ||
		response.Envelope.Gatekeeper.ModelUsed || response.Envelope.Gatekeeper.ProductionAuthoritative ||
		response.Envelope.Gatekeeper.ErrorCode != nil {
		t.Fatalf("shadow submission evidence overstated or lost result: %+v", response.Envelope.Gatekeeper)
	}
	if response.decisionContext != nil || response.decisionTranscriptPath != "" || response.decisionCWD != "" {
		t.Fatal("transient decision context was not cleared")
	}

	request := <-received
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if request.Mode != "shadow-submit" || !bytes.Equal(request.Prompt, prompt) || !bytes.Equal(request.ToolInput, toolInput) ||
		request.ToolName != "functions.exec" || request.TranscriptPath == "" || request.CWD != root {
		t.Fatalf("Gatekeeper did not receive the exact bound context: %+v", request)
	}
	if request.ActualRequest.TargetID != target.TargetID || request.ActualRequest.Operation != target.Operation ||
		request.ActualRequest.RequestContext != target.RequestContext ||
		request.ActualRequest.RequesterContext != target.RequesterContext ||
		request.ActualRequest.PayloadDigest != target.PayloadDigest ||
		request.CoreBinarySHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("Gatekeeper actual target mismatch: %+v", request.ActualRequest)
	}
	if !json.Valid(request.Evidence) || !bytes.Contains(request.Evidence, []byte(`"production_authoritative":false`)) {
		t.Fatal("Gatekeeper evidence was missing or unsafe")
	}
	clearGatekeeperLocalRequest(&request)
}

func TestShadowGatekeeperTimeoutBoundsCoverR3(t *testing.T) {
	if !validShadowGatekeeperTimeout(610*time.Second) ||
		validShadowGatekeeperTimeout(0) ||
		validShadowGatekeeperTimeout(maximumShadowGatekeeperRoundTrip+time.Millisecond) {
		t.Fatal("shadow Gatekeeper timeout bounds do not match the R3 transport contract")
	}
}

func TestShadowSubmissionPreservesFallbackEvidenceHandle(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "bh-gk-fallback-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		code := "evidence-source-privacy-check-failed"
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion, RequestID: request.RequestID,
			Decision: "escalate", Reason: "A minimal failure bundle was retained.",
			ErrorCode: &code, EvidenceID: request.RequestID,
		})
	}()
	requestID := "shadow-fallback-00000001"
	response, err := client.submit(gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: requestID, Mode: "shadow-submit",
		Prompt: []byte("inspect the router"), ToolName: "functions.exec",
		ToolInput: json.RawMessage(`{"cmd":"ssh router"}`), TranscriptPath: filepath.Join(root, "session.jsonl"), CWD: root,
		Evidence: json.RawMessage(`{"collection":{"status":"ready"}}`),
		ActualRequest: gatekeeperLocalTarget{
			SchemaVersion: decisionBindingSchemaVersion, Surface: "ssh-agent", Operation: "ssh.authentication",
			TargetKind: "ssh-key", PayloadDigest: strings.Repeat("a", 64),
		},
	})
	if serverErr := <-serverError; serverErr != nil {
		t.Fatal(serverErr)
	}
	if err != nil || response.EvidenceID != requestID || response.ErrorCode == nil ||
		*response.ErrorCode != "evidence-source-privacy-check-failed" {
		t.Fatalf("fallback evidence handle was discarded: response=%+v err=%v", response, err)
	}
}

func TestShadowGatekeeperFailsClosedAndClearsTransientContextWhenUnavailable(t *testing.T) {
	t.Parallel()
	prompt := []byte("transient prompt sentinel")
	toolInput := json.RawMessage(`{"command":"transient tool sentinel"}`)
	response := wireResponse{
		Accepted: true,
		Envelope: &evidenceEnvelope{Gatekeeper: gatekeeperEvidence{Disposition: "escalate"}},
		decisionContext: &transientDecisionContext{
			Prompt: append([]byte(nil), prompt...), ToolInput: append(json.RawMessage(nil), toolInput...),
		},
		decisionTranscriptPath: "/private/tmp/session.jsonl", decisionCWD: "/private/tmp",
	}
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may", Operation: "credential.use",
		TargetKind: "onepassword-item", PayloadDigest: strings.Repeat("b", 64),
	}
	if decision := (&broker{}).runShadowGatekeeper(&response, target); decision != "escalate" {
		t.Fatalf("unavailable Gatekeeper decision = %q", decision)
	}
	if response.Envelope.Gatekeeper.ErrorCode == nil ||
		*response.Envelope.Gatekeeper.ErrorCode != "gatekeeper-not-configured" ||
		response.Envelope.Gatekeeper.Executed || response.Envelope.Gatekeeper.ModelUsed ||
		response.Envelope.Gatekeeper.ProductionAuthoritative {
		t.Fatalf("unavailable Gatekeeper did not fail closed: %+v", response.Envelope.Gatekeeper)
	}
	if response.decisionContext != nil || response.decisionTranscriptPath != "" || response.decisionCWD != "" {
		t.Fatal("unavailable Gatekeeper retained transient context")
	}
	if !bytes.Equal(prompt, []byte("transient prompt sentinel")) ||
		!bytes.Equal(toolInput, []byte(`{"command":"transient tool sentinel"}`)) {
		t.Fatal("test-owned context was unexpectedly aliased")
	}
}

func TestShadowGatekeeperRecordsIncompleteAttributionAsModelFreeTelemetry(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "bh-gk-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	received := make(chan gatekeeperLocalRequest, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		received <- request
		code := "execution-root-unverified"
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion, RequestID: request.RequestID,
			Decision: "escalate", Reason: "The request attribution is incomplete.", ErrorCode: &code, ModelUsed: false,
		})
	}()

	code := "execution-root-unverified"
	response := wireResponse{
		SchemaVersion: protocolSchemaVersion, Accepted: false, ErrorCode: &code,
		Envelope: &evidenceEnvelope{
			SchemaVersion: protocolSchemaVersion, FeatureSchemaVersion: featureSchemaVersion,
			Collection: collectionEvidence{Status: "incomplete", ErrorCode: &code},
			Attribution: attributionEvidence{
				Result: "unattributed", Conflicts: []string{code}, EvidenceKinds: []string{},
			},
			Gatekeeper: gatekeeperEvidence{
				Disposition: "escalate", ErrorCode: &code, ProductionAuthoritative: false,
			},
		},
	}
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may",
		Operation: "credential.use", TargetKind: "onepassword-item",
		TargetID:      `{"item_id":"fixture","field_ids":["credential"]}`,
		PayloadDigest: strings.Repeat("c", 64),
	}
	(&broker{gatekeeper: client}).recordShadowEscalation(&response, target)
	request := <-received
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if request.Mode != "telemetry" || len(request.Prompt) != 0 || len(request.ToolInput) != 0 ||
		request.TranscriptPath != "" || request.CWD != "" || !json.Valid(request.Evidence) {
		t.Fatalf("incomplete attribution telemetry contained transient decision input: %+v", request)
	}
	if request.ActualRequest.PayloadDigest != target.PayloadDigest {
		t.Fatal("telemetry lost the exact in-flight payload digest")
	}
	clearGatekeeperLocalRequest(&request)
}

func TestShadowGatekeeperRejectsMismatchedResponseRequestID(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "bh-gk-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion, RequestID: "shadow-wrong",
			Decision: "allow", Reason: "The response belongs to the wrong request.", ModelUsed: true,
		})
	}()
	_, err = client.decide(gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: "shadow-expected", Mode: "shadow",
		Prompt: []byte("prompt"), ToolName: "functions.exec",
		ToolInput: json.RawMessage(`{"command":"true"}`), Evidence: json.RawMessage(`{"safe":true}`),
		ActualRequest: gatekeeperLocalTarget{
			SchemaVersion: 1, Surface: "direct-may", Operation: "credential.use",
			TargetKind: "onepassword-item", PayloadDigest: strings.Repeat("a", 64),
		},
	})
	if serverErr := <-serverError; serverErr != nil {
		t.Fatal(serverErr)
	}
	if err == nil {
		t.Fatal("Gatekeeper response with a mismatched request ID was accepted")
	}
}

func TestShadowGatekeeperPreservesSafeHumanOutcomeFailureCode(t *testing.T) {
	t.Parallel()
	root, err := os.MkdirTemp("/tmp", "bh-gk-outcome-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	const evidenceID = "shadow-outcome-stage-0000000000000001"
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		code := "human-outcome-bundle-not-found"
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion, RequestID: request.RequestID,
			Decision: "escalate", Reason: "The human outcome evidence could not be persisted.",
			ErrorCode: &code,
		})
	}()
	now := time.Now().UTC()
	err = client.recordOutcome(humanOutcome{
		SchemaVersion: 1, RecordType: "beholder_human_outcome", EvidenceID: evidenceID,
		OperationTargetSHA256: strings.Repeat("a", 64), AuthorizationSource: "pwa-interactive",
		Decision: "approved", StatusTimeline: []outcomeStatus{{Status: "approved", ObservedAt: now}},
		OperationCompleted: true, ObservedAt: now,
	})
	if serverErr := <-serverError; serverErr != nil {
		t.Fatal(serverErr)
	}
	if code := gatekeeperOutcomeFailureCode(err); code != "human-outcome-bundle-not-found" {
		t.Fatalf("safe Gatekeeper outcome error was collapsed: %q (%v)", code, err)
	}
}
