package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestBeholderLeaseFailureKeepsReasonAndTraceWithoutAuthority(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	code := "prompt-binding-missing"
	var trace string
	_, err := requestBeholderSSHLease(dependencies{beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
		trace = request.TraceID
		return beholderWireResponse{ErrorCode: &code}, nil
	}}, beholderLeasePurposeSSH)
	diagnostic := diagnosticFromError(err)
	if !validBeholderDiagnostic(diagnostic) || diagnostic.TraceID != trace || diagnostic.Code != code || diagnostic.ModelCalled == nil || *diagnostic.ModelCalled {
		t.Fatalf("lost cause: %v", err)
	}
	connection := approvalAgentConnection{}
	raw, _ := json.Marshal(diagnostic)
	if _, err := connection.Extension(beholderDiagnosticExtensionName, raw); err != nil {
		t.Fatal(err)
	}
	if connection.state.beholderBinding != "" || connection.state.binding != nil {
		t.Fatal("diagnostic granted authority")
	}
	request := sshSignRequest{}
	attachBeholderAuthorization(&request, beholderObservation{Diagnostic: diagnostic})
	if request.BeholderAuthorization != nil || request.Client.BeholderDiagnostic == nil {
		t.Fatal("diagnostic became capability")
	}
	var log bytes.Buffer
	tracker := newBeholderOutcomeTracker(dependencies{stderr: &log}, beholderObservation{}, false)
	tracker.setObservation(beholderObservation{Diagnostic: diagnostic})
	tracker.setRequest("00000000-0000-7000-8000-000000000002", "pending")
	if !strings.Contains(log.String(), trace) || !strings.Contains(log.String(), "00000000-0000-7000-8000-000000000002") {
		t.Fatalf("request correlation lost: %s", log.String())
	}
}

func TestBeholderDiagnosticRejectsTextAndRetainsUnknownModelState(t *testing.T) {
	base := newBeholderDiagnostic("core", "decision-unavailable", nil)
	for _, modify := range []func(*beholderDiagnostic){
		func(d *beholderDiagnostic) { d.Code = "raw task text\n" },
		func(d *beholderDiagnostic) { d.TraceID = strings.Repeat("A", 32) },
		func(d *beholderDiagnostic) { d.Stage = "arbitrary" },
		func(d *beholderDiagnostic) { d.SchemaVersion = 2 },
	} {
		d := *base
		modify(&d)
		if validBeholderDiagnostic(&d) {
			t.Fatal("invalid diagnostic accepted")
		}
	}
	connection := approvalAgentConnection{}
	raw, _ := json.Marshal(base)
	for _, invalid := range [][]byte{append(append([]byte(nil), raw...), []byte(` {}`)...), []byte(`{"schema_version":1,"arbitrary":"text"}`)} {
		if _, err := connection.Extension(beholderDiagnosticExtensionName, invalid); err == nil {
			t.Fatal("malformed extension accepted")
		}
	}
	d := diagnosticForDecision(beholderWireResponse{}, base.TraceID)
	encoded, _ := json.Marshal(d)
	if d.ModelCalled != nil || bytes.Contains(encoded, []byte("model_called")) {
		t.Fatal("unknown model state reported as no")
	}
}

func TestFallbackDiagnosticIsBoundByFinalSSHSessionProof(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := sshSignRequest{Action: "ssh.sign", Client: clientObservation{Application: "Codex", Source: "unavailable"}, Operation: sshOperation{Kind: "ssh.opaque-signature"}, IdempotencyKey: "fixture-request"}
	client := localClientContext{Observation: request.Client, ScopeID: "fixture-scope", ScopeKind: "application"}
	if err = attachSshAuthorizationSession(&request, client, key); err != nil {
		t.Fatal(err)
	}
	request.Client.BeholderDiagnostic = newBeholderDiagnostic("lease", "prompt-binding-missing", nil)
	if err = attachSshAuthorizationSession(&request, client, key); err != nil {
		t.Fatal(err)
	}
	proof, err := base64.RawURLEncoding.DecodeString(request.AuthorizationSession.Proof)
	if err != nil {
		t.Fatal(err)
	}
	request.AuthorizationSession.Proof = ""
	material, err := canonicalJSON(request)
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), material, proof) {
		t.Fatal("final request proof failed")
	}
	request.Client.BeholderDiagnostic.Code = "changed"
	material, _ = canonicalJSON(request)
	if ed25519.Verify(key.Public().(ed25519.PublicKey), material, proof) {
		t.Fatal("proof did not cover diagnostic")
	}
}
