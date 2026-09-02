package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestBeholderDirectObservationSendsOnlyMetadataAndCanonicalDigest(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	secretSentinel := "credential-value-must-never-cross-beholder-boundary"
	request := itemCreateRequest{
		Action:         "item.create",
		Category:       "LOGIN",
		IdempotencyKey: "request-1",
		Title:          "Example",
		Fields: []itemCreateFieldRequest{{
			FieldID: "password", FieldType: "CONCEALED", Label: "password", Value: secretSentinel,
		}},
	}
	canonical, err := canonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(canonical)
	clear(canonical)

	var captured beholderWireRequest
	observeBeholderDirectRequest(dependencies{
		beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
			captured = request
			return beholderWireResponse{
				SchemaVersion: beholderProtocolSchemaVersion,
				Accepted:      true,
				Disposition:   "escalate",
			}, nil
		},
	}, request)

	encoded, err := json.Marshal(captured)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secretSentinel)) {
		t.Fatal("direct Beholder observation included a credential value")
	}
	if captured.Kind != "direct-operation" || captured.ThreadID != os.Getenv("CODEX_THREAD_ID") ||
		captured.Binding != "" ||
		captured.Operation == nil || captured.Operation.Surface != "direct-may" ||
		captured.Operation.Operation != "item.create" ||
		captured.Operation.PayloadDigest != hex.EncodeToString(expectedDigest[:]) ||
		len(captured.Nonce) != 64 {
		t.Fatalf("unexpected direct observation: %+v", captured)
	}
}

func TestBeholderLeaseSelectsAValidatedSocketForSSHAndGit(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	listener, socketPath := temporaryUnixListener(t)
	defer listener.Close()

	var purposes []string
	deps := dependencies{beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
		if request.Kind != "ssh-proxy-lease" || request.ThreadID != os.Getenv("CODEX_THREAD_ID") ||
			request.Binding != "" {
			t.Fatalf("unexpected lease request: %+v", request)
		}
		purposes = append(purposes, request.Purpose)
		return beholderWireResponse{
			SchemaVersion: beholderProtocolSchemaVersion,
			Accepted:      true,
			AgentSocket:   socketPath,
		}, nil
	}}
	lease, err := requestBeholderSSHLease(deps, beholderLeasePurposeSSH)
	if err != nil || lease.AgentSocket != socketPath {
		t.Fatalf("SSH lease failed: %+v, %v", lease, err)
	}
	if selected := gitSignAgentSocket(deps); selected != socketPath {
		t.Fatalf("Git signing did not select its task lease: %q", selected)
	}
	if !reflect.DeepEqual(purposes, []string{beholderLeasePurposeSSH, beholderLeasePurposeGit}) {
		t.Fatalf("unexpected lease purposes: %v", purposes)
	}
}

func TestGitSigningFallsBackToTheExistingAgentWithoutABeholderLease(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	called := false
	selected := gitSignAgentSocket(dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			called = true
			return beholderWireResponse{}, errors.New("Core unavailable")
		},
	})
	if !called || selected != defaultAgentSocket() {
		t.Fatalf("Git signing did not preserve the existing Agent fallback: called=%t socket=%q", called, selected)
	}
}

func TestGitSigningDoesNotContactCoreOutsideACodexTask(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "")
	called := false
	selected := gitSignAgentSocket(dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			called = true
			return beholderWireResponse{}, errors.New("must not be called")
		},
	})
	if called || selected != defaultAgentSocket() {
		t.Fatalf("unattributed Git signing changed its existing Agent path: called=%t socket=%q", called, selected)
	}
}

func TestTransparentSSHShimPreservesTheNativeCommandSurface(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	spaceRoot, err := os.MkdirTemp("", "beholder space-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(spaceRoot)
	listener, err := net.Listen("unix", filepath.Join(spaceRoot, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	socketPath := listener.Addr().String()
	defer listener.Close()
	original := []string{"-p", "2222", "git@example.invalid", "git-upload-pack 'repo.git'"}
	var capturedPath string
	var capturedArguments []string
	err = runBeholderSSHShim(original, dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			return beholderWireResponse{
				SchemaVersion: beholderProtocolSchemaVersion,
				Accepted:      true,
				AgentSocket:   socketPath,
			}, nil
		},
		processExec: func(path string, arguments, _ []string) error {
			capturedPath = path
			capturedArguments = append([]string(nil), arguments...)
			return nil
		},
	})
	if err != nil || capturedPath != systemSSHPath {
		t.Fatalf("transparent ssh dispatch failed: %q, %v", capturedPath, err)
	}
	expected := append(
		[]string{systemSSHPath, "-o", "IdentityAgent=" + quoteOpenSSHConfigValue(socketPath)},
		original...,
	)
	if !reflect.DeepEqual(capturedArguments, expected) {
		t.Fatalf("ssh arguments changed unexpectedly: %q", capturedArguments)
	}
}

func TestOpenSSHConfigValueQuotingPreservesSpacesAndEscapesSyntax(t *testing.T) {
	if got, want := quoteOpenSSHConfigValue(`/Library/Application Support/Beholder/run/agent.sock`),
		`"/Library/Application Support/Beholder/run/agent.sock"`; got != want {
		t.Fatalf("space-bearing value was not quoted: %q", got)
	}
	if got, want := quoteOpenSSHConfigValue(`a\b"c`), `"a\\b\"c"`; got != want {
		t.Fatalf("OpenSSH quoted value escaped incorrectly: got %q want %q", got, want)
	}
}

func TestTransparentSSHShimFallsBackToOrdinarySSHWithoutTaskBinding(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "")
	original := []string{"example.invalid", "true"}
	beholderCalled := false
	var captured []string
	err := runBeholderSSHShim(original, dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			beholderCalled = true
			return beholderWireResponse{}, errors.New("must not be called")
		},
		processExec: func(_ string, arguments, _ []string) error {
			captured = append([]string(nil), arguments...)
			return nil
		},
	})
	if err != nil || beholderCalled ||
		!reflect.DeepEqual(captured, append([]string{systemSSHPath}, original...)) {
		t.Fatalf("fallback changed ordinary ssh: called=%t arguments=%q err=%v", beholderCalled, captured, err)
	}
}

func TestTransparentSSHShimFallsBackWhenExecutionRootIsUnverified(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	original := []string{"example.invalid", "true"}
	beholderCalled := false
	var captured []string
	err := runBeholderSSHShim(original, dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			beholderCalled = true
			return beholderWireResponse{}, errors.New("execution root unverified")
		},
		processExec: func(_ string, arguments, _ []string) error {
			captured = append([]string(nil), arguments...)
			return nil
		},
	})
	if err != nil || !beholderCalled ||
		!reflect.DeepEqual(captured, append([]string{systemSSHPath}, original...)) {
		t.Fatalf("missing binding changed ordinary ssh: called=%t arguments=%q err=%v", beholderCalled, captured, err)
	}
}

func TestDirectObservationSkipsCoreWithoutThreadCandidate(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "")
	called := false
	observeBeholderDirectRequest(dependencies{
		beholder: func(beholderWireRequest) (beholderWireResponse, error) {
			called = true
			return beholderWireResponse{}, nil
		},
	}, itemArchiveRequest{Action: "item.archive", ItemID: "item-1", ExpectedVersion: 1})
	if called {
		t.Fatal("direct request without a thread candidate reached Core")
	}
}

func TestBeholderRequesterContextPreservesEnvironmentAndRedactsSecrets(t *testing.T) {
	t.Setenv("E2_OBS_DIAGNOSTIC_CONTEXT", "diagnostic-value")
	t.Setenv("E2_OBS_API_KEY", "abcdefghijklmnopqrstuvwxyz123456")
	target, ok := directBeholderOperationTarget(itemArchiveRequest{
		Action: "item.archive", ItemID: "fixture-a", ExpectedVersion: 7,
		Client: clientObservation{Application: "Codex"},
	}, []byte(`{"action":"item.archive"}`), cliConfig{
		origin:       "https://user:credential@example.invalid/gateway?token=credential",
		pollInterval: 2 * time.Second, timeout: 3 * time.Minute,
	})
	if !ok || target.RequesterContext == "" || !json.Valid([]byte(target.RequesterContext)) {
		t.Fatalf("requester context was unavailable: %+v", target)
	}
	if strings.Contains(target.RequesterContext, "abcdefghijklmnopqrstuvwxyz123456") ||
		!strings.Contains(target.RequesterContext, "diagnostic-value") ||
		!strings.Contains(target.RequesterContext, "[REDACTED:CREDENTIAL]") ||
		!strings.Contains(target.RequesterContext, `"redaction_rule":"sensitive-requester-environment"`) ||
		!strings.Contains(target.RequesterContext, `"gateway_origin":"https://example.invalid/gateway"`) ||
		strings.Contains(target.RequesterContext, "user:credential") || strings.Contains(target.RequesterContext, "token=credential") {
		t.Fatalf("requester environment evidence was incomplete or unsafe: %s", target.RequesterContext)
	}
}

func TestBeholderOutcomeTrackerCorrelatesInteractiveApprovalWithoutCredentialMaterial(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	const evidenceID = "shadow-0123456789abcdef0123456789abcdef"
	var capturedOutcome beholderWireRequest
	calls := 0
	deps := dependencies{beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
		calls++
		switch request.Kind {
		case "direct-operation":
			return beholderWireResponse{
				SchemaVersion: beholderProtocolSchemaVersion, Accepted: true,
				Disposition: "allow", EvidenceID: evidenceID,
			}, nil
		case "human-outcome":
			capturedOutcome = request
			return beholderWireResponse{
				SchemaVersion: beholderProtocolSchemaVersion, Accepted: true, EvidenceID: evidenceID,
			}, nil
		default:
			t.Fatalf("unexpected Beholder request kind %q", request.Kind)
			return beholderWireResponse{}, nil
		}
	}}
	request := createRequest{
		Action: "secret.read", Client: clientObservation{Application: "Codex"},
		ExpectedVersion: 3, FieldID: "credential", IdempotencyKey: "not-persisted",
		ItemID: "fixture-a",
	}
	observation := observeBeholderDirectRequest(deps, request)
	tracker := newBeholderOutcomeTracker(deps, observation, true)
	tracker.setRequest("request-0001", "pending")
	tracker.observeStatus("approved")
	tracker.observeStatus("consumed")
	tracker.finish(nil, true)
	if calls != 2 || capturedOutcome.EvidenceID != evidenceID || capturedOutcome.Operation == nil ||
		capturedOutcome.HumanOutcome == nil {
		t.Fatalf("outcome was not correlated: calls=%d request=%+v", calls, capturedOutcome)
	}
	outcome := capturedOutcome.HumanOutcome
	if outcome.AuthorizationSource != "pwa-interactive" || outcome.Decision != "approved" ||
		!outcome.OperationCompleted || !outcome.CredentialDelivered || outcome.OneNodRequestID == nil ||
		*outcome.OneNodRequestID != "request-0001" || len(outcome.StatusTimeline) != 3 {
		t.Fatalf("unexpected interactive outcome: %+v", outcome)
	}
	encoded, err := json.Marshal(capturedOutcome)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"poll_token", "credential-value", "Authorization: Bearer ", "idempotency_key"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("outcome wire included forbidden material %q: %s", forbidden, encoded)
		}
	}
}

func TestBeholderOutcomeTrackerDistinguishesRememberedRejectedTimeoutAndFallback(t *testing.T) {
	tests := []struct {
		name, initial, source, decision string
		err                             error
		fallback, completed             bool
	}{
		{name: "remembered", initial: "approved", source: "remembered-grant", decision: "approved", completed: true},
		{name: "rejected", initial: "pending", source: "pwa-interactive", decision: "rejected", err: errors.New("request rejected")},
		{name: "timeout", initial: "pending", source: "pwa-interactive", decision: "timed_out", err: errors.New("timed out waiting for approval")},
		{name: "fallback", initial: "", source: "local-fallback", decision: "approved", fallback: true, completed: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const evidenceID = "shadow-abcdef0123456789abcdef0123456789"
			var captured *beholderHumanOutcome
			deps := dependencies{beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
				if request.Kind == "human-outcome" {
					captured = request.HumanOutcome
				}
				return beholderWireResponse{SchemaVersion: 1, Accepted: true, EvidenceID: evidenceID}, nil
			}}
			observation := beholderObservation{EvidenceID: evidenceID, Target: beholderOperationTarget{
				SchemaVersion: 1, Surface: "direct-may", Operation: "secret.read",
				TargetKind: "onepassword-item", PayloadDigest: strings.Repeat("a", 64),
			}}
			tracker := newBeholderOutcomeTracker(deps, observation, true)
			if test.initial != "" {
				tracker.setRequest("request-0002", test.initial)
			}
			if test.name == "rejected" {
				tracker.observeStatus("rejected")
			}
			if test.fallback {
				tracker.useLocalFallback()
			}
			tracker.finish(test.err, test.completed)
			if captured == nil || captured.AuthorizationSource != test.source || captured.Decision != test.decision {
				t.Fatalf("unexpected outcome: %+v", captured)
			}
			if captured.ObservedAt.Before(time.Now().Add(-time.Minute)) {
				t.Fatalf("outcome timestamp is stale: %s", captured.ObservedAt)
			}
		})
	}
}

func TestBeholderDispositionAndRecordingFailurePreserveDirectApprovalPath(t *testing.T) {
	t.Setenv("CODEX_THREAD_ID", "00000000-0000-7000-8000-000000000001")
	credential, err := credentialFromSeed("beholder-approval-invariance")
	if err != nil {
		t.Fatal(err)
	}
	encodedCredential, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		disposition string
		observeErr  error
		wantCalls   int
	}{
		{name: "allow", disposition: "allow", wantCalls: 2},
		{name: "escalate", disposition: "escalate", wantCalls: 2},
		{name: "core unavailable", observeErr: errors.New("Core unavailable"), wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gatewayPaths := []string{}
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				gatewayPaths = append(gatewayPaths, request.URL.Path)
				switch request.URL.Path {
				case "/v1/requests":
					return jsonHTTPResponse(http.StatusCreated, `{
						"expires_at":"2099-01-01T00:00:00Z",
						"poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
						"request_id":"request-beholder-invariance",
						"status":"pending"
					}`), nil
				case "/v1/requests/request-beholder-invariance/status":
					return jsonHTTPResponse(http.StatusOK, `{
						"request_id":"request-beholder-invariance",
						"status":"approved"
					}`), nil
				case "/v1/requests/request-beholder-invariance/consume":
					return jsonHTTPResponse(http.StatusOK, `{
						"ok":true,
						"request_id":"request-beholder-invariance",
						"status":"consumed",
						"value":"dummy-approved-value"
					}`), nil
				default:
					t.Fatalf("unexpected Gateway path %q", request.URL.Path)
					return nil, nil
				}
			})
			beholderCalls := 0
			deps := dependencies{
				beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
					beholderCalls++
					if request.Kind == "direct-operation" {
						if test.observeErr != nil {
							return beholderWireResponse{}, test.observeErr
						}
						return beholderWireResponse{
							SchemaVersion: beholderProtocolSchemaVersion,
							Accepted:      true,
							Disposition:   test.disposition,
							EvidenceID:    "shadow-approval-invariance",
						}, nil
					}
					if request.Kind != "human-outcome" {
						t.Fatalf("unexpected Beholder request kind %q", request.Kind)
					}
					return beholderWireResponse{}, errors.New("evidence store unavailable")
				},
				httpClient: &http.Client{Transport: transport},
				keychain: keychainStore{backend: &recordingKeychainBackend{
					found: true, output: encodedCredential,
				}},
				stderr: io.Discard,
			}
			value, err := readApprovedSecret(cliConfig{
				origin:       "https://onenod.example-account.workers.dev",
				pollInterval: time.Millisecond,
				timeout:      time.Second,
			}, deps, "fixture-a", "credential", 1)
			if err != nil || value != "dummy-approved-value" {
				t.Fatalf("Beholder changed the approved credential result: value=%q err=%v", value, err)
			}
			wantPaths := []string{
				"/v1/requests",
				"/v1/requests/request-beholder-invariance/status",
				"/v1/requests/request-beholder-invariance/consume",
			}
			if !reflect.DeepEqual(gatewayPaths, wantPaths) || beholderCalls != test.wantCalls {
				t.Fatalf("approval path changed: Gateway=%v Beholder calls=%d", gatewayPaths, beholderCalls)
			}
		})
	}
}

func TestBeholderAgentBindingExtensionIsOpaqueAndOneUse(t *testing.T) {
	nonce := bytes.Repeat([]byte{0x5a}, 32)
	contents := ssh.Marshal(struct {
		Version uint32
		Nonce   []byte
	}{Version: beholderBindingVersion, Nonce: nonce})
	binding := strings.Repeat("b", 32)
	calls := 0
	connection := approvalAgentConnection{agent: approvalAgent{deps: dependencies{
		beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
			calls++
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(request.Nonce)
			if err != nil || !bytes.Equal(decoded, nonce) || request.Kind != "agent-binding-consume" {
				t.Fatalf("unexpected binding consume: %+v", request)
			}
			return beholderWireResponse{
				SchemaVersion: beholderProtocolSchemaVersion,
				Accepted:      true,
				Binding:       binding,
			}, nil
		},
	}}}
	response, err := connection.Extension(beholderBindingExtensionName, contents)
	if err != nil || !bytes.Equal(response, []byte{sshAgentSuccessResponse}) ||
		connection.state.beholderBinding != binding {
		t.Fatalf("binding extension failed: %x, %+v, %v", response, connection.state, err)
	}
	if _, err := connection.Extension(beholderBindingExtensionName, contents); err == nil || calls != 1 {
		t.Fatalf("binding extension replay was accepted: calls=%d err=%v", calls, err)
	}
}

func TestParseBeholderBindingExtensionRejectsTrailingOrShortData(t *testing.T) {
	valid := ssh.Marshal(struct {
		Version uint32
		Nonce   []byte
	}{Version: beholderBindingVersion, Nonce: bytes.Repeat([]byte{1}, 32)})
	if parsed, err := parseBeholderBindingExtension(valid); err != nil || len(parsed) != 32 {
		t.Fatalf("valid binding extension failed: %x, %v", parsed, err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte(nil), valid...), 0),
		ssh.Marshal(struct {
			Version uint32
			Nonce   []byte
		}{Version: beholderBindingVersion, Nonce: []byte("short")}),
	} {
		if _, err := parseBeholderBindingExtension(invalid); err == nil {
			t.Fatalf("invalid binding extension was accepted: %x", invalid)
		}
	}
}

func temporaryUnixListener(t *testing.T) (net.Listener, string) {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "bh-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.RemoveAll(directory)
	})
	return listener, path
}
