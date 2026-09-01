package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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
