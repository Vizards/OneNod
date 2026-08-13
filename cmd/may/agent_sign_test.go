package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestAgentVerifiesTheGatewaySignatureBeforeRelease(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBlob := signer.PublicKey().Marshal()
	data := []byte("data that OpenSSH asked the agent to sign")
	signature, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	requester, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	encodedRequester, err := json.Marshal(requester)
	if err != nil {
		t.Fatal(err)
	}
	identity := servedSSHIdentity{
		catalog: sshCatalogIdentity{
			ItemID: "item-ssh-1",
			Metadata: catalogSSHMetadata{
				Algorithm:     signer.PublicKey().Type(),
				Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
				PublicKeyBlob: base64URL(keyBlob),
			},
			Title:   "Disposable SSH key",
			Version: 3,
		},
		keyBlob: keyBlob,
	}
	responseSignature := append([]byte(nil), signature.Blob...)
	consumeFailure := false
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/v1/requests":
			var body sshSignRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Action != "ssh.sign" || body.Data != base64URL(data) ||
				body.ItemID != identity.catalog.ItemID ||
				body.ExpectedVersion != identity.catalog.Version ||
				body.ExpectedFingerprint != identity.catalog.Metadata.Fingerprint {
				t.Fatalf("unexpected SSH request: %+v", body)
			}
			return jsonHTTPResponse(
				http.StatusOK,
				`{"expires_at":"2099-01-01T00:00:00Z","poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","request_id":"request-ssh-1","status":"approved"}`,
			), nil
		case "/v1/requests/request-ssh-1/consume":
			if request.Header.Get("authorization") !=
				"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
				t.Fatal("SSH consume did not require its polling capability")
			}
			if consumeFailure {
				return jsonHTTPResponse(http.StatusInternalServerError, `{"code":"internal_error","error":"internal_error","ok":false}`), nil
			}
			response := sshSignConsumeResponse{
				Algorithm:     signature.Format,
				Fingerprint:   identity.catalog.Metadata.Fingerprint,
				ItemID:        identity.catalog.ItemID,
				OK:            true,
				PublicKeyBlob: identity.catalog.Metadata.PublicKeyBlob,
				RequestID:     "request-ssh-1",
				SignatureBlob: base64URL(responseSignature),
				Status:        "consumed",
				Version:       identity.catalog.Version,
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			return jsonHTTPResponse(http.StatusOK, string(encoded)), nil
		default:
			t.Fatalf("unexpected gateway path %q", request.URL.Path)
			return nil, nil
		}
	})
	agent := approvalAgent{
		config: cliConfig{
			origin:       "https://onenod.example-account.workers.dev",
			pollInterval: time.Millisecond,
			timeout:      time.Second,
		},
		context: context.Background(),
		deps: dependencies{
			httpClient: &http.Client{Transport: transport},
			keychain: keychainStore{backend: &recordingKeychainBackend{
				found:  true,
				output: encodedRequester,
			}},
			stderr: io.Discard,
		},
		identities: []servedSSHIdentity{identity},
	}
	connection := approvalAgentConnection{
		agent: agent,
		state: sshAgentConnectionState{client: unknownLocalClientContext()},
	}
	result, err := connection.Sign(signer.PublicKey(), data)
	if err != nil || result == nil || result.Format != signature.Format ||
		!bytes.Equal(result.Blob, signature.Blob) {
		t.Fatalf("valid signature response failed: %+v, %v", result, err)
	}

	responseSignature[0] ^= 1
	if _, err := connection.Sign(signer.PublicKey(), data); err == nil ||
		!strings.Contains(err.Error(), "did not verify") {
		t.Fatalf("tampered gateway signature returned %v", err)
	}

	consumeFailure = true
	if _, err := connection.Sign(signer.PublicKey(), data); err == nil ||
		!strings.Contains(err.Error(), "consume SSH request request-ssh-1 failed") ||
		!strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("consume failure omitted its safe request stage: %v", err)
	}
}

func TestSystemSSHKeygenCreatesAndVerifiesGitSSHSIGThroughFixedAgent(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBlob := signer.PublicKey().Marshal()
	publicText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	identity := servedSSHIdentity{
		catalog: sshCatalogIdentity{
			ItemID: "item-git-sign",
			Metadata: catalogSSHMetadata{
				Algorithm:     signer.PublicKey().Type(),
				Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
				PublicKey:     publicText,
				PublicKeyBlob: base64URL(keyBlob),
			},
			Title:   "Git signing key",
			Version: 5,
		},
		keyBlob: keyBlob,
	}
	requester, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	encodedRequester, err := json.Marshal(requester)
	if err != nil {
		t.Fatal(err)
	}
	var signingData []byte
	var signingMutex sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		writer.Header().Set("content-type", "application/json")
		if request.URL.Path == "/v1/requests" {
			var body sshSignRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				http.Error(writer, "invalid", http.StatusBadRequest)
				return
			}
			if body.Operation.Kind != "git.ssh-signature" ||
				body.Operation.Namespace != "git" {
				t.Errorf("unexpected SSHSIG operation: %+v", body.Operation)
			}
			decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(body.Data)
			if decodeErr != nil {
				t.Error(decodeErr)
				http.Error(writer, "invalid", http.StatusBadRequest)
				return
			}
			signingMutex.Lock()
			signingData = append(signingData[:0], decoded...)
			signingMutex.Unlock()
			_, _ = io.WriteString(writer, `{
				"expires_at":"2099-01-01T00:00:00Z",
				"poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"request_id":"request-git-sign",
				"status":"approved"
			}`)
			return
		}
		if request.URL.Path == "/v1/requests/request-git-sign/consume" {
			if request.Header.Get("authorization") !=
				"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
				t.Error("Git-sign consume did not require its polling capability")
				http.Error(writer, "missing polling capability", http.StatusUnauthorized)
				return
			}
			signingMutex.Lock()
			payload := append([]byte(nil), signingData...)
			signingMutex.Unlock()
			if len(payload) == 0 {
				http.Error(writer, "missing create payload", http.StatusInternalServerError)
				return
			}
			signature, signErr := signer.Sign(rand.Reader, payload)
			if signErr != nil {
				t.Error(signErr)
				http.Error(writer, "sign failed", http.StatusInternalServerError)
				return
			}
			response := sshSignConsumeResponse{
				Algorithm:     signature.Format,
				Fingerprint:   identity.catalog.Metadata.Fingerprint,
				ItemID:        identity.catalog.ItemID,
				OK:            true,
				PublicKeyBlob: identity.catalog.Metadata.PublicKeyBlob,
				RequestID:     "request-git-sign",
				SignatureBlob: base64URL(signature.Blob),
				Status:        "consumed",
				Version:       identity.catalog.Version,
			}
			if err := json.NewEncoder(writer).Encode(response); err != nil {
				t.Error(err)
			}
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()

	directory, err := os.MkdirTemp("/tmp", "may-agent-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "agent.sock")
	listener, err := listenApprovalAgent(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agent := approvalAgent{
		config: cliConfig{
			origin: server.URL, pollInterval: time.Millisecond, timeout: time.Second,
		},
		context: ctx,
		deps: dependencies{
			httpClient: server.Client(),
			keychain: keychainStore{backend: &recordingKeychainBackend{
				found: true, output: encodedRequester,
			}},
			stderr: io.Discard,
		},
		identities: []servedSSHIdentity{identity},
	}
	result := make(chan error, 1)
	go func() { result <- agent.serveListener(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-result
	})

	publicPath := filepath.Join(directory, "signing.pub")
	inputPath := filepath.Join(directory, "message")
	if err := os.WriteFile(publicPath, []byte(publicText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, []byte("reviewed commit payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sign := exec.Command(
		"/usr/bin/ssh-keygen",
		"-Y", "sign",
		"-n", "git",
		"-f", publicPath,
		inputPath,
	)
	sign.Env = withEnvironmentValue(os.Environ(), "SSH_AUTH_SOCK", socketPath)
	if output, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("system ssh-keygen sign failed: %v: %s", err, output)
	}
	allowedSignersPath := filepath.Join(directory, "allowed_signers")
	if err := os.WriteFile(
		allowedSignersPath,
		[]byte("test "+publicText+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	verify := exec.Command(
		"/usr/bin/ssh-keygen",
		"-Y", "verify",
		"-f", allowedSignersPath,
		"-I", "test",
		"-n", "git",
		"-s", inputPath+".sig",
	)
	verify.Stdin = input
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("system ssh-keygen verify failed: %v: %s", err, output)
	}
}
