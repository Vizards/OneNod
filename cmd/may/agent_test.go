package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
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
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestSignatureAlgorithmRequiresExplicitRSASHA2(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		flags     uint32
		expected  string
		shouldErr bool
	}{
		{name: "RSA SHA2-256", key: "ssh-rsa", flags: uint32(sshagent.SignatureFlagRsaSha256), expected: "rsa-sha2-256"},
		{name: "RSA SHA2-512", key: "ssh-rsa", flags: uint32(sshagent.SignatureFlagRsaSha512), expected: "rsa-sha2-512"},
		{name: "RSA SHA1", key: "ssh-rsa", shouldErr: true},
		{name: "ambiguous RSA flags", key: "ssh-rsa", flags: uint32(sshagent.SignatureFlagRsaSha256 | sshagent.SignatureFlagRsaSha512), shouldErr: true},
		{name: "Ed25519", key: "ssh-ed25519", expected: "ssh-ed25519"},
		{name: "unsupported ECDSA", key: "ecdsa-sha2-nistp256", shouldErr: true},
		{name: "flags on Ed25519", key: "ssh-ed25519", flags: uint32(sshagent.SignatureFlagRsaSha256), shouldErr: true},
		{name: "unsupported key", key: "ssh-dss", shouldErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := signatureAlgorithm(test.key, test.flags)
			if test.shouldErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", actual)
				}
				return
			}
			if err != nil || actual != test.expected {
				t.Fatalf("signatureAlgorithm() = %q, %v; want %q", actual, err, test.expected)
			}
		})
	}
}

func TestSSHAuthorizationSessionProofBindsAgentInstanceAndLocalScope(t *testing.T) {
	t.Parallel()
	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := sshSignRequest{
		Action:    "ssh.sign",
		Algorithm: "ssh-ed25519",
		Client: clientObservation{
			Application: "Codex via Paseo",
			Source:      "process-ancestry",
		},
		Data:                base64URL([]byte("signing payload")),
		ExpectedFingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		ExpectedVersion:     7,
		IdempotencyKey:      "request-1",
		ItemID:              "item-1",
		Operation:           sshOperation{Kind: "ssh.opaque-signature"},
	}
	localClient := localClientContext{
		Observation: request.Client,
		ScopeID:     "scope-1",
		ScopeKind:   "terminal-session",
	}
	if err := attachSshAuthorizationSession(&request, localClient, sessionKey); err != nil {
		t.Fatal(err)
	}
	if request.AuthorizationSession == nil {
		t.Fatal("authorization session was not attached")
	}
	proof, err := base64.RawURLEncoding.Strict().DecodeString(
		request.AuthorizationSession.Proof,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.AuthorizationSession.Proof = ""
	material, err := canonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(sessionKey.Public().(ed25519.PublicKey), material, proof) {
		t.Fatal("authorization session proof did not verify")
	}
	request.AuthorizationSession.ScopeID = "different-scope"
	changedMaterial, err := canonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(sessionKey.Public().(ed25519.PublicKey), changedMaterial, proof) {
		t.Fatal("authorization session proof survived a scope change")
	}

	_, restartedKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(restartedKey.Public().(ed25519.PublicKey), material, proof) {
		t.Fatal("authorization session proof survived an SSH Agent restart")
	}
}

func TestSSHAuthorizationSessionIsUnavailableWithoutReliableLocalScope(t *testing.T) {
	t.Parallel()
	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := sshSignRequest{Action: "ssh.sign"}
	if err := attachSshAuthorizationSession(
		&request,
		unknownLocalClientContext(),
		sessionKey,
	); err != nil {
		t.Fatal(err)
	}
	if request.AuthorizationSession != nil {
		t.Fatal("unidentified local clients must not receive reusable authorization")
	}
}

func TestSessionBindRequiresAValidLocalSession(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := []byte("test-session-identifier")
	signature, err := signer.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	valid := sessionBindContents(
		signer.PublicKey().Marshal(),
		sessionID,
		ssh.Marshal(signature),
		0,
	)
	if !verifySessionBindExtension(valid) {
		t.Fatal("a valid local session binding was rejected")
	}
	client, connection := newPipeAgentClient(t, approvalAgent{
		context: context.Background(),
		deps:    dependencies{stderr: io.Discard},
	})
	response, err := client.Extension(sessionBindExtensionName, valid)
	if err != nil || !bytes.Equal(response, []byte{sshAgentSuccessResponse}) {
		t.Fatalf("upstream agent server rejected session-bind: %x, %v", response, err)
	}
	if connection.state.binding == nil ||
		!bytes.Equal(connection.state.binding.hostKeyBlob, signer.PublicKey().Marshal()) ||
		!bytes.Equal(connection.state.binding.sessionID, sessionID) {
		t.Fatalf("session binding was not retained on its connection: %+v", connection.state.binding)
	}

	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-2] ^= 1
	if verifySessionBindExtension(tampered) {
		t.Fatal("a tampered session binding was accepted")
	}
	forwarded := sessionBindContents(
		signer.PublicKey().Marshal(),
		sessionID,
		ssh.Marshal(signature),
		1,
	)
	if verifySessionBindExtension(forwarded) {
		t.Fatal("a forwarded session binding was accepted")
	}
}

func TestNativeSSHUserauthIsBoundToTheVerifiedSession(t *testing.T) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, userPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	userSigner, err := ssh.NewSignerFromKey(userPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	binding := sshSessionBinding{
		hostKeyBlob: hostSigner.PublicKey().Marshal(),
		sessionID:   []byte("bound-session"),
	}
	data := userauthPayload(
		binding.sessionID,
		"root",
		"publickey-hostbound-v00@openssh.com",
		userSigner.PublicKey(),
		binding.hostKeyBlob,
	)
	request, err := parseSSHUserauthRequest(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySSHUserauthBinding(
		request,
		binding,
		userSigner.PublicKey().Marshal(),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSSHUserauthRequest(userauthPayload(
		binding.sessionID,
		"root\nspoofed",
		"publickey-hostbound-v00@openssh.com",
		userSigner.PublicKey(),
		binding.hostKeyBlob,
	)); err == nil {
		t.Fatal("an SSH username containing control characters was accepted")
	}
	operation := sshOperationForPayload(data, userSigner.PublicKey().Marshal(), &binding)
	if operation.Kind != "ssh.authentication" ||
		operation.RemoteUsername != "root" ||
		operation.SessionBinding != "verified" ||
		operation.ServerHostKeyFingerprint != ssh.FingerprintSHA256(hostSigner.PublicKey()) ||
		operation.SessionIDFingerprint != byteFingerprint(binding.sessionID) {
		t.Fatalf("unexpected native SSH operation: %+v", operation)
	}

	tamperedBinding := binding
	tamperedBinding.sessionID = []byte("another-session")
	if err := verifySSHUserauthBinding(
		request,
		tamperedBinding,
		userSigner.PublicKey().Marshal(),
	); err == nil {
		t.Fatal("a userauth request was accepted for a different session")
	}

	tamperedHost := append([]byte(nil), binding.hostKeyBlob...)
	tamperedHost[len(tamperedHost)-1] ^= 1
	tamperedBinding = binding
	tamperedBinding.hostKeyBlob = tamperedHost
	if err := verifySSHUserauthBinding(
		request,
		tamperedBinding,
		userSigner.PublicKey().Marshal(),
	); err == nil {
		t.Fatal("a host-bound userauth request was accepted for a different server key")
	}
}

func TestNativeSSHWithoutSessionBindStillReportsVerifiedPayloadFacts(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := []byte("unbound-session")
	data := userauthPayload(sessionID, "git", "publickey", signer.PublicKey(), nil)
	operation := sshOperationForPayload(data, signer.PublicKey().Marshal(), nil)
	if operation.Kind != "ssh.authentication" ||
		operation.RemoteUsername != "git" ||
		operation.SessionBinding != "unavailable" ||
		operation.ServerHostKeyFingerprint != "" ||
		operation.SessionIDFingerprint != byteFingerprint(sessionID) {
		t.Fatalf("unexpected unbound operation: %+v", operation)
	}
}

func TestUpstreamAgentServerPreservesReadOnlyBoundaryAndConnectionCache(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	identity := servedSSHIdentity{
		catalog: sshCatalogIdentity{
			ItemID: "item-read-only",
			Metadata: catalogSSHMetadata{
				Algorithm:     signer.PublicKey().Type(),
				Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
				PublicKeyBlob: base64URL(signer.PublicKey().Marshal()),
			},
			Title:   "Read-only key",
			Version: 1,
		},
		keyBlob: signer.PublicKey().Marshal(),
	}
	loads := 0
	client, _ := newPipeAgentClient(t, approvalAgent{
		context: context.Background(),
		deps:    dependencies{stderr: io.Discard},
		loadIdentities: func() ([]servedSSHIdentity, error) {
			loads++
			return []servedSSHIdentity{identity}, nil
		},
	})
	keys, err := client.List()
	if err != nil || len(keys) != 1 || !bytes.Equal(keys[0].Blob, identity.keyBlob) ||
		keys[0].Comment != "may:"+identity.catalog.Title {
		t.Fatalf("unexpected upstream identity list: %+v, %v", keys, err)
	}
	if loads != 1 {
		t.Fatalf("identity loader ran %d times after one list", loads)
	}

	_, unrelatedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedSigner, err := ssh.NewSignerFromKey(unrelatedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Sign(unrelatedSigner.PublicKey(), []byte("not configured")); err == nil {
		t.Fatal("an unconfigured identity was accepted")
	}
	if loads != 1 {
		t.Fatalf("signing discarded the per-connection identity snapshot; loader ran %d times", loads)
	}
	if _, err := client.Sign(keys[0], make([]byte, 64*1024+1)); err == nil {
		t.Fatal("a signing payload larger than 64 KiB was accepted")
	}

	if err := client.Add(sshagent.AddedKey{PrivateKey: privateKey}); err == nil {
		t.Fatal("the read-only agent accepted Add")
	}
	if err := client.Remove(keys[0]); err == nil {
		t.Fatal("the read-only agent accepted Remove")
	}
	if err := client.RemoveAll(); err == nil {
		t.Fatal("the read-only agent accepted RemoveAll")
	}
	if err := client.Lock([]byte("passphrase")); err == nil {
		t.Fatal("the read-only agent accepted Lock")
	}
	if err := client.Unlock([]byte("passphrase")); err == nil {
		t.Fatal("the read-only agent accepted Unlock")
	}
}

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

func TestAgentSocketIsPrivate(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "agent.sock")
	listener, err := listenApprovalAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected socket mode %v", info.Mode())
	}
}

func TestAgentListenerCancellationClosesActiveConnections(t *testing.T) {
	directory, err := os.MkdirTemp("", "ag-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := listenApprovalAgent(filepath.Join(directory, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	agent := approvalAgent{context: ctx, deps: dependencies{stderr: io.Discard}}
	result := make(chan error, 1)
	go func() {
		result <- agent.serveListener(ctx, listener)
	}()

	connection, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := sshagent.NewClient(connection)
	identities, err := client.List()
	if err != nil || len(identities) != 0 {
		t.Fatalf("agent did not accept the test connection: %+v, %v", identities, err)
	}

	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("canceled listener returned an error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled listener kept an active connection alive")
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(); err == nil {
		t.Fatal("active connection remained usable after cancellation")
	}
}

func TestAdapterReplacesOnlyTheSSHSocketEnvironment(t *testing.T) {
	result := withEnvironmentValue(
		[]string{"PATH=/usr/bin", "SSH_AUTH_SOCK=/native.sock", "OTHER=value"},
		"SSH_AUTH_SOCK",
		"/task/agent.sock",
	)
	joined := strings.Join(result, "\n")
	if strings.Count(joined, "SSH_AUTH_SOCK=") != 1 ||
		!strings.Contains(joined, "SSH_AUTH_SOCK=/task/agent.sock") ||
		!strings.Contains(joined, "PATH=/usr/bin") ||
		!strings.Contains(joined, "OTHER=value") {
		t.Fatalf("unexpected child environment: %v", result)
	}
}

func TestAgentUsesOneFixedSocket(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	first := defaultAgentSocket()
	second := defaultAgentSocket()
	if first != second || first != filepath.Join(os.Getenv("HOME"), ".onenod", "agent.sock") {
		t.Fatalf("agent socket is not fixed: %q %q", first, second)
	}
}

func TestGitSSHSIGNamespaceIsDetected(t *testing.T) {
	payload := new(bytes.Buffer)
	payload.WriteString("SSHSIG")
	writeWireString(payload, []byte("git"))
	writeWireString(payload, nil)
	writeWireString(payload, []byte("sha256"))
	writeWireString(payload, make([]byte, sha256.Size))
	operation := sshOperationForPayload(payload.Bytes(), []byte("irrelevant"), nil)
	if operation.Kind != "git.ssh-signature" || operation.Namespace != "git" {
		t.Fatalf("unexpected SSHSIG operation: %+v", operation)
	}
}

func TestSSHIdentityCacheIsPublicMetadataOnlyAndStrictlyPrivate(t *testing.T) {
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
	cachePath := filepath.Join(t.TempDir(), "ssh", "identities.json")
	catalog := []sshCatalogIdentity{{
		ItemID: "item-cache-1",
		Metadata: catalogSSHMetadata{
			Algorithm:     signer.PublicKey().Type(),
			Fingerprint:   ssh.FingerprintSHA256(signer.PublicKey()),
			PublicKey:     publicText,
			PublicKeyBlob: base64URL(keyBlob),
		},
		Title:   "Cached key",
		Version: 2,
	}}
	if err := writeSSHIdentityCache(cachePath, catalog); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cachePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected cache mode: %v %v", info, err)
	}
	identities, err := readSSHIdentityCache(cachePath)
	if err != nil || len(identities) != 1 || !bytes.Equal(identities[0].keyBlob, keyBlob) {
		t.Fatalf("unexpected cached identities: %+v %v", identities, err)
	}
	if err := os.Chmod(cachePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSHIdentityCache(cachePath); err == nil {
		t.Fatal("world-readable SSH identity cache was accepted")
	}
	if err := os.Chmod(cachePath, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, append(encoded, []byte("{}")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSHIdentityCache(cachePath); err == nil {
		t.Fatal("SSH identity cache with trailing JSON was accepted")
	}
	symlinkPath := filepath.Join(filepath.Dir(cachePath), "identities-link.json")
	if err := os.Symlink(cachePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readSSHIdentityCache(symlinkPath); err == nil {
		t.Fatal("symlinked SSH identity cache was accepted")
	}
}

func sessionBindContents(hostKey, sessionID, signature []byte, forwarded byte) []byte {
	payload := new(bytes.Buffer)
	writeWireString(payload, hostKey)
	writeWireString(payload, sessionID)
	writeWireString(payload, signature)
	payload.WriteByte(forwarded)
	return payload.Bytes()
}

func userauthPayload(
	sessionID []byte,
	username string,
	method string,
	key ssh.PublicKey,
	serverHostKey []byte,
) []byte {
	payload := new(bytes.Buffer)
	writeWireString(payload, sessionID)
	payload.WriteByte(50)
	writeWireString(payload, []byte(username))
	writeWireString(payload, []byte("ssh-connection"))
	writeWireString(payload, []byte(method))
	payload.WriteByte(1)
	writeWireString(payload, []byte(key.Type()))
	writeWireString(payload, key.Marshal())
	if method == "publickey-hostbound-v00@openssh.com" {
		writeWireString(payload, serverHostKey)
	}
	return payload.Bytes()
}

func base64URL(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func TestAgentPrivateVersionExtensionReportsRunningBinaryIdentity(t *testing.T) {
	if versionExtensionName != "version@github.com/Vizards/OneNod" {
		t.Fatalf("private extension must remain bound to the canonical repository path: %q", versionExtensionName)
	}
	client, _ := newPipeAgentClient(t, approvalAgent{
		context: context.Background(),
		deps:    dependencies{stderr: io.Discard},
	})
	response, err := client.Extension(versionExtensionName, nil)
	if err != nil || len(response) < 2 || response[0] != sshAgentSuccessResponse {
		t.Fatalf("version extension failed: %x, %v", response, err)
	}
	reader := wireReader{value: response[1:]}
	encoded, err := reader.string()
	if err != nil || !reader.done() {
		t.Fatal("invalid version extension framing")
	}
	var version agentRuntimeVersion
	if json.Unmarshal(encoded, &version) != nil || version.Version != productVersion ||
		version.SourceCommit != sourceCommit || version.ClientProtocol != mayClientProtocol {
		t.Fatalf("unexpected version metadata %+v", version)
	}
	if _, err := client.Extension(versionExtensionName, []byte{0}); err == nil {
		t.Fatal("version extension accepted trailing data")
	}
	if _, err := client.Extension("unsupported@example.com", nil); !errors.Is(err, sshagent.ErrExtensionUnsupported) {
		t.Fatalf("unsupported extension returned %v", err)
	}
}

func newPipeAgentClient(
	t *testing.T,
	agent approvalAgent,
) (sshagent.ExtendedAgent, *approvalAgentConnection) {
	t.Helper()
	serverConnection, clientConnection := net.Pipe()
	connection := &approvalAgentConnection{
		agent: agent,
		state: sshAgentConnectionState{client: unknownLocalClientContext()},
	}
	result := make(chan error, 1)
	go func() {
		result <- sshagent.ServeAgent(connection, serverConnection)
	}()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
		<-result
	})
	return sshagent.NewClient(clientConnection), connection
}
