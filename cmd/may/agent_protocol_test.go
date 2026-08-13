package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

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
		ScopeKind:   "application",
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
