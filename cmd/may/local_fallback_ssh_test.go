package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func TestSecretAndSSHLocalFallbackReturnOnlyVerifiedResults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vaultID := strings.Repeat("d", 26)
	writeFallbackTestConfig(t, "Test Family", vaultID)
	identity, signer := localFallbackTestIdentity(t)
	backend := &fakeLocalOnePasswordBackend{
		vault:  localFallbackVault{ID: vaultID, Title: localFallbackVaultTitle},
		secret: "dummy-local-secret",
	}
	deps := dependencies{
		localOnePassword: func(context.Context, string) (localOnePasswordBackend, error) {
			return backend, nil
		},
		localSSHAgent: func(context.Context) (localSSHAgent, error) {
			return &fakeLocalSSHAgent{
				keys: []*sshagent.Key{{Blob: identity.keyBlob}}, signer: signer,
			}, nil
		},
		stderr: io.Discard,
	}
	rateLimit := &gatewayHTTPError{Code: "onepassword_rate_limited", Status: http.StatusTooManyRequests}
	secret, err := readSecretWithLocalFallback(
		context.Background(), rateLimit, deps,
		strings.Repeat("e", 26), "password", 1,
	)
	if err != nil || secret != "dummy-local-secret" || backend.readCalls != 1 {
		t.Fatalf("secret fallback failed: value=%q calls=%d err=%v", secret, backend.readCalls, err)
	}
	if backend.readVault != vaultID || backend.readItem != strings.Repeat("e", 26) ||
		backend.readField != "password" || backend.readExpected != 1 {
		t.Fatalf("fallback changed the approved target: %+v", backend)
	}
	if _, err := readSecretWithLocalFallback(
		context.Background(), errors.New("gateway returned HTTP 502"), deps,
		strings.Repeat("e", 26), "password", 1,
	); err == nil || backend.readCalls != 1 {
		t.Fatalf("generic gateway failure used secret fallback: calls=%d err=%v", backend.readCalls, err)
	}

	payload := []byte("dummy-signing-payload")
	result, err := signWithConfiguredLocalSSHAgent(
		context.Background(), deps, identity, "ssh-ed25519", payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := base64.RawURLEncoding.Strict().DecodeString(result.SignatureBlob)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.ParsePublicKey(identity.keyBlob)
	if err != nil || publicKey.Verify(payload, &ssh.Signature{Format: result.Algorithm, Blob: blob}) != nil {
		t.Fatal("local SSH fallback returned a signature that did not verify")
	}
}
