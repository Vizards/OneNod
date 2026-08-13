package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"
)

func TestCatalogFallsBackOnlyForAuthenticatedRateLimitCode(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeFallbackTestConfig(t, "Test Family", strings.Repeat("b", 26))
	backend := &fakeLocalOnePasswordBackend{
		vault: localFallbackVault{ID: strings.Repeat("b", 26), Title: localFallbackVaultTitle},
		catalog: catalogSearchResponse{Items: []catalogItemResult{{
			ItemID: strings.Repeat("c", 26), Title: "Local item", Version: 1,
		}}},
	}
	credential, err := credentialFromSeed("local-fallback-catalog")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		code         string
		status       int
		wantFallback bool
	}{
		{code: "onepassword_rate_limited", status: http.StatusTooManyRequests, wantFallback: true},
		{code: "onepassword_rate_limited", status: http.StatusBadGateway, wantFallback: false},
		{code: "private_diagnostic", status: http.StatusTooManyRequests, wantFallback: false},
	} {
		backend.searchCalls = 0
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.Header().Set(headerGatewayErrorCode, test.code)
			response.WriteHeader(test.status)
			_, _ = io.WriteString(response, `{"ok":false}`)
		}))
		client, err := newAPIClient(server.URL, credential, server.Client())
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		var diagnostics strings.Builder
		response, requestErr := searchCatalogWithLocalFallback(
			context.Background(),
			client,
			"Local",
			dependencies{
				localOnePassword: func(context.Context, string) (localOnePasswordBackend, error) {
					return backend, nil
				},
				stderr: &diagnostics,
			},
		)
		server.Close()
		if test.wantFallback {
			if requestErr != nil || len(response.Items) != 1 || backend.searchCalls != 1 ||
				backend.searchVault != strings.Repeat("b", 26) || backend.searchQuery != "Local" ||
				!strings.Contains(diagnostics.String(), "quota is exhausted") {
				t.Fatalf("authenticated rate limit did not use fallback: response=%+v calls=%d err=%v diagnostics=%q", response, backend.searchCalls, requestErr, diagnostics.String())
			}
		} else if requestErr == nil || backend.searchCalls != 0 {
			t.Fatalf("non-rate-limit response used fallback: calls=%d err=%v", backend.searchCalls, requestErr)
		}
	}
}

func TestLocalCatalogProjectionNeverReturnsFieldValues(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateValue := "dummy-private-key-material"
	item := onepassword.Item{
		ID: strings.Repeat("f", 26), Title: "Agent SSH", Category: onepassword.ItemCategorySSHKey,
		VaultID: strings.Repeat("a", 26), Version: 2, UpdatedAt: time.Now(),
		Fields: []onepassword.ItemField{
			{ID: "private_key", Title: "private key", FieldType: onepassword.ItemFieldTypeSSHKey, Value: privateValue,
				Details: pointerTo(onepassword.NewItemFieldDetailsTypeVariantSSHKey(&onepassword.SSHKeyAttributes{
					PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))),
					Fingerprint: ssh.FingerprintSHA256(sshPublic),
					KeyType:     "Ed25519",
				}))},
		},
	}
	projected, err := projectLocalCatalogItem(item, item.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), privateValue) || projected.SSH == nil ||
		projected.SSH.Fingerprint != ssh.FingerprintSHA256(sshPublic) {
		t.Fatalf("local catalog projection exposed a value or lost SSH metadata: %s", encoded)
	}
}
