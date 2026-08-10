package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type fakeLocalOnePasswordBackend struct {
	catalog      catalogSearchResponse
	catalogCtx   context.Context
	clientCtx    context.Context
	clientCtxErr error
	readCalls    int
	readExpected int64
	readField    string
	readItem     string
	readVault    string
	resolveCalls int
	resolveCtxs  []context.Context
	searchCalls  int
	searchQuery  string
	searchVault  string
	secret       string
	vault        localFallbackVault
	vaultError   error
}

func (backend *fakeLocalOnePasswordBackend) ResolveAgentVault(
	ctx context.Context,
) (localFallbackVault, error) {
	backend.resolveCalls++
	backend.resolveCtxs = append(backend.resolveCtxs, ctx)
	return backend.vault, backend.vaultError
}

func (backend *fakeLocalOnePasswordBackend) SearchCatalog(
	ctx context.Context,
	vaultID string,
	query string,
) (catalogSearchResponse, error) {
	backend.searchCalls++
	backend.catalogCtx = ctx
	if backend.clientCtx != nil {
		backend.clientCtxErr = backend.clientCtx.Err()
	}
	backend.searchVault = vaultID
	backend.searchQuery = query
	return backend.catalog, nil
}

func (backend *fakeLocalOnePasswordBackend) ReadSecret(
	_ context.Context,
	vaultID string,
	itemID string,
	fieldID string,
	expectedVersion int64,
) (string, error) {
	backend.readCalls++
	backend.readVault = vaultID
	backend.readItem = itemID
	backend.readField = fieldID
	backend.readExpected = expectedVersion
	return backend.secret, nil
}

type fakeLocalSSHAgent struct {
	keys   []*sshagent.Key
	signer ssh.Signer
}

func (agent *fakeLocalSSHAgent) List() ([]*sshagent.Key, error) {
	return agent.keys, nil
}

func (agent *fakeLocalSSHAgent) SignWithFlags(
	_ ssh.PublicKey,
	data []byte,
	_ sshagent.SignatureFlags,
) (*ssh.Signature, error) {
	return agent.signer.Sign(rand.Reader, data)
}

func (agent *fakeLocalSSHAgent) Close() error { return nil }

type lineCountingReader struct {
	reader io.Reader
	lines  int
}

func (reader *lineCountingReader) Read(buffer []byte) (int, error) {
	count, err := reader.reader.Read(buffer)
	for _, value := range buffer[:count] {
		if value == '\n' {
			reader.lines++
		}
	}
	return count, err
}

func TestLocalFallbackConfigurationGuidesAndVerifiesAgentVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	vaultID := strings.Repeat("a", 26)
	identity, signer := localFallbackTestIdentity(t)
	agentConfig := filepath.Join(home, ".config", "1Password", "ssh", "agent.toml")
	if err := os.MkdirAll(filepath.Dir(agentConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentConfig, []byte("[[ssh-keys]]\nvault = \"Agent\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeLocalOnePasswordBackend{
		vault: localFallbackVault{ID: vaultID, Title: localFallbackVaultTitle},
		catalog: catalogSearchResponse{Items: []catalogItemResult{{
			ItemID:  identity.catalog.ItemID,
			SSH:     &identity.catalog.Metadata,
			Title:   identity.catalog.Title,
			Version: identity.catalog.Version,
		}}},
	}
	var clientContexts []context.Context
	input := &lineCountingReader{reader: strings.NewReader("y\ny\n")}
	factoryPromptLines := -1
	var output strings.Builder
	err := runConfigureLocalFallback(
		[]string{"apply", "--account", "Test Family"},
		dependencies{
			localOnePassword: func(ctx context.Context, _ string) (localOnePasswordBackend, error) {
				factoryPromptLines = input.lines
				clientContexts = append(clientContexts, ctx)
				backend.clientCtx = ctx
				return backend, nil
			},
			localSSHAgent: func(context.Context) (localSSHAgent, error) {
				return &fakeLocalSSHAgent{
					keys: []*sshagent.Key{{
						Blob: identity.keyBlob,
					}},
					signer: signer,
				}, nil
			},
			stdin:  input,
			stderr: io.Discard,
			stdout: &output,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(backend.resolveCtxs) != 1 || backend.catalogCtx == nil || backend.resolveCtxs[0] != backend.catalogCtx {
		t.Fatal("Agent Vault resolution and catalog validation did not share one post-confirmation operation context")
	}
	if len(clientContexts) != 1 {
		t.Fatalf("configuration initialized the SDK an unexpected number of times: %d", len(clientContexts))
	}
	if factoryPromptLines != 2 {
		t.Fatalf("SDK initialized before all human configuration prompts completed: %d lines", factoryPromptLines)
	}
	if backend.clientCtxErr != nil {
		t.Fatalf("SDK client context was canceled before catalog validation: %v", backend.clientCtxErr)
	}
	for _, expected := range []string{
		"onepassword_rate_limited",
		"Integrate with 1Password SDKs",
		agentConfig,
		"vault = \"Agent\"",
		"account = \"Test Family\"",
		"Verified 1 Agent Vault SSH key",
		"must continue to call may",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("configuration output omitted %q:\n%s", expected, output.String())
		}
	}
	config, found, err := readLocalFallbackConfig()
	if err != nil || !found || config.Account != "Test Family" || config.VaultID != vaultID {
		t.Fatalf("unexpected stored fallback configuration: %+v found=%t err=%v", config, found, err)
	}
	path, err := localFallbackConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("fallback configuration is not private: info=%v err=%v", info, err)
	}
	if err := runConfigureLocalFallback(
		[]string{"restore"},
		dependencies{stdout: io.Discard},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fallback config remained after restore: %v", err)
	}
	if _, err := os.Stat(agentConfig); err != nil {
		t.Fatalf("restore changed the user-owned agent.toml: %v", err)
	}
}

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

func localFallbackTestIdentity(t *testing.T) (servedSSHIdentity, ssh.Signer) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	blob := publicKey.Marshal()
	metadata := catalogSSHMetadata{
		Algorithm: publicKey.Type(), Fingerprint: ssh.FingerprintSHA256(publicKey),
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))),
		PublicKeyBlob: base64.RawURLEncoding.EncodeToString(blob),
	}
	return servedSSHIdentity{
		catalog: sshCatalogIdentity{
			ItemID: strings.Repeat("s", 26), Metadata: metadata,
			Title: "Agent SSH", Version: 1,
		},
		keyBlob: blob,
	}, signer
}

func writeFallbackTestConfig(t *testing.T, account string, vaultID string) {
	t.Helper()
	if err := writeLocalFallbackConfig(localFallbackConfig{
		Account: account, SchemaVersion: localFallbackConfigSchema,
		VaultID: vaultID, VaultTitle: localFallbackVaultTitle,
	}); err != nil {
		t.Fatal(err)
	}
}

func pointerTo[T any](value T) *T { return &value }
