package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"

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

func (backend *fakeLocalOnePasswordBackend) ReadCatalogItem(
	_ context.Context,
	_ string,
	itemID string,
) (catalogItemResult, error) {
	for _, item := range backend.catalog.Items {
		if item.ItemID == itemID {
			return item, nil
		}
	}
	return catalogItemResult{}, nil
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

func (backend *fakeLocalOnePasswordBackend) ReadCredential(
	ctx context.Context,
	vaultID string,
	itemID string,
	fieldIDs []string,
	expectedVersion int64,
) (map[string]string, error) {
	values := make(map[string]string, len(fieldIDs))
	for _, fieldID := range fieldIDs {
		value, err := backend.ReadSecret(
			ctx,
			vaultID,
			itemID,
			fieldID,
			expectedVersion,
		)
		if err != nil {
			return nil, err
		}
		values[fieldID] = value
	}
	return values, nil
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
