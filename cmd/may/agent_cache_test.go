package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
	encoded, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("Cached key")) || bytes.Contains(bytes.ToLower(encoded), []byte("title")) {
		t.Fatalf("private item title was persisted in the SSH inventory cache: %s", encoded)
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
	encoded, err = os.ReadFile(cachePath)
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

func TestSSHIdentityLoaderUsesVerifiedCacheUntilExplicitRefresh(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyBlob := signer.PublicKey().Marshal()
	cachePath := filepath.Join(t.TempDir(), "ssh", "identities.json")
	if err := writeSSHIdentityCache(cachePath, []sshCatalogIdentity{{
		ItemID: "item-ttl-1",
		Metadata: catalogSSHMetadata{
			Algorithm: signer.PublicKey().Type(), Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()),
			PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))),
			PublicKeyBlob: base64URL(keyBlob),
		},
		Version: 4,
	}}); err != nil {
		t.Fatal(err)
	}
	backend := &recordingKeychainBackend{loadErr: errors.New("catalog unavailable")}
	loader := newSSHIdentityLoader(cachePath, cliConfig{
		origin: "https://onenod.example.workers.dev",
	}, dependencies{
		keychain: keychainStore{backend: backend}, stderr: io.Discard,
	})
	identities, err := loader()
	if err != nil || len(identities) != 1 || backend.account != "" {
		t.Fatalf("verified cache unnecessarily refreshed: identities=%d account=%q err=%v", len(identities), backend.account, err)
	}
	old := time.Now().Add(-365 * 24 * time.Hour)
	if err := os.Chtimes(cachePath, old, old); err != nil {
		t.Fatal(err)
	}
	identities, err = loader()
	if err != nil || len(identities) != 1 {
		t.Fatalf("verified cache was not served: identities=%d err=%v", len(identities), err)
	}
	if backend.account != "" {
		t.Fatalf("cache age triggered an implicit catalog refresh: account=%q", backend.account)
	}
}
