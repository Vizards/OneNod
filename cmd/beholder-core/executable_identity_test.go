package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

func TestTrustedExecutableUsesRootOwnershipExactFileAndSHA256WithoutDeveloperID(t *testing.T) {
	encoded, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	identity, err := captureTrustedExecutable("/bin/echo", hex.EncodeToString(digest[:]), true)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.matches("/bin/echo") || identity.matches("/usr/bin/true") {
		t.Fatal("exact trusted executable identity was not enforced")
	}
	if _, err := captureTrustedExecutable("/bin/echo", string(make([]byte, 64)), true); err == nil {
		t.Fatal("wrong trusted executable digest was accepted")
	}
}

func TestProductionHookIdentityAcceptsRootControlledHashWithCodexAncestry(t *testing.T) {
	encoded, err := os.ReadFile("/bin/echo")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	core, err := newBrokerWithKey(
		t.TempDir(), "production", "/bin/echo", hex.EncodeToString(digest[:]),
		time.Minute, make([]byte, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	peer := processChain{
		Nodes: []processIdentity{
			{PID: 10, Path: "/bin/echo"},
			{PID: 11, Path: "/Applications/ChatGPT.app/codex"},
			{PID: 12, Path: "/Applications/ChatGPT.app/ChatGPT"},
		},
		Roles: []string{"managed-hook", "codex-runtime", "codex-desktop-host"},
	}
	owner, writable, code := core.validateHookPeer(peer)
	if code != "" || owner != "root" || writable {
		t.Fatalf("root-controlled hook identity was rejected: owner=%s writable=%t code=%s", owner, writable, code)
	}
	// A supervisor between the pinned worker and Codex is not an authority.
	peer.Nodes = append(peer.Nodes[:1], append([]processIdentity{{PID: 13, Path: "/untrusted/guard"}}, peer.Nodes[1:]...)...)
	peer.Roles = []string{"managed-hook", "managed-hook", "codex-runtime", "codex-desktop-host"}
	if _, _, code := core.validateHookPeer(peer); code != "" {
		t.Fatalf("pinned worker with a supervisor was rejected: %s", code)
	}
	peer.Nodes[0].Path = "/usr/bin/true"
	if _, _, code := core.validateHookPeer(peer); code != "managed-hook-identity-mismatch" {
		t.Fatalf("different executable was accepted: %s", code)
	}
}

func TestInstalledContextHookBasenameHasTheManagedHookRole(t *testing.T) {
	t.Parallel()
	path := "/Library/Application Support/Beholder/codex-hooks/beholder-e1-context"
	if role := processRole(path); role != "managed-hook" {
		t.Fatalf("installed v2 hook role = %q, want managed-hook", role)
	}
}
