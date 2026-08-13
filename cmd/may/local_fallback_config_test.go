package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sshagent "golang.org/x/crypto/ssh/agent"
)

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
