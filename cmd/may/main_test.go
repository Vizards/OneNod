package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandHelpRunsBeforeConfigurationCredentialsAndNetwork(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, userAgentEnvFileName), []byte("BROKEN=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, args := range [][]string{
		{"--help"},
		{"help", "version"},
		{"version", "--help"},
		{"install", "--help"},
		{"preflight", "--help"},
		{"enroll", "-h"},
		{"catalog", "search", "--help"},
		{"read", "--help"},
		{"secret", "read", "--help"},
		{"item", "create", "--help"},
		{"item", "patch", "--help"},
		{"item", "archive", "--help"},
		{"ssh", "public-key", "export", "--help"},
		{"agent", "status", "--help"},
		{"configure", "ssh", "--help"},
		{"configure", "git-signing", "apply", "--help"},
		{"configure", "local-fallback", "apply", "--help"},
		{"update", "check", "--help"},
		{"dev", "verify-release", "--help"},
		{"operator", "init", "--help"},
		{"operator", "revoke-cloudflare", "--help"},
		{"--origin", "https://ignored.example.workers.dev", "catalog", "search", "--help"},
	} {
		name := strings.NewReplacer("-", "_", " ", "_").Replace(strings.Join(args, "_"))
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			backend := &recordingKeychainBackend{
				loadErr: errors.New("credentials must not be loaded for help"),
			}
			err := runCLI(args, dependencies{
				keychain: keychainStore{backend: backend},
				stderr:   &stderr,
				stdin:    strings.NewReader(""),
				stdout:   io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(stderr.String()) == "" {
				t.Fatal("help output was empty")
			}
			if backend.account != "" {
				t.Fatal("help loaded requester credentials")
			}
		})
	}
}
