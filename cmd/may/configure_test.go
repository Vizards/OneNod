package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

type testReaderFunc func([]byte) (int, error)

func (read testReaderFunc) Read(buffer []byte) (int, error) {
	return read(buffer)
}

func TestSSHConfigurationDetectsIdentityAgentConflicts(t *testing.T) {
	if !hasSSHIdentityAgentConflict([]byte("Host github.com\n  IdentityAgent ~/.1password/agent.sock\n")) {
		t.Fatal("existing IdentityAgent was not detected")
	}
	if hasSSHIdentityAgentConflict([]byte("# IdentityAgent ~/.1password/agent.sock\nHost *\n  IdentitiesOnly yes\n")) {
		t.Fatal("comment was treated as a conflict")
	}
	settings := inspectSSHIdentityAgentSettings([]byte(
		"IdentityAgent $SSH_AUTH_SOCK\nHost github.com\n  IdentityAgent ~/.1password/agent.sock\n",
	))
	if len(settings) != 2 || settings[0].Line != 1 || settings[0].Scope != "global defaults" ||
		settings[1].Line != 3 || settings[1].Scope != "Host github.com" {
		t.Fatalf("IdentityAgent settings were not reported with their scopes: %#v", settings)
	}
}

func TestNormalizedSigningKeyUsesGitKeyLiteral(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	value, err := normalizedSigningKey(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, "key::ssh-ed25519 ") || strings.Contains(value, "\n") {
		t.Fatalf("Git signing key was not normalized as a key:: literal: %q", value)
	}
}

func TestSSHConfigurationApplyAndRestorePreserveUnrelatedContent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDirectory, "config")
	original := []byte("Host example.test\n  User example\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	deps := dependencies{stdin: strings.NewReader("y\n"), stdout: &output, stderr: io.Discard}
	if err := runConfigureSSH([]string{"apply"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "IdentityAgent") ||
		!strings.Contains(output.String(), "~/.onenod/agent.sock") ||
		!strings.Contains(output.String(), "[y/N]") {
		t.Fatalf("opt-in plan was not displayed for an otherwise unconfigured SSH client:\n%s", output.String())
	}
	configured, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(configured) != sshManagedBlock()+"\n"+string(original) {
		t.Fatalf("unrelated SSH content changed:\n%s", configured)
	}
	info, err := os.Stat(configurationReceiptPath(home))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("configuration receipt is not private: info=%v err=%v", info, err)
	}
	edited := bytes.Replace(
		configured,
		[]byte("~/.onenod/agent.sock"),
		[]byte("~/.other/agent.sock"),
		1,
	)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runConfigureSSH([]string{"apply"}, deps); err == nil {
		t.Fatal("apply accepted an edited managed block")
	}
	if err := runConfigureSSH([]string{"restore"}, deps); err == nil {
		t.Fatal("restore accepted an edited managed block")
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, edited) {
		t.Fatalf("a failed-closed operation changed the edited block: %q %v", unchanged, err)
	}
	if err := os.WriteFile(path, configured, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runConfigureSSH([]string{"restore"}, deps); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(original) {
		t.Fatalf("SSH restore did not preserve the original bytes: %q", restored)
	}
}

func TestSSHConfigurationShowsAndConfirmsEffectiveIdentityAgentOverride(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDirectory, "config")
	original := []byte("Host *\n  IdentityAgent ~/.1password/agent.sock\nHost github.com\n  User git\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	var deniedOutput strings.Builder
	denied := dependencies{
		stdin: strings.NewReader("n\n"), stdout: &deniedOutput, stderr: io.Discard,
	}
	if err := runConfigureSSH([]string{"apply"}, denied); err == nil {
		t.Fatalf("declined IdentityAgent replacement did not fail closed: %v", err)
	}
	if !strings.Contains(deniedOutput.String(), "IdentityAgent ~/.1password/agent.sock") ||
		!strings.Contains(deniedOutput.String(), "~/.onenod/agent.sock") ||
		!strings.Contains(deniedOutput.String(), "[y/N]") {
		t.Fatalf("current setting and default-no decision were not displayed:\n%s", deniedOutput.String())
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(unchanged, original) {
		t.Fatalf("declined replacement changed SSH config: %q %v", unchanged, err)
	}

	var acceptedOutput strings.Builder
	accepted := dependencies{
		stdin: strings.NewReader("y\n"), stdout: &acceptedOutput, stderr: io.Discard,
	}
	if err := runConfigureSSH([]string{"apply"}, accepted); err != nil {
		t.Fatal(err)
	}
	configured, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(configured) != sshManagedBlock()+"\n"+string(original) {
		t.Fatalf("OneNod block did not take precedence while preserving prior directives:\n%s", configured)
	}
	if !managedSSHBlockTakesPrecedence(configured, sshManagedBlock()) {
		t.Fatal("managed block does not take first-value precedence")
	}
	if err := runConfigureSSH([]string{"restore"}, accepted); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("restore did not recover the exact prior directives: %q %v", restored, err)
	}
}

func TestGitSigningConfigurationRequiresOptInAndRestoresExactPriorValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for key, value := range map[string]string{
		"gpg.format":      "openpgp",
		"user.signingkey": "legacy-openpgp-key",
		"commit.gpgsign":  "false",
	} {
		if err := setGitGlobalValue(key, value); err != nil {
			t.Fatal(err)
		}
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic)))
	normalizedKey, err := normalizedSigningKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	var deniedOutput strings.Builder
	err = runConfigureGitSigning(
		[]string{"apply", "--signing-key", publicKey},
		dependencies{stdin: strings.NewReader("n\n"), stdout: &deniedOutput, stderr: io.Discard},
	)
	if err == nil {
		t.Fatalf("declined Git signing setup did not fail closed: %v", err)
	}
	for _, expected := range []string{
		"gpg.format:",
		`current:  "openpgp"`,
		`proposed: "ssh"`,
		"gpg.ssh.program:",
		"[y/N]",
	} {
		if !strings.Contains(deniedOutput.String(), expected) {
			t.Fatalf("Git signing plan omitted %q:\n%s", expected, deniedOutput.String())
		}
	}
	if values, err := gitGlobalValues("gpg.format"); err != nil || len(values) != 1 || values[0] != "openpgp" {
		t.Fatalf("declined Git signing setup changed gpg.format: %#v %v", values, err)
	}
	if _, err := os.Stat(configurationReceiptPath(home)); !os.IsNotExist(err) {
		t.Fatalf("declined Git signing setup created a receipt: %v", err)
	}

	var acceptedOutput strings.Builder
	err = runConfigureGitSigning(
		[]string{"apply", "--signing-key", publicKey},
		dependencies{stdin: strings.NewReader("y\n"), stdout: &acceptedOutput, stderr: io.Discard},
	)
	if err != nil {
		t.Fatal(err)
	}
	desired := map[string]string{
		"gpg.format":      "ssh",
		"gpg.ssh.program": filepath.Join(home, userAgentDirectoryName, "bin", gitSignAdapterBinaryName),
		"user.signingkey": normalizedKey,
		"commit.gpgsign":  "true",
	}
	for key, expected := range desired {
		values, err := gitGlobalValues(key)
		if err != nil || len(values) != 1 || values[0] != expected {
			t.Fatalf("Git key %s was not applied: %#v %v", key, values, err)
		}
	}
	if err := runConfigureGitSigning(
		[]string{"restore"},
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]string{
		"gpg.format":      "openpgp",
		"user.signingkey": "legacy-openpgp-key",
		"commit.gpgsign":  "false",
	} {
		values, err := gitGlobalValues(key)
		if err != nil || len(values) != 1 || values[0] != expected {
			t.Fatalf("Git key %s was not restored: %#v %v", key, values, err)
		}
	}
	if values, err := gitGlobalValues("gpg.ssh.program"); err != nil || len(values) != 0 {
		t.Fatalf("previously unset gpg.ssh.program was not restored: %#v %v", values, err)
	}
}

func TestGitSigningConfigurationRefusesConcurrentEditAfterConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := setGitGlobalValue("gpg.format", "openpgp"); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic)))
	answer := strings.NewReader("y\n")
	changed := false
	stdin := testReaderFunc(func(buffer []byte) (int, error) {
		if !changed {
			changed = true
			if err := setGitGlobalValue("gpg.format", "changed-during-review"); err != nil {
				t.Fatal(err)
			}
		}
		return answer.Read(buffer)
	})
	err = runConfigureGitSigning(
		[]string{"apply", "--signing-key", publicKey},
		dependencies{stdin: stdin, stdout: io.Discard, stderr: io.Discard},
	)
	if err == nil {
		t.Fatalf("concurrent Git edit was not rejected: %v", err)
	}
	values, readErr := gitGlobalValues("gpg.format")
	if readErr != nil || len(values) != 1 || values[0] != "changed-during-review" {
		t.Fatalf("concurrent Git edit was overwritten: %#v %v", values, readErr)
	}
}

func TestSSHConfigurationRefusesAConcurrentEditAfterConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDirectory := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sshDirectory, "config")
	original := []byte("Host *\n  IdentityAgent ~/.1password/agent.sock\n")
	changed := []byte("Host *\n  IdentityAgent ~/.edited/agent.sock\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	answer := strings.NewReader("y\n")
	changedOnce := false
	stdin := testReaderFunc(func(buffer []byte) (int, error) {
		if !changedOnce {
			changedOnce = true
			if err := os.WriteFile(path, changed, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return answer.Read(buffer)
	})
	err := runConfigureSSH(
		[]string{"apply"},
		dependencies{stdin: stdin, stdout: io.Discard, stderr: io.Discard},
	)
	if err == nil {
		t.Fatalf("concurrent SSH edit was not rejected: %v", err)
	}
	current, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(current, changed) {
		t.Fatalf("concurrent SSH edit was overwritten: %q %v", current, readErr)
	}
}

func TestConfigurationReceiptMustRemainPrivateAndStrict(t *testing.T) {
	home := t.TempDir()
	path := configurationReceiptPath(home)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigurationReceipt(home); err == nil {
		t.Fatal("configuration receipt with unknown fields was accepted")
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readConfigurationReceipt(home); err == nil {
		t.Fatal("group-readable configuration receipt was accepted")
	}
}
