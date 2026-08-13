package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandDiscoveryCreatesUserLinkWithoutProfileChangeWhenPathIsReady(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, userAgentDirectoryName, "bin", "may")
	t.Setenv("PATH", filepath.Join(home, ".local", "bin")+string(os.PathListSeparator)+"/usr/bin")
	plan, err := planCommandDiscovery(home, target, dependencies{
		stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard,
	})
	if err != nil || plan.writeProfile {
		t.Fatalf("unexpected command plan: %+v %v", plan, err)
	}
	transaction, err := plan.apply()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".local", "bin", "may")
	if targetValue, err := os.Readlink(link); err != nil || filepath.IsAbs(targetValue) {
		t.Fatalf("user command is not a relative symlink: %q %v", targetValue, err)
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("rollback retained new user command: %v", err)
	}
}

func TestCommandDiscoveryShowsAndRollsBackBoundedZprofileChange(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".zprofile")
	original := []byte("export EDITOR=vim\n")
	if err := os.WriteFile(profile, original, 0o640); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/usr/bin:/bin")
	var output strings.Builder
	plan, err := planCommandDiscovery(
		home,
		filepath.Join(home, userAgentDirectoryName, "bin", "may"),
		dependencies{stdin: strings.NewReader("\n"), stdout: &output, stderr: io.Discard},
	)
	if err != nil || !plan.writeProfile {
		t.Fatalf("default-yes command plan failed: %+v %v", plan, err)
	}
	if !strings.Contains(output.String(), commandPathBlockStart) ||
		!strings.Contains(output.String(), "[Y/n]") {
		t.Fatalf("bounded profile plan was not shown:\n%s", output.String())
	}
	transaction, err := plan.apply()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(profile)
	if err != nil || !strings.Contains(string(updated), commandPathBlock()) {
		t.Fatalf("managed profile block missing: %q %v", updated, err)
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(profile)
	if err != nil || string(restored) != string(original) {
		t.Fatalf("profile rollback changed prior bytes: %q %v", restored, err)
	}
	if info, err := os.Stat(profile); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("profile rollback changed mode: %v %v", info, err)
	}
}

func TestCommandDiscoveryDeclineLeavesShellProfileAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", "/usr/bin:/bin")
	plan, err := planCommandDiscovery(
		home,
		filepath.Join(home, userAgentDirectoryName, "bin", "may"),
		dependencies{stdin: strings.NewReader("n\n"), stdout: io.Discard, stderr: io.Discard},
	)
	if err != nil || plan.writeProfile {
		t.Fatalf("declined command plan = %+v, %v", plan, err)
	}
	transaction, err := plan.apply()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".zprofile")); !os.IsNotExist(err) {
		t.Fatalf("declined profile change created ~/.zprofile: %v", err)
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
}

func TestCommandDiscoveryNeverOverwritesAnUnrelatedMay(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "may")
	if err := os.WriteFile(link, []byte("different\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := planCommandDiscovery(
		home,
		filepath.Join(home, userAgentDirectoryName, "bin", "may"),
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	)
	if err != nil || plan.manageLink {
		t.Fatalf("unrelated command was considered manageable: %+v %v", plan, err)
	}
	transaction, err := plan.apply()
	if err != nil || transaction != nil {
		t.Fatalf("unrelated command produced a transaction: %+v %v", transaction, err)
	}
	content, err := os.ReadFile(link)
	if err != nil || string(content) != "different\n" {
		t.Fatalf("unrelated command changed: %q %v", content, err)
	}
}
