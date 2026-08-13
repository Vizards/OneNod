package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstalledUserOriginRequiresOneStrictNonSecretEntry(t *testing.T) {
	const origin = "https://onenod.example-account.workers.dev"
	actual, err := parseInstalledUserOrigin("ONENOD_ORIGIN=" + origin + "\n")
	if err != nil || actual != origin {
		t.Fatalf("origin %q returned %v", actual, err)
	}
	for _, invalid := range []string{
		"ONENOD_ORIGIN=" + origin,
		"ONENOD_ORIGIN=" + origin + "\r\n",
		"ONENOD_ORIGIN=" + origin + "\nEXTRA=value\n",
		"BOOTSTRAP_TOKEN=dummy\n",
		"ONENOD_ORIGIN=https://onenod.example-account.workers.dev/path\n",
	} {
		if _, err := parseInstalledUserOrigin(invalid); err == nil {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestReadInstalledUserOriginRejectsLooseModeAndSymlink(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "env")
	if err := os.WriteFile(path, []byte("ONENOD_ORIGIN=https://onenod.example.workers.dev\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalledUserOrigin(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalledUserOrigin(path); err == nil {
		t.Fatal("loose mode accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalledUserOrigin(link); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestEnvironmentOriginOverridesUserConfiguration(t *testing.T) {
	t.Setenv(userAgentOriginKey, "https://explicit.example.workers.dev")
	origin, err := resolveDefaultConfiguredOrigin()
	if err != nil || origin != "https://explicit.example.workers.dev" {
		t.Fatalf("%q %v", origin, err)
	}
}

func TestHelpDoesNotReadBrokenInstalledConfiguration(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, userAgentEnvFileName), []byte("BROKEN=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	var output strings.Builder
	if err := runCLI([]string{"help"}, dependencies{stderr: &output, stdin: strings.NewReader(""), stdout: &output}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalInstallChoiceDefaultsToYesAndAcceptsNo(t *testing.T) {
	for _, fixture := range []struct {
		input    string
		expected bool
	}{{"\n", true}, {"yes\n", true}, {"n\n", false}} {
		input := strings.NewReader(fixture.input)
		console := operatorConsole{stdin: input, stderr: io.Discard, stdout: io.Discard}
		actual, err := console.confirmDefaultYes("Install")
		if err != nil || actual != fixture.expected {
			t.Fatalf("%q: %v %v", fixture.input, actual, err)
		}
	}
}

func TestActivateApprovalAgentRetriesBootstrapAfterBootoutRace(t *testing.T) {
	bootstrapAttempts := 0
	run := func(arguments ...string) ([]byte, error) {
		if arguments[0] == "bootout" {
			return nil, errors.New("not loaded")
		}
		bootstrapAttempts++
		if bootstrapAttempts == 1 {
			return nil, errors.New("race")
		}
		return nil, nil
	}
	plan := &userCLIInstallPlan{launchAgentPath: "/tmp/onenod.plist"}
	if err := activateApprovalAgentWith(plan, run, func(time.Duration) {}); err != nil {
		t.Fatal(err)
	}
	if bootstrapAttempts != 2 {
		t.Fatalf("attempts %d", bootstrapAttempts)
	}
}
