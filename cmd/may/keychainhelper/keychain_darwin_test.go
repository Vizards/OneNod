//go:build darwin && cgo

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

const keychainProbeModeEnvironment = "ONENOD_KEYCHAIN_METADATA_PROBE_MODE"

func TestKeychainMetadataProbeSubprocess(t *testing.T) {
	mode := os.Getenv(keychainProbeModeEnvironment)
	if mode == "" {
		return
	}
	account := os.Getenv("ONENOD_KEYCHAIN_METADATA_PROBE_ACCOUNT")
	service := os.Getenv("ONENOD_KEYCHAIN_METADATA_PROBE_SERVICE")
	switch mode {
	case "inspect":
		metadata, found, err := (systemCredentialStore{}).Inspect(account, service)
		if err != nil || !found {
			fmt.Fprintf(os.Stderr, "inspect failed: found=%v err=%v", found, err)
			os.Exit(31)
		}
		_, _ = os.Stdout.Write(metadata)
		os.Exit(0)
	case "read":
		data, found, err := (systemCredentialStore{}).Load(account, service)
		if err != nil || !found {
			fmt.Fprintf(os.Stderr, "read failed: found=%v err=%v", found, err)
			os.Exit(34)
		}
		_, _ = os.Stdout.Write(data)
		zero(data)
		os.Exit(0)
	default:
		os.Exit(33)
	}
}

// This test is opt-in because the final replacement-helper data read is
// intentionally expected to present a macOS Keychain approval dialog. It uses
// cryptographically random names and never touches OneNod's real account or
// service namespace. Run only in an attended local session:
//
//	ONENOD_RUN_KEYCHAIN_ACL_PROBE=1 go test ./keychainhelper \
//	  -run TestDisposableKeychainMetadataAndExactBuildACL -count=1
func TestDisposableKeychainMetadataAndExactBuildACL(t *testing.T) {
	if os.Getenv("ONENOD_RUN_KEYCHAIN_ACL_PROBE") != "1" {
		t.Skip("attended disposable Keychain ACL probe is opt-in")
	}
	tokenBytes := make([]byte, 18)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	account := "onenod-disposable-probe-" + token
	service := "com.github.vizards.onenod.disposable-probe." + token
	store := systemCredentialStore{}
	data := []byte("disposable-secret-" + token)
	metadata := []byte("disposable-metadata-" + token)
	if err := store.Create(account, service, data, metadata, keychainAccessSelfOnly); err != nil {
		t.Fatal(err)
	}
	defer deleteDisposableKeychainItem(t, account, service)

	if observed, found, err := store.Inspect(account, service); err != nil || !found ||
		!bytes.Equal(observed, metadata) {
		t.Fatalf("creator metadata inspection failed: found=%v err=%v", found, err)
	}

	replacement := buildAdHocProbeBinary(t)
	inspect := runKeychainProbeProcess(t, replacement, "inspect", account, service, 3*time.Second)
	if inspect.timedOut || inspect.err != nil || !bytes.Equal(inspect.stdout, metadata) {
		t.Fatalf("attribute-only replacement inspect was not prompt-free: timeout=%v err=%v stderr=%s",
			inspect.timedOut, inspect.err, inspect.stderr)
	}

	// Legacy Keychain ACLs may also present a dialog if an untrusted process asks
	// to mutate attributes, so the security model does not treat prompt count or
	// a prompt-free metadata-mutation failure as an invariant. Signed metadata
	// detects any such mutation. This read is the attended replacement-helper
	// ceremony; the test deletes the random item immediately afterward.
	read := runKeychainProbeProcess(t, replacement, "read", account, service, 2*time.Minute)
	if read.err != nil || !bytes.Equal(read.stdout, data) {
		t.Fatalf("replacement helper ceremony read failed: %v %s", read.err, read.stderr)
	}
}

type keychainProbeResult struct {
	stdout   []byte
	stderr   []byte
	err      error
	timedOut bool
}

func runKeychainProbeProcess(
	t *testing.T,
	binary,
	mode,
	account,
	service string,
	timeout time.Duration,
) keychainProbeResult {
	t.Helper()
	command := exec.Command(binary, "-test.run=^TestKeychainMetadataProbeSubprocess$")
	command.Env = append(os.Environ(),
		keychainProbeModeEnvironment+"="+mode,
		"ONENOD_KEYCHAIN_METADATA_PROBE_ACCOUNT="+account,
		"ONENOD_KEYCHAIN_METADATA_PROBE_SERVICE="+service,
	)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		return keychainProbeResult{err: err}
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return keychainProbeResult{stdout: stdout.Bytes(), stderr: stderr.Bytes(), err: err}
	case <-time.After(timeout):
		_ = command.Process.Kill()
		<-done
		return keychainProbeResult{stderr: stderr.Bytes(), timedOut: true}
	}
}

func buildAdHocProbeBinary(t *testing.T) string {
	t.Helper()
	path := t.TempDir() + "/onenod-keychain-probe-replacement"
	command := exec.Command("go", "test", "-c", "-o", path, ".")
	command.Env = append(os.Environ(), "CGO_ENABLED=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build disposable Keychain probe: %v: %s", err, output)
	}
	identifier := "com.github.vizards.onenod.disposable-keychain-probe"
	if output, err := exec.Command(
		"codesign", "--force", "--sign", "-", "--identifier", identifier,
		"--options", "runtime", path,
	).CombinedOutput(); err != nil {
		t.Fatalf("sign disposable Keychain probe: %v: %s", err, output)
	}
	return path
}

func deleteDisposableKeychainItem(t *testing.T, account, service string) {
	t.Helper()
	if output, err := exec.Command(
		"/usr/bin/security", "delete-generic-password", "-a", account, "-s", service,
	).CombinedOutput(); err != nil {
		t.Errorf("delete disposable Keychain item: %v: %s", err, output)
	}
}
