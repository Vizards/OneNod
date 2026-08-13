package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeychainHelperResponseAcceptsHelloContract(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(
		`{"ok":true,"protocol":3,"source_commit":"0123456789abcdef0123456789abcdef01234567","version":"2.0.0"}`,
	))
	decoder.DisallowUnknownFields()
	var response keychainHelperResponse
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode helper hello response: %v", err)
	}
	if !response.OK || response.Protocol != 3 || response.Version != "2.0.0" ||
		response.Source != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("unexpected helper hello response: %+v", response)
	}
}

func TestTransportCapabilityUsesAnonymousInheritedFilesOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	helperPath := filepath.Join(home, userAgentDirectoryName, "libexec", keychainHelperBinaryName)
	if err := os.MkdirAll(filepath.Dir(helperPath), 0o700); err != nil {
		t.Fatal(err)
	}
	requestCapture := filepath.Join(home, "request.json")
	argumentCapture := filepath.Join(home, "arguments")
	environmentCapture := filepath.Join(home, "environment")
	capabilityCapture := filepath.Join(home, "capability")
	stageScript := "#!/bin/sh\n" +
		"/bin/cat > " + requestCapture + "\n" +
		"printf '%s' \"$*\" > " + argumentCapture + "\n" +
		"/usr/bin/env > " + environmentCapture + "\n" +
		"printf '01234567890123456789012345678901' >&6\n" +
		"printf '{\"ok\":true}'\n"
	if err := os.WriteFile(helperPath, []byte(stageScript), 0o700); err != nil {
		t.Fatal(err)
	}
	paths := []string{
		filepath.Join(home, "candidate-may"),
		filepath.Join(home, "candidate-adapter"),
		filepath.Join(home, "candidate-helper"),
	}
	digests := make([]string, len(paths))
	for index, path := range paths {
		value := []byte{byte(index + 1)}
		if err := os.WriteFile(path, value, 0o700); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(value)
		digests[index] = "sha256:" + hex.EncodeToString(digest[:])
	}
	identity := exactBuildRuntimeIdentity{
		Architecture:                    runtime.GOARCH,
		CodeDirectoryHash:               "QkJCQkJCQkJCQkJCQkJCQkJCQkI",
		DesignatedRequirementDataSHA256: "sha256:" + strings.Repeat("4", 64),
	}
	capability, err := stageTransportUpdateExpected(
		"https://gateway.example.workers.dev", "active", strings.Repeat("T", 32),
		paths[0], paths[1], paths[2], digests[0], digests[1], digests[2],
		identity, identity, identity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(capability) != "01234567890123456789012345678901" {
		t.Fatalf("stage capability = %q", capability)
	}
	request, err := os.ReadFile(requestCapture)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(request, []byte("capability")) {
		t.Fatal("stage JSON exposed the one-time capability")
	}

	commitScript := "#!/bin/sh\n" +
		"/bin/cat > " + requestCapture + "\n" +
		"printf '%s' \"$*\" > " + argumentCapture + "\n" +
		"/usr/bin/env > " + environmentCapture + "\n" +
		"/bin/cat <&3 > " + capabilityCapture + "\n" +
		"printf '{\"ok\":true}'\n"
	if err := os.WriteFile(helperPath, []byte(commitScript), 0o700); err != nil {
		t.Fatal(err)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writePipe.Write(capability); err != nil {
		t.Fatal(err)
	}
	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	if err := finalizeTransportUpdate(
		"https://gateway.example.workers.dev", "active", strings.Repeat("T", 32),
		"transport-commit", readPipe,
	); err != nil {
		t.Fatal(err)
	}
	_ = readPipe.Close()
	for _, path := range []string{requestCapture, argumentCapture, environmentCapture} {
		value, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(value, capability) || bytes.Contains(value, []byte("capability")) {
			t.Fatalf("commit proof leaked through %s", filepath.Base(path))
		}
	}
	transported, err := os.ReadFile(capabilityCapture)
	if err != nil || !bytes.Equal(transported, capability) {
		t.Fatalf("anonymous capability transport = %x, %v", transported, err)
	}
}
