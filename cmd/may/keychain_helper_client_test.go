package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
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

func TestTransportCandidateDigestUsesManagedSymlinkFileDescriptor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	versionRoot := filepath.Join(root, "versions", "0.0.2-alpha.24")
	if err := os.MkdirAll(versionRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mayTarget := filepath.Join(versionRoot, "may")
	adapterTarget := filepath.Join(versionRoot, gitSignAdapterBinaryName)
	if err := os.WriteFile(mayTarget, []byte("exact managed build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapterTarget, []byte("exact adapter build"), 0o700); err != nil {
		t.Fatal(err)
	}
	binRoot := filepath.Join(root, "bin")
	if err := os.MkdirAll(binRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	mayEntry := filepath.Join(binRoot, "may")
	adapterEntry := filepath.Join(binRoot, gitSignAdapterBinaryName)
	if err := os.Symlink(filepath.Join("..", "versions", "0.0.2-alpha.24", "may"), mayEntry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "versions", "0.0.2-alpha.24", gitSignAdapterBinaryName), adapterEntry); err != nil {
		t.Fatal(err)
	}
	priorExecutablePath := currentExecutablePath
	currentExecutablePath = func() (string, error) { return mayEntry, nil }
	t.Cleanup(func() { currentExecutablePath = priorExecutablePath })
	mayPath, adapterPath, err := currentTransportCandidatePaths()
	if err != nil {
		t.Fatal(err)
	}
	if mayPath != mayEntry || adapterPath != adapterEntry {
		t.Fatalf("managed candidate paths = %q, %q", mayPath, adapterPath)
	}
	files, err := openExactTransportCandidates(mayPath, adapterPath)
	if err != nil {
		t.Fatal(err)
	}
	defer closeExactTransportCandidates(files)
	mayDigest, err := transportCandidateDigest(files[0])
	if err != nil {
		t.Fatalf("digest managed target descriptor: %v", err)
	}
	expected := sha256.Sum256([]byte("exact managed build"))
	if mayDigest != "sha256:"+hex.EncodeToString(expected[:]) {
		t.Fatalf("managed target digest = %q", mayDigest)
	}
	if _, err := transportCandidateDigest(files[1]); err != nil {
		t.Fatalf("digest managed adapter descriptor: %v", err)
	}
	if _, err := regularFileSHA256(mayEntry, maxReleaseArtifactBytes); err == nil {
		t.Fatal("generic release file digest unexpectedly followed a symlink")
	}
	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mayEntry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, mayEntry); err != nil {
		t.Fatal(err)
	}
	afterRetarget, err := transportCandidateDigest(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if afterRetarget != mayDigest {
		t.Fatalf("opened transport descriptor followed retargeted symlink: %q", afterRetarget)
	}
}

func TestRequesterBootstrapBindsReceiptDigestsToInheritedManagedFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://onenod.example-account.workers.dev"
	root := filepath.Join(home, userAgentDirectoryName)
	versionRoot := filepath.Join(root, "versions", "0.0.2-alpha.24")
	binRoot := filepath.Join(root, "bin")
	helperRoot := filepath.Join(root, "libexec")
	for _, directory := range []string{versionRoot, binRoot, helperRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mayTarget := filepath.Join(versionRoot, "may")
	adapterTarget := filepath.Join(versionRoot, gitSignAdapterBinaryName)
	mayBytes := []byte("exact bootstrap may")
	adapterBytes := []byte("exact bootstrap adapter")
	if err := os.WriteFile(mayTarget, mayBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adapterTarget, adapterBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	mayEntry := filepath.Join(binRoot, "may")
	adapterEntry := filepath.Join(binRoot, gitSignAdapterBinaryName)
	if err := os.Symlink(filepath.Join("..", "versions", "0.0.2-alpha.24", "may"), mayEntry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "versions", "0.0.2-alpha.24", gitSignAdapterBinaryName), adapterEntry); err != nil {
		t.Fatal(err)
	}
	requestCapture := filepath.Join(home, "bootstrap-request.json")
	mayCapture := filepath.Join(home, "may-fd.sha256")
	adapterCapture := filepath.Join(home, "adapter-fd.sha256")
	publicKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	helperScript := fmt.Sprintf(`#!/bin/sh
/bin/cat > %q
/bin/cat <&3 | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}' > %q
/bin/cat <&4 | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}' > %q
/usr/bin/printf '%%s' '{"ok":true,"identity":{"device_id":"11111111-2222-4333-8444-555555555555","display_name":"Mac mini","public_key":"%s","version":1}}'
`, requestCapture, mayCapture, adapterCapture, publicKey)
	if err := os.WriteFile(
		filepath.Join(helperRoot, keychainHelperBinaryName), []byte(helperScript), 0o700,
	); err != nil {
		t.Fatal(err)
	}
	receipt := writeTestLocalInstallReceipt(t, home, origin, "0.0.2-alpha.24")
	mayDigest, err := regularFileSHA256(mayTarget, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	adapterDigest, err := regularFileSHA256(adapterTarget, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Files["bin/may"] = mayDigest
	receipt.Files["bin/"+gitSignAdapterBinaryName] = adapterDigest
	if err := writeLocalInstallReceipt(filepath.Join(root, "install.json"), receipt); err != nil {
		t.Fatal(err)
	}
	priorExecutablePath := currentExecutablePath
	currentExecutablePath = func() (string, error) { return mayEntry, nil }
	t.Cleanup(func() { currentExecutablePath = priorExecutablePath })
	credential, err := bootstrapRequesterTransport(
		origin, "11111111-2222-4333-8444-555555555555", "Mac mini",
	)
	if err != nil {
		t.Fatal(err)
	}
	if credential.DeviceID != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("bootstrap credential = %+v", credential)
	}
	requestBytes, err := os.ReadFile(requestCapture)
	if err != nil {
		t.Fatal(err)
	}
	var request keychainHelperRequest
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	if request.CandidateMaySHA256 != mayDigest || request.CandidateAdapterSHA256 != adapterDigest {
		t.Fatalf("bootstrap request digests = %q, %q", request.CandidateMaySHA256, request.CandidateAdapterSHA256)
	}
	for path, value := range map[string][]byte{mayCapture: mayBytes, adapterCapture: adapterBytes} {
		captured, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		expected := sha256.Sum256(value)
		if strings.TrimSpace(string(captured)) != hex.EncodeToString(expected[:]) {
			t.Fatalf("inherited file digest at %s = %q", filepath.Base(path), captured)
		}
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

func TestExactBuildMaySubprocessesReceiveOnlyCanonicalHome(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	ambientHome := t.TempDir()
	t.Setenv("HOME", ambientHome)
	t.Setenv("ONENOD_EXACT_BUILD_SENTINEL", "must-not-leak")
	t.Setenv("CLOUDFLARE_API_TOKEN", "must-not-leak")
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "must-not-leak")

	command, err := newExactBuildMayCommand("/nonexistent/may", "--version")
	if err != nil {
		t.Fatal(err)
	}
	expectedHome := "HOME=" + account.HomeDir
	if len(command.Env) != 1 || command.Env[0] != expectedHome {
		t.Fatalf("exact-build may environment = %q, want only %q", command.Env, expectedHome)
	}

	transactionID := strings.Repeat("E", 32)
	captures := map[string]string{
		"status": filepath.Join(ambientHome, "status-environment"),
		"commit": filepath.Join(ambientHome, "commit-environment"),
		"abort":  filepath.Join(ambientHome, "abort-environment"),
	}
	scriptPath := filepath.Join(ambientHome, "may")
	script := fmt.Sprintf(`#!/bin/sh
case "$2" in
  status) capture=%q ;;
  commit) capture=%q ;;
  abort) capture=%q ;;
  *) exit 90 ;;
esac
/usr/bin/env > "$capture"
if [ "$2" = status ]; then
  /usr/bin/printf '%%s' '{"role":"current","transaction_id":"%s","transaction_state":"committed"}'
fi
`, captures["status"], captures["commit"], captures["abort"], transactionID)
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	const origin = "https://gateway.example.workers.dev"
	const slot = "active"
	if _, err := runExactTransportStatus(scriptPath, origin, slot, transactionID); err != nil {
		t.Fatal(err)
	}
	if err := runStagedTransportFinalize(
		scriptPath, origin, slot, transactionID, false, bytes.Repeat([]byte{0x45}, 32),
	); err != nil {
		t.Fatal(err)
	}
	if err := runCurrentTransportAbort(scriptPath, origin, slot, transactionID); err != nil {
		t.Fatal(err)
	}

	for operation, path := range captures {
		captured, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s environment: %v", operation, err)
		}
		if !bytes.Contains(captured, []byte(expectedHome+"\n")) {
			t.Fatalf("%s environment omitted canonical home: %q", operation, captured)
		}
		for _, forbidden := range []string{
			"HOME=" + ambientHome,
			"ONENOD_EXACT_BUILD_SENTINEL=",
			"CLOUDFLARE_API_TOKEN=",
			"OP_SERVICE_ACCOUNT_TOKEN=",
		} {
			if bytes.Contains(captured, []byte(forbidden)) {
				t.Fatalf("%s inherited forbidden environment %q", operation, forbidden)
			}
		}
	}
}
