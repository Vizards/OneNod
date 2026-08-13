package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseCommandEntrypointsRejectConflictingSelectors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	deps := dependencies{
		stdin: strings.NewReader(""), stderr: io.Discard, stdout: io.Discard,
	}
	selectorArguments := []string{
		"--channel", "alpha", "--version", "0.0.2-alpha.7",
	}
	for _, fixture := range []struct {
		name string
		run  func() error
	}{
		{
			name: "install",
			run: func() error {
				return runBinaryInstall(append([]string{
					"--origin", "https://gateway.account.workers.dev",
				}, selectorArguments...), deps)
			},
		},
		{name: "update check", run: func() error {
			return runUpdateCheck(append(append([]string(nil), selectorArguments...), "--json"), deps)
		}},
		{name: "update", run: func() error {
			return runLocalUpdate(append([]string(nil), selectorArguments...), deps)
		}},
		{name: "operator init", run: func() error {
			return runProductionInitialization(append([]string(nil), selectorArguments...), deps)
		}},
		{name: "operator update", run: func() error {
			return runBinaryOperatorUpdate(append([]string(nil), selectorArguments...), deps)
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			err := fixture.run()
			if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Fatalf("conflicting selector returned %v", err)
			}
		})
	}
}

func TestPreserveImmutableReceiptCanonicalizesSchemaChannelAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.Mkdir(filepath.Join(home, userAgentDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := localInstallReceipt{
		Channel:        string(releaseChannelAlpha),
		ReleaseVersion: "0.0.2-alpha.25",
		SourceCommit:   strings.Repeat("a", 40),
	}
	if err := preserveImmutableReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(
		home, userAgentDirectoryName, "receipt-versions", receipt.ReleaseVersion+".json",
	)
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	var stored localInstallReceipt
	if err := json.Unmarshal(first, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.SchemaVersion != localReceiptSchema {
		t.Fatalf("immutable receipt schema = %d, want %d", stored.SchemaVersion, localReceiptSchema)
	}
	if stored.Channel != string(releaseChannelAlpha) {
		t.Fatalf("immutable receipt channel = %q, want %q", stored.Channel, releaseChannelAlpha)
	}
	if err := preserveImmutableReceipt(receipt); err != nil {
		t.Fatalf("preserving the same receipt again failed: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) || !os.SameFile(before, after) {
		t.Fatal("preserving the same immutable receipt rewrote it")
	}
}

func TestInstallCannotBypassTheExistingInstallationUpdateCeremony(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod local receipts are supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	origin := "https://gateway.account.workers.dev"
	writeTestLocalInstallReceipt(t, home, origin, "0.0.2-alpha.1")
	var output strings.Builder
	err := runBinaryInstall([]string{"--origin", origin}, dependencies{
		stdin: strings.NewReader(""), stderr: io.Discard, stdout: &output,
	})
	if err == nil || !strings.Contains(err.Error(), "use may update") {
		t.Fatalf("install bypassed the existing-installation update ceremony: %v", err)
	}
	if strings.Contains(output.String(), "FIRST EXECUTION SECURITY CEREMONY") {
		t.Fatal("complete existing installation repeated the first-execution gate")
	}
}

func TestFreshInstallFirstExecutionCeremonyDefaultsNoBeforeReleaseOrLocalWrite(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod local installation is supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://gateway.account.workers.dev"
	source := &memoryReleaseSource{}
	var output strings.Builder
	err := runBinaryInstall([]string{"--origin", origin}, dependencies{
		releases: source,
		stdin:    strings.NewReader("\n"),
		stderr:   io.Discard,
		stdout:   &output,
	})
	if err == nil || !strings.Contains(err.Error(), "first execution ceremony was not confirmed") {
		t.Fatalf("fresh install default-no gate returned %v", err)
	}
	if source.requested != "" || source.requestedVersion != "" {
		t.Fatal("fresh install resolved or downloaded a Release before the human gate")
	}
	if !strings.Contains(output.String(), "FIRST EXECUTION SECURITY CEREMONY") ||
		!strings.Contains(output.String(), origin) ||
		!strings.Contains(output.String(), "human-controlled terminal") {
		t.Fatalf("fresh install ceremony summary is incomplete: %s", output.String())
	}
	if _, statErr := os.Stat(filepath.Join(home, userAgentDirectoryName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("fresh install wrote local OneNod state before confirmation")
	}
}

func TestFreshOperatorInitFirstExecutionCeremonyDefaultsNoBeforeReleaseOrLocalWrite(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod operator initialization is supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	source := &memoryReleaseSource{}
	var output strings.Builder
	err := runProductionInitialization(nil, dependencies{
		releases: source,
		stdin:    strings.NewReader("n\n"),
		stderr:   io.Discard,
		stdout:   &output,
	})
	if err == nil || !strings.Contains(err.Error(), "first execution ceremony was not confirmed") {
		t.Fatalf("fresh operator init default-no gate returned %v", err)
	}
	if source.requested != "" || source.requestedVersion != "" {
		t.Fatal("fresh operator init resolved or downloaded a Release before the human gate")
	}
	if !strings.Contains(output.String(), "FIRST EXECUTION SECURITY CEREMONY") ||
		!strings.Contains(output.String(), "may operator init") ||
		!strings.Contains(output.String(), "same macOS user") {
		t.Fatalf("operator init ceremony summary is incomplete: %s", output.String())
	}
	if _, statErr := os.Stat(filepath.Join(home, userAgentDirectoryName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("fresh operator init wrote local OneNod state before confirmation")
	}
}

func TestExistingTrustedInstallSkipsOperatorFirstExecutionGate(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod operator initialization is supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeTestLocalInstallReceipt(t, home, "https://gateway.account.workers.dev", "0.0.2-alpha.1")
	var output strings.Builder
	err := runProductionInitialization(nil, dependencies{
		releases: &memoryReleaseSource{},
		stdin:    strings.NewReader(""),
		stderr:   io.Discard,
		stdout:   &output,
	})
	if err == nil || !strings.Contains(err.Error(), "no release") {
		t.Fatalf("trusted operator path did not reach normal release resolution: %v", err)
	}
	if strings.Contains(output.String(), "FIRST EXECUTION SECURITY CEREMONY") {
		t.Fatal("trusted operator path repeated the first-execution gate")
	}
}

func TestHelperReuseRequiresExactVersionSourceArtifactAndBinaryIdentity(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("OneNod requester artifacts are macOS-only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	helperDirectory := filepath.Join(home, userAgentDirectoryName, "libexec")
	if err := os.MkdirAll(helperDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	helperPath := filepath.Join(helperDirectory, keychainHelperBinaryName)
	if err := os.WriteFile(helperPath, []byte("verified helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	binaryDigest, err := regularFileSHA256(helperPath, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest := validManifestFixture("0.0.2", nil)
	helperName, err := helperArtifactName(manifest.Components.KeychainHelper.Version)
	if err != nil {
		t.Fatal(err)
	}
	helperArtifact := releaseArtifact{Name: helperName, Kind: "keychain_helper", Size: 1, SHA256: "sha256:" + strings.Repeat("c", 64), Platform: &struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
	}{Architecture: runtime.GOARCH, OS: "darwin"}}
	manifest.Artifacts = []releaseArtifact{helperArtifact}
	release := &verifiedRelease{Manifest: manifest}
	receipt := &localInstallReceipt{Artifacts: map[string]string{helperName: helperArtifact.SHA256}}
	receipt.Helper.Artifact = helperName
	receipt.Helper.ArtifactSHA = helperArtifact.SHA256
	receipt.Helper.BinarySHA256 = binaryDigest
	receipt.Helper.Protocol = 3
	receipt.Helper.SourceDigest = manifest.Components.KeychainHelper.SourceDigest
	receipt.Helper.Version = manifest.Components.KeychainHelper.Version
	helper := keychainHelperResponse{Protocol: 3, Version: manifest.Components.KeychainHelper.Version}
	if !helperMatchesRelease(release, receipt, helper) {
		t.Fatal("exact helper identity was not reusable")
	}
	changed := *release
	changed.Manifest = manifest
	changed.Manifest.Components.KeychainHelper.Version = "1.0.1"
	if helperMatchesRelease(&changed, receipt, helper) {
		t.Fatal("old helper reused after version change")
	}
	changed.Manifest = manifest
	changed.Manifest.Components.KeychainHelper.SourceDigest = "sha256:" + strings.Repeat("d", 64)
	if helperMatchesRelease(&changed, receipt, helper) {
		t.Fatal("old helper reused after source identity change")
	}
	changed.Manifest = manifest
	changed.Manifest.Artifacts[0].SHA256 = "sha256:" + strings.Repeat("e", 64)
	if helperMatchesRelease(&changed, receipt, helper) {
		t.Fatal("old helper reused after artifact identity change")
	}
}

func TestReusedHelperArchiveKeepsItsIndependentSourceCommit(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("OneNod requester artifacts are macOS-only")
	}
	manifest := validManifestFixture("0.0.2-alpha.2", nil)
	manifest.Source.Commit = strings.Repeat("b", 40)
	binary := []byte("immutable independently versioned helper")
	digest := sha256.Sum256(binary)
	metadata := helperReleaseMetadata{
		Architecture:       runtime.GOARCH,
		ArtifactKind:       "keychain_helper",
		BinarySHA256:       "sha256:" + hex.EncodeToString(digest[:]),
		CodeIdentity:       manifest.Components.KeychainHelper.CodeIdentity,
		ExactCodeIdentity:  testExactBuildRuntimeIdentity(),
		HelperProtocol:     keychainHelperProtocol,
		HelperSourceDigest: manifest.Components.KeychainHelper.SourceDigest,
		HelperVersion:      manifest.Components.KeychainHelper.Version,
		Repository:         officialRepository,
		SchemaVersion:      1,
		SourceCommit:       strings.Repeat("a", 40),
	}
	encodeArchive := func(t *testing.T, value helperReleaseMetadata) []byte {
		t.Helper()
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(t.TempDir(), "helper.tar.gz")
		writeTestRegularArchive(t, archive, []testArchiveFile{
			{name: "onenod-keychain-helper/RELEASE.json", content: encoded},
			{name: "onenod-keychain-helper/bin/onenod-keychain-helper", content: binary},
		})
		snapshot, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	if _, err := extractVerifiedHelperArchive(
		encodeArchive(t, metadata), t.TempDir(), manifest,
	); err != nil {
		t.Fatalf("reused helper archive rejected its independently bound source commit: %v", err)
	}
	metadata.SourceCommit = "not-a-commit"
	if _, err := extractVerifiedHelperArchive(
		encodeArchive(t, metadata), t.TempDir(), manifest,
	); err == nil {
		t.Fatal("helper archive accepted an invalid independent source commit")
	}
}

func TestByteIdenticalHelperActivationPerformsNoReplacement(t *testing.T) {
	root := t.TempDir()
	stable := filepath.Join(root, "stable-helper")
	source := filepath.Join(root, "release-helper")
	for _, path := range []string{stable, source} {
		if err := os.WriteFile(path, []byte("same exact helper bytes"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	before, err := os.Stat(stable)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := activateStableHelper(stable, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(stable)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Changed || !os.SameFile(before, after) {
		t.Fatal("byte-identical helper was replaced and could disturb its Keychain trust identity")
	}
}

func TestSkillDiscoveryAdoptsExactBootstrapTreeAndRollsBack(t *testing.T) {
	home := t.TempDir()
	stable := filepath.Join(home, userAgentDirectoryName, "skill")
	target := filepath.Join(home, userAgentDirectoryName, "skill-versions", "0.0.1", "onenod")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("verified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("skill-versions", "0.0.1", "onenod"), stable); err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(home, ".agents", "skills", "onenod")
	if err := os.MkdirAll(bootstrap, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bootstrap, "SKILL.md"), []byte("verified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := directoryTreeSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	entries, transaction, err := installSkillDiscoveryLinks(home, stable, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || len(transaction.backupPaths()) != 1 {
		t.Fatalf("unexpected adoption %+v %+v", entries, transaction.backupPaths())
	}
	if info, err := os.Lstat(bootstrap); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("bootstrap tree was not adopted")
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(bootstrap); err != nil || !info.IsDir() {
		t.Fatal("bootstrap tree was not restored")
	}
	if _, err := os.Lstat(filepath.Join(home, ".claude", "skills", "onenod")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new discovery link survived rollback")
	}
}

func TestSkillDiscoveryRejectsDifferentExistingContentWithoutMutation(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, userAgentDirectoryName, "skill-versions", "0.0.1", "onenod")
	stable := filepath.Join(home, userAgentDirectoryName, "skill")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("verified\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("skill-versions", "0.0.1", "onenod"), stable); err != nil {
		t.Fatal(err)
	}
	conflict := filepath.Join(home, ".agents", "skills", "onenod")
	if err := os.MkdirAll(conflict, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(conflict, "SKILL.md"), []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, _ := directoryTreeSHA256(target)
	if _, _, err := installSkillDiscoveryLinks(home, stable, digest); err == nil {
		t.Fatal("different Skill content was overwritten")
	}
	value, err := os.ReadFile(filepath.Join(conflict, "SKILL.md"))
	if err != nil || string(value) != "different\n" {
		t.Fatal("conflicting Skill was mutated")
	}
}

func TestManagedFileSnapshotsRestorePreviousState(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	created := filepath.Join(root, "created")
	if err := os.WriteFile(existing, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshots, err := captureManagedFiles([]string{existing, created})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("after\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreManagedFiles(snapshots); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(existing); err != nil || string(value) != "before\n" {
		t.Fatal("existing managed file was not restored")
	}
	if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("new managed file survived rollback")
	}
}
