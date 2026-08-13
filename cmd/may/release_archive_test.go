package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArchiveExtractionRejectsTraversal(t *testing.T) {
	for _, fixture := range archiveExtractorFixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			archive := filepath.Join(t.TempDir(), "unsafe.tar.gz")
			writeTestArchive(t, archive, "../escape", tar.TypeReg, []byte("binary"))
			if err := fixture.extract(archive, t.TempDir()); err == nil {
				t.Fatal("archive traversal entry was accepted")
			}
		})
	}
}

func TestReleaseArchiveExtractionRejectsSymlinkEntry(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "unsafe.tar.gz")
	writeTestArchive(t, archive, "onenod/bin/may", tar.TypeSymlink, nil)
	if err := archiveExtractorFixtures()[0].extract(archive, t.TempDir()); err == nil {
		t.Fatal("archive symlink entry was accepted")
	}
}

func TestReleaseArchiveExtractionWritesInsideRoot(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	writeTestArchive(t, archive, "onenod/bin/may", tar.TypeReg, []byte("binary"))
	destination := t.TempDir()
	if err := archiveExtractorFixtures()[0].extract(archive, destination); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(filepath.Join(destination, "onenod", "bin", "may")); err != nil || string(value) != "binary" {
		t.Fatal("release archive was not extracted inside its root")
	}
}

func TestDeploymentArtifactInstallabilityUsesRuntimeMetadataContract(t *testing.T) {
	const (
		version = "0.0.2-alpha.7"
		commit  = "966e685c6cc1acc5d7d3704280cd88ca2c371243"
	)
	manifest := releaseManifest{ReleaseVersion: version}
	manifest.Source.Commit = commit
	descriptor, err := json.Marshal(map[string]any{
		"executor": map[string]string{
			"config": "executor/wrangler.jsonc", "entrypoint": "executor/worker.mjs", "plugin": "executor/plugin.wasm",
		},
		"gateway": map[string]string{
			"assets": "gateway/assets", "config": "gateway/wrangler.jsonc", "entrypoint": "gateway/worker.mjs",
		},
		"release_version": version,
		"schema_version":  1,
		"source_commit":   commit,
		"template_tokens": []string{
			"__ACCOUNT_ID__", "__ACCOUNT_SUBDOMAIN__", "__EXECUTOR_NAME__", "__GATEWAY_NAME__",
			"__OP_ACCOUNT__", "__OP_VAULT_ID__", "__ORIGIN__", "__RELEASE_VERSION__",
			"__RP_ID__", "__SOURCE_COMMIT__", "__VAPID_PUBLIC_KEY__",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseMetadata, err := json.Marshal(deploymentReleaseMetadata{
		ArtifactKind: "deployment", Repository: officialRepository, ReleaseVersion: version,
		SchemaVersion: 1, SourceCommit: commit,
	})
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "deployment.tar.gz")
	entries := []testArchiveFile{
		{name: "onenod-deployment/deployment.json", content: descriptor},
		{name: "onenod-deployment/RELEASE.json", content: releaseMetadata},
		{name: "onenod-deployment/gateway/assets/index.html", content: []byte("index")},
	}
	for path := range deploymentBundleRequiredFiles() {
		if path == "onenod-deployment/deployment.json" || path == "onenod-deployment/RELEASE.json" {
			continue
		}
		entries = append(entries, testArchiveFile{name: path, content: []byte("runtime")})
	}
	writeTestRegularArchive(t, archive, entries)
	archiveBytes, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseArtifactInstallability(
		manifest, releaseArtifact{Kind: "deployment"}, archiveBytes,
	); err != nil {
		t.Fatal(err)
	}
	wrongKind, err := json.Marshal(deploymentReleaseMetadata{
		ArtifactKind: "local", Repository: officialRepository, ReleaseVersion: version,
		SchemaVersion: 1, SourceCommit: commit,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := range entries {
		if entries[index].name == "onenod-deployment/RELEASE.json" {
			entries[index].content = wrongKind
		}
	}
	wrongArchive := filepath.Join(t.TempDir(), "wrong-kind.tar.gz")
	writeTestRegularArchive(t, wrongArchive, entries)
	wrongArchiveBytes, err := os.ReadFile(wrongArchive)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseArtifactInstallability(
		manifest, releaseArtifact{Kind: "deployment"}, wrongArchiveBytes,
	); err == nil {
		t.Fatal("deployment artifact accepted RELEASE.json with the wrong artifact kind")
	}
}

func TestNativeArtifactInstallabilityUsesManifestArchitecture(t *testing.T) {
	manifest := validManifestFixture("0.0.2-alpha.23", nil)
	architecture := oppositeTestArchitecture()
	fixtures := []struct {
		archive func(*testing.T, releaseManifest, string, string) []byte
		kind    string
	}{
		{archive: testLocalReleaseArchive, kind: "local"},
		{archive: testHelperReleaseArchive, kind: "keychain_helper"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.kind, func(t *testing.T) {
			snapshot := fixture.archive(t, manifest, architecture, architecture)
			artifact := testNativeReleaseArtifact(fixture.kind, architecture)
			if err := verifyReleaseArtifactInstallability(manifest, artifact, snapshot); err != nil {
				t.Fatalf("release verifier rejected a valid %s artifact for %s: %v", fixture.kind, architecture, err)
			}

			artifact.Platform.Architecture = runtime.GOARCH
			if err := verifyReleaseArtifactInstallability(manifest, artifact, snapshot); err == nil {
				t.Fatalf("release verifier accepted %s metadata that disagreed with manifest platform", fixture.kind)
			}

			artifact.Platform.Architecture = architecture
			identityMismatch := fixture.archive(t, manifest, architecture, runtime.GOARCH)
			if err := verifyReleaseArtifactInstallability(manifest, artifact, identityMismatch); err == nil {
				t.Fatalf("release verifier accepted %s exact identity for the wrong architecture", fixture.kind)
			}
		})
	}
}

func TestHostBoundNativeArtifactExtractionRejectsOtherArchitecture(t *testing.T) {
	manifest := validManifestFixture("0.0.2-alpha.23", nil)
	architecture := oppositeTestArchitecture()
	if _, err := extractVerifiedLocalArchive(
		testLocalReleaseArchive(t, manifest, architecture, architecture), t.TempDir(), manifest,
	); err == nil {
		t.Fatal("host-bound local extractor accepted another architecture")
	}
	if _, err := extractVerifiedHelperArchive(
		testHelperReleaseArchive(t, manifest, architecture, architecture), t.TempDir(), manifest,
	); err == nil {
		t.Fatal("host-bound helper extractor accepted another architecture")
	}
}

func TestNativeArtifactInstallabilityRejectsInvalidManifestPlatform(t *testing.T) {
	manifest := validManifestFixture("0.0.2-alpha.23", nil)
	snapshot := testLocalReleaseArchive(t, manifest, runtime.GOARCH, runtime.GOARCH)
	fixtures := []struct {
		name     string
		platform *struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		}
	}{
		{name: "missing"},
		{name: "wrong operating system", platform: &struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		}{Architecture: runtime.GOARCH, OS: "linux"}},
		{name: "unsupported architecture", platform: &struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		}{Architecture: "riscv64", OS: "darwin"}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			artifact := releaseArtifact{Kind: "local", Platform: fixture.platform}
			if err := verifyReleaseArtifactInstallability(manifest, artifact, snapshot); err == nil {
				t.Fatal("release verifier accepted an invalid native artifact platform")
			}
		})
	}
}

func TestArchiveExtractionRejectsDestinationSymlinkEscape(t *testing.T) {
	for _, test := range archiveExtractorFixtures() {
		t.Run(test.name, func(t *testing.T) {
			destination := t.TempDir()
			outside := t.TempDir()
			topLevel, remainder, found := strings.Cut(test.entry, "/")
			if !found {
				t.Fatal("test entry must contain a top-level directory")
			}
			if err := os.Symlink(outside, filepath.Join(destination, topLevel)); err != nil {
				t.Fatal(err)
			}
			archive := filepath.Join(t.TempDir(), "unsafe.tar.gz")
			writeTestArchive(t, archive, test.entry, tar.TypeReg, []byte("outside root"))
			if err := test.extract(archive, destination); err == nil {
				t.Fatal("archive extraction followed a destination symlink outside its root")
			}
			if _, err := os.Lstat(filepath.Join(outside, filepath.FromSlash(remainder))); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("archive extraction created a file outside its root")
			}
		})
	}
}

func writeTestArchive(t *testing.T, path, name string, typeflag byte, content []byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	header := &tar.Header{Name: name, Mode: 0o700, Size: int64(len(content)), Typeflag: typeflag}
	if typeflag == tar.TypeSymlink {
		header.Size = 0
		header.Linkname = "/tmp/evil"
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if typeflag == tar.TypeReg {
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

type testArchiveFile struct {
	content []byte
	name    string
}

func oppositeTestArchitecture() string {
	if runtime.GOARCH == "arm64" {
		return "amd64"
	}
	return "arm64"
}

func testNativeReleaseArtifact(kind, architecture string) releaseArtifact {
	return releaseArtifact{
		Kind: kind,
		Platform: &struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		}{Architecture: architecture, OS: "darwin"},
	}
}

func testLocalReleaseArchive(
	t *testing.T,
	manifest releaseManifest,
	metadataArchitecture, identityArchitecture string,
) []byte {
	t.Helper()
	mayBytes := []byte("verified may for " + metadataArchitecture)
	adapterBytes := []byte("verified may SSH adapter for " + metadataArchitecture)
	metadata := localReleaseMetadata{
		Architecture: metadataArchitecture, ArtifactKind: "local",
		ReleaseVersion: manifest.ReleaseVersion, Repository: officialRepository,
		SchemaVersion: 1, SourceCommit: manifest.Source.Commit,
	}
	metadata.CodeIdentities.May = manifest.Components.May.CodeIdentity
	metadata.CodeIdentities.MaySSHSign = manifest.Components.May.AdapterCodeIdentity
	metadata.ExactCodeIdentities.May = testExactBuildRuntimeIdentityForArchitecture(identityArchitecture)
	metadata.ExactCodeIdentities.MaySSHSign = testExactBuildRuntimeIdentityForArchitecture(identityArchitecture)
	mayDigest := sha256.Sum256(mayBytes)
	adapterDigest := sha256.Sum256(adapterBytes)
	metadata.BinarySHA256.May = "sha256:" + hex.EncodeToString(mayDigest[:])
	metadata.BinarySHA256.MaySSHSign = "sha256:" + hex.EncodeToString(adapterDigest[:])
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return testReleaseArchiveSnapshot(t, []testArchiveFile{
		{name: "onenod/RELEASE.json", content: metadataBytes},
		{name: "onenod/bin/may", content: mayBytes},
		{name: "onenod/bin/" + gitSignAdapterBinaryName, content: adapterBytes},
	})
}

func testHelperReleaseArchive(
	t *testing.T,
	manifest releaseManifest,
	metadataArchitecture, identityArchitecture string,
) []byte {
	t.Helper()
	binary := []byte("verified Keychain helper for " + metadataArchitecture)
	digest := sha256.Sum256(binary)
	metadata := helperReleaseMetadata{
		Architecture:       metadataArchitecture,
		ArtifactKind:       "keychain_helper",
		BinarySHA256:       "sha256:" + hex.EncodeToString(digest[:]),
		CodeIdentity:       manifest.Components.KeychainHelper.CodeIdentity,
		ExactCodeIdentity:  testExactBuildRuntimeIdentityForArchitecture(identityArchitecture),
		HelperProtocol:     manifest.Components.KeychainHelper.HelperProtocol.Maximum,
		HelperSourceDigest: manifest.Components.KeychainHelper.SourceDigest,
		HelperVersion:      manifest.Components.KeychainHelper.Version,
		Repository:         officialRepository,
		SchemaVersion:      1,
		SourceCommit:       manifest.Source.Commit,
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return testReleaseArchiveSnapshot(t, []testArchiveFile{
		{name: "onenod-keychain-helper/RELEASE.json", content: metadataBytes},
		{name: "onenod-keychain-helper/bin/onenod-keychain-helper", content: binary},
	})
}

func testReleaseArchiveSnapshot(t *testing.T, entries []testArchiveFile) []byte {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	writeTestRegularArchive(t, archive, entries)
	snapshot, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func writeTestRegularArchive(t *testing.T, path string, entries []testArchiveFile) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Mode: 0o600, Size: int64(len(entry.content)), Typeflag: tar.TypeReg,
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
