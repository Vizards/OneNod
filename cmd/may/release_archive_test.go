package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
