package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInitializerReexecPreservesExactReleaseSelection(t *testing.T) {
	for _, fixture := range []struct {
		selection releaseSelection
		want      []string
	}{
		{
			selection: releaseSelection{Channel: releaseChannelAlpha, Version: "0.0.2-alpha.7"},
			want:      []string{"--version", "0.0.2-alpha.7"},
		},
		{
			selection: releaseSelection{Channel: releaseChannelBeta},
			want:      []string{"--channel", "beta"},
		},
	} {
		arguments := releaseSelectionArguments(fixture.selection)
		if strings.Join(arguments, "\x00") != strings.Join(fixture.want, "\x00") {
			t.Fatalf("re-exec arguments = %q, want %q", arguments, fixture.want)
		}
	}
}

func TestOperatorUpdateReexecUsesExactVerifiedTargetWithoutInstallingIt(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod operator updates support macOS release binaries")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLOUDFLARE_API_TOKEN", "must-not-cross-the-reexec-boundary")
	archivePath := filepath.Join(t.TempDir(), "onenod.tar.gz")
	mayBytes := []byte(`#!/bin/sh
set -eu
umask 077
printf '%s' "$*" > "$HOME/reexec-arguments"
printf '%s' "${ONENOD_UPDATE_REEXEC_IDENTITY-unset}" > "$HOME/reexec-identity"
printf '%s' "${CLOUDFLARE_API_TOKEN-unset}" > "$HOME/reexec-cloudflare-environment"
`)
	adapterBytes := []byte("verified adapter")
	manifest := validManifestFixture("0.0.2-alpha.16", nil)
	metadata := localReleaseMetadata{
		Architecture: runtime.GOARCH, ArtifactKind: "local",
		ReleaseVersion: manifest.ReleaseVersion, Repository: officialRepository,
		SchemaVersion: 1, SourceCommit: manifest.Source.Commit,
	}
	metadata.CodeIdentities.May = manifest.Components.May.CodeIdentity
	metadata.CodeIdentities.MaySSHSign = manifest.Components.May.AdapterCodeIdentity
	metadata.ExactCodeIdentities.May = testExactBuildRuntimeIdentity()
	metadata.ExactCodeIdentities.MaySSHSign = testExactBuildRuntimeIdentity()
	mayDigest := sha256.Sum256(mayBytes)
	adapterDigest := sha256.Sum256(adapterBytes)
	metadata.BinarySHA256.May = "sha256:" + hex.EncodeToString(mayDigest[:])
	metadata.BinarySHA256.MaySSHSign = "sha256:" + hex.EncodeToString(adapterDigest[:])
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writeTestRegularArchive(t, archivePath, []testArchiveFile{
		{name: "onenod/RELEASE.json", content: metadataBytes},
		{name: "onenod/bin/may", content: mayBytes},
		{name: "onenod/bin/" + gitSignAdapterBinaryName, content: adapterBytes},
	})
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive)
	artifactName, err := localArtifactName()
	if err != nil {
		t.Fatal(err)
	}
	artifact := releaseArtifact{
		Kind: "local", Name: artifactName, Size: int64(len(archive)),
		SHA256: "sha256:" + hex.EncodeToString(digest[:]), Subject: "requester",
		Platform: &struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		}{Architecture: runtime.GOARCH, OS: runtime.GOOS},
	}
	manifest.Artifacts = []releaseArtifact{artifact}
	source := &memoryReleaseSource{downloads: map[string][]byte{artifactName: archive}}
	release := &verifiedRelease{Manifest: manifest, Source: source}

	oldVersion, oldTag, oldSource := productVersion, releaseTag, sourceCommit
	productVersion = "0.0.2-alpha.15"
	releaseTag = "v0.0.2-alpha.15"
	sourceCommit = strings.Repeat("b", 40)
	t.Cleanup(func() {
		productVersion, releaseTag, sourceCommit = oldVersion, oldTag, oldSource
	})

	reexecuted, err := ensureCurrentOperatorUpdater(
		context.Background(), release,
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	)
	if err != nil || !reexecuted {
		t.Fatalf("verified target updater was not re-executed: reexecuted=%t err=%v", reexecuted, err)
	}
	assertFile := func(name, want string) {
		t.Helper()
		value, err := os.ReadFile(filepath.Join(home, name))
		if err != nil || string(value) != want {
			t.Fatalf("%s = %q, %v; want %q", name, value, err, want)
		}
	}
	assertFile("reexec-arguments", "operator update --version 0.0.2-alpha.16")
	assertFile("reexec-identity", "0.0.2-alpha.16@"+manifest.Source.Commit)
	assertFile("reexec-cloudflare-environment", "unset")
	if _, err := os.Lstat(filepath.Join(home, userAgentDirectoryName, "bin", "may")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target updater changed the installed stable may path: %v", err)
	}
	stages, err := filepath.Glob(filepath.Join(home, userAgentDirectoryName, "update", ".stage-*"))
	if err != nil || len(stages) != 0 {
		t.Fatalf("verified updater staging was not cleaned: %v %v", stages, err)
	}
}

func TestHigherRiskChannelRequiresExplicitApproval(t *testing.T) {
	// A pre-channel 0.0.1 receipt is stable authority, not permission to
	// discover prereleases. Explicit beta receipts may still consume stable.
	channel, err := normalizedReceiptChannel("", "0.0.1")
	if err != nil || channel != releaseChannelStable {
		t.Fatalf("legacy receipt channel = %q, err = %v", channel, err)
	}
	if _, err := normalizedReceiptChannel("", "0.0.2-beta.1"); err == nil {
		t.Fatal("legacy stable receipt accepted a prerelease artifact")
	}
	channel, err = normalizedReceiptChannel("beta", "0.0.2")
	if err != nil || channel != releaseChannelBeta {
		t.Fatalf("beta receipt rejected a stable artifact: %q, %v", channel, err)
	}

	var output strings.Builder
	if err := confirmHigherRiskChannel(
		strings.NewReader("n\n"), &output,
		releaseChannelStable, releaseChannelBeta, "Test operation",
	); err == nil {
		t.Fatal("higher-risk channel proceeded without approval")
	}
	if !strings.Contains(output.String(), "PRERELEASE CHANNEL OPT-IN") {
		t.Fatal("higher-risk channel warning was not prominent")
	}
	if err := confirmHigherRiskChannel(
		strings.NewReader("y\n"), io.Discard,
		releaseChannelStable, releaseChannelAlpha, "Test operation",
	); err != nil {
		t.Fatalf("explicit higher-risk approval failed: %v", err)
	}
	if err := confirmHigherRiskChannel(
		strings.NewReader(""), io.Discard,
		releaseChannelAlpha, releaseChannelStable, "Test operation",
	); err != nil {
		t.Fatalf("lower-risk selection unnecessarily prompted: %v", err)
	}
}

func TestLowerRiskChannelWaitsForNonDowngradingCandidate(t *testing.T) {
	if !awaitingCompatibleRelease(
		"0.0.2-beta.1", releaseChannelBeta,
		"0.0.1", releaseChannelStable,
	) {
		t.Fatal("beta to older stable should await a compatible stable release")
	}
	for _, fixture := range []struct {
		currentVersion  string
		currentChannel  releaseChannel
		candidate       string
		selectedChannel releaseChannel
	}{
		{"0.0.2-beta.1", releaseChannelBeta, "0.0.2", releaseChannelStable},
		{"0.0.2-beta.1", releaseChannelBeta, "0.0.1", releaseChannelBeta},
		{"0.0.2", releaseChannelStable, "0.0.1", releaseChannelBeta},
	} {
		if awaitingCompatibleRelease(
			fixture.currentVersion, fixture.currentChannel,
			fixture.candidate, fixture.selectedChannel,
		) {
			t.Fatalf("true anti-rollback case was classified as awaiting: %+v", fixture)
		}
	}
	var output strings.Builder
	writeAwaitingCompatibleRelease(
		&output, "0.0.2-beta.1", releaseChannelBeta,
		"0.0.1", releaseChannelStable,
	)
	if !strings.Contains(output.String(), "awaiting_compatible_release") ||
		!strings.Contains(output.String(), "no receipt or runtime state was changed") {
		t.Fatalf("unexpected awaiting-compatible-release message: %s", output.String())
	}
}

func TestUpdateCheckAndMutationWaitForCompatibleLowerRiskRelease(t *testing.T) {
	priorCanonical := canonicalLocalUpdateHome
	canonicalLocalUpdateHome = func() (string, error) { return os.Getenv("HOME"), nil }
	t.Cleanup(func() { canonicalLocalUpdateHome = priorCanonical })
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod local receipts are supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.MkdirAll(filepath.Join(root, "versions", "fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	fixtureMay := filepath.Join(root, "versions", "fixture", "may")
	if err := os.WriteFile(fixtureMay, []byte("fixture exact may"), 0o700); err != nil {
		t.Fatal(err)
	}
	priorExecutable := currentLocalUpdateExecutable
	currentLocalUpdateExecutable = func() (string, error) { return fixtureMay, nil }
	t.Cleanup(func() { currentLocalUpdateExecutable = priorExecutable })
	currentVersion := "0.0.2-beta.1"
	localName, err := localArtifactName()
	if err != nil {
		t.Fatal(err)
	}
	helperName, err := helperArtifactName("1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	receipt := localInstallReceipt{
		Artifacts: map[string]string{
			localName:                         digest,
			helperName:                        digest,
			skillArtifactName(currentVersion): digest,
		},
		Channel: string(releaseChannelBeta),
		Files: map[string]string{
			"bin/may":                         digest,
			"bin/" + gitSignAdapterBinaryName: digest,
		},
		Origin:         "https://gateway.account.workers.dev",
		ReleaseVersion: currentVersion,
		SourceCommit:   strings.Repeat("b", 40),
	}
	receipt.Helper.Artifact = helperName
	receipt.Helper.ArtifactSHA = digest
	receipt.Helper.BinarySHA256 = digest
	receipt.Helper.Protocol = 3
	receipt.Helper.SourceDigest = digest
	receipt.Helper.Version = "1.0.0"
	receipt.ExactCodeIdentities.May = testExactBuildRuntimeIdentity()
	receipt.ExactCodeIdentities.MaySSHSign = testExactBuildRuntimeIdentity()
	receipt.ExactCodeIdentities.Helper = testExactBuildRuntimeIdentity()
	receipt.Skill.Artifact = skillArtifactName(currentVersion)
	receipt.Skill.ArtifactSHA = digest
	receipt.Skill.Discovery = []string{"~/.agents/skills/onenod", "~/.claude/skills/onenod"}
	receipt.Skill.TreeSHA256 = digest
	receipt.Skill.Version = currentVersion
	versionMay := filepath.Join(root, "versions", currentVersion, "may")
	currentLocalUpdateExecutable = func() (string, error) { return versionMay, nil }
	if err := os.MkdirAll(filepath.Dir(versionMay), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(versionMay, []byte("installed exact may"), 0o700); err != nil {
		t.Fatal(err)
	}
	mayDigest, err := regularFileSHA256(versionMay, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Files["bin/may"] = mayDigest
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		managedReleaseTargets(currentVersion, currentVersion)["may"],
		filepath.Join(root, "bin", "may"),
	); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(root, "install.json")
	if err := writeLocalInstallReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}

	manifest := validManifestFixture("0.0.1", nil)
	source := &memoryReleaseSource{}
	source.release = &verifiedRelease{Manifest: manifest, Source: source}
	deps := dependencies{
		releases: source,
		stderr:   io.Discard,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: runtime.GOARCH, Version: "15.0"}, nil
		},
	}
	var checkOutput strings.Builder
	deps.stdout = &checkOutput
	if err := runUpdateCheck([]string{"--channel", "stable", "--json"}, deps); err != nil {
		t.Fatal(err)
	}
	var report updateCheckReport
	if err := json.Unmarshal([]byte(checkOutput.String()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "awaiting_compatible_release" {
		t.Fatalf("update status = %q, want awaiting_compatible_release", report.Status)
	}

	var updateOutput strings.Builder
	deps.stdout = &updateOutput
	if err := runLocalUpdate([]string{"--channel", "stable"}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(updateOutput.String(), "awaiting_compatible_release") {
		t.Fatalf("mutation command did not explain the wait: %s", updateOutput.String())
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("channel switch modified the local receipt while awaiting a non-downgrading stable release")
	}
}

func TestRemoteRuntimeVersionCrossChecksDeclaredReleaseChannels(t *testing.T) {
	base := map[string]any{
		"release_channel": "beta",
		"release_version": "0.0.2-beta.1",
		"components": map[string]any{
			"executor": map[string]any{"channel": "beta", "version": "0.0.2-beta.1"},
			"gateway": map[string]any{
				"accepted_client_protocol": map[string]int{"min": 1, "max": 2},
				"channel":                  "beta",
				"protocol":                 1,
				"version":                  "0.0.2-beta.1",
			},
			"pwa": map[string]any{"channel": "beta", "version": "0.0.2-beta.1"},
		},
	}
	for _, fixture := range []struct {
		name     string
		mutate   func(map[string]any)
		complete bool
	}{
		{name: "matching declarations", mutate: func(map[string]any) {}, complete: true},
		{name: "top-level mismatch", mutate: func(value map[string]any) {
			value["release_channel"] = "stable"
		}},
		{name: "component mismatch", mutate: func(value map[string]any) {
			value["components"].(map[string]any)["pwa"].(map[string]any)["channel"] = "alpha"
		}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var value map[string]any
			if err := json.Unmarshal(encoded, &value); err != nil {
				t.Fatal(err)
			}
			fixture.mutate(value)
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.URL.Path != "/api/version" {
					t.Fatalf("unexpected runtime version path %s", request.URL.Path)
				}
				response.Header().Set("content-type", "application/json")
				_ = json.NewEncoder(response).Encode(value)
			}))
			defer server.Close()
			remote, complete := readRemoteRuntimeVersion(server.URL, server.Client())
			if complete != fixture.complete {
				t.Fatalf("complete = %v, want %v; remote = %+v", complete, fixture.complete, remote)
			}
		})
	}
}

func TestLocalUpdateRequiresTheTargetClientProtocolOnTheGateway(t *testing.T) {
	serve := func(t *testing.T, minimum, maximum int, complete bool) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/api/version" {
				t.Fatalf("unexpected runtime version path %s", request.URL.Path)
			}
			if !complete {
				http.Error(response, "unavailable", http.StatusServiceUnavailable)
				return
			}
			response.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"release_channel": "alpha",
				"release_version": "0.0.2-alpha.1",
				"components": map[string]any{
					"executor": map[string]any{"channel": "alpha", "version": "0.0.2-alpha.1"},
					"gateway": map[string]any{
						"accepted_client_protocol": map[string]int{"min": minimum, "max": maximum},
						"channel":                  "alpha", "protocol": 2, "version": "0.0.2-alpha.1",
					},
					"pwa": map[string]any{"channel": "alpha", "version": "0.0.2-alpha.1"},
				},
			})
		}))
	}
	for _, fixture := range []struct {
		name              string
		minimum, maximum  int
		complete, allowed bool
	}{
		{name: "old Gateway", minimum: 1, maximum: 1, complete: true},
		{name: "compatible Gateway", minimum: 1, maximum: 2, complete: true, allowed: true},
		{name: "unverifiable Gateway"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			server := serve(t, fixture.minimum, fixture.maximum, fixture.complete)
			defer server.Close()
			err := requireRemoteGatewayCompatibility(server.URL, 2, server.Client())
			if (err == nil) != fixture.allowed {
				t.Fatalf("compatibility result = %v, allowed = %v", err, fixture.allowed)
			}
		})
	}
}

func TestFreshInstallChecksGatewayCompatibilityBeforeLocalMutation(t *testing.T) {
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod local installation is supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	const version = "0.0.2-alpha.1"
	manifest := validManifestFixture(version, nil)
	source := &memoryReleaseSource{}
	source.release = &verifiedRelease{Manifest: manifest, Source: source}
	oldVersion, oldTag, oldSource := productVersion, releaseTag, sourceCommit
	productVersion, releaseTag, sourceCommit = version, "v"+version, manifest.Source.Commit
	t.Cleanup(func() {
		productVersion, releaseTag, sourceCommit = oldVersion, oldTag, oldSource
	})
	remote, err := json.Marshal(map[string]any{
		"release_channel": "alpha",
		"release_version": version,
		"components": map[string]any{
			"executor": map[string]any{"channel": "alpha", "version": version},
			"gateway": map[string]any{
				"accepted_client_protocol": map[string]int{"min": 1, "max": 1},
				"channel":                  "alpha", "protocol": 1, "version": version,
			},
			"pwa": map[string]any{"channel": "alpha", "version": version},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "gateway.account.workers.dev" || request.URL.Path != "/api/version" {
			t.Fatalf("unexpected remote compatibility request %s", request.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       ioNopCloser(string(remote)),
			Request:    request,
		}, nil
	})}
	err = runBinaryInstall([]string{
		"--origin", "https://gateway.account.workers.dev", "--version", version,
	}, dependencies{
		httpClient: client, releases: source,
		stdin: strings.NewReader("y\n"), stderr: io.Discard, stdout: io.Discard,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: runtime.GOARCH, Version: "15.0"}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "deploy a Gateway that accepts") {
		t.Fatalf("fresh install did not stop at its Gateway compatibility gate: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(home, userAgentDirectoryName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("fresh install mutated local state before proving Gateway compatibility")
	}
}

func TestUpdateCheckJSONIsReadOnlyAndReportsUninstalledState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	artifact := releaseArtifact{
		Name: "onenod-darwin-arm64.tar.gz", Size: 1,
		SHA256: "sha256:" + strings.Repeat("a", 64),
	}
	manifest := validManifestFixture("0.0.1", []releaseArtifact{artifact})
	source := &memoryReleaseSource{}
	source.release = &verifiedRelease{Manifest: manifest, Source: source}
	var output strings.Builder
	err := runUpdateCheck([]string{"--json"}, dependencies{
		releases: source, stderr: io.Discard, stdout: &output,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: "arm64", Version: "15.0"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var report updateCheckReport
	if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "mixed_installation" || len(report.Plan) != 1 {
		t.Fatalf("unexpected read-only report %+v", report)
	}
	if source.requested != releaseChannelStable {
		t.Fatalf("default update channel = %q, want stable", source.requested)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), userAgentDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("update check mutated local installation state")
	}

	output.Reset()
	if err := runUpdateCheck([]string{"--channel", "beta", "--json"}, dependencies{
		releases: source, stderr: io.Discard, stdout: &output,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: "arm64", Version: "15.0"}, nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	if source.requested != releaseChannelBeta {
		t.Fatalf("explicit update channel = %q, want beta", source.requested)
	}
}

func TestUpdateCheckSelectsAnExactImmutablePrerelease(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const version = "0.0.2-alpha.7"
	artifact := releaseArtifact{
		Name: "onenod-darwin-arm64.tar.gz", Size: 1,
		SHA256: "sha256:" + strings.Repeat("a", 64),
	}
	manifest := validManifestFixture(version, []releaseArtifact{artifact})
	source := &memoryReleaseSource{}
	source.release = &verifiedRelease{Manifest: manifest, Source: source}
	var output strings.Builder
	err := runUpdateCheck([]string{"--version", version, "--json"}, dependencies{
		releases: source, stderr: io.Discard, stdout: &output,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: "arm64", Version: "15.0"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var report updateCheckReport
	if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
		t.Fatal(err)
	}
	if source.requestedVersion != version || source.requested != releaseChannelAlpha {
		t.Fatalf("resolver request = %q on %q", source.requestedVersion, source.requested)
	}
	if report.RequestedVersion != version || report.LatestVersion != version ||
		report.Channel != string(releaseChannelAlpha) {
		t.Fatalf("unexpected exact-version report: %+v", report)
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), userAgentDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("exact-version update check mutated local installation state")
	}
}
