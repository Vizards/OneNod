package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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

	in_toto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

type memoryReleaseSource struct {
	release          *verifiedRelease
	downloads        map[string][]byte
	requested        releaseChannel
	requestedVersion string
}

func (source *memoryReleaseSource) Latest(_ context.Context, channel releaseChannel) (*verifiedRelease, error) {
	if source.release == nil {
		return nil, errors.New("no release")
	}
	source.requested = channel
	source.requestedVersion = ""
	source.release.SelectedChannel = channel
	source.release.RequestedVersion = ""
	return source.release, nil
}

func (source *memoryReleaseSource) Exact(_ context.Context, version string) (*verifiedRelease, error) {
	if source.release == nil {
		return nil, errors.New("no release")
	}
	if source.release.Manifest.ReleaseVersion != version {
		return nil, errors.New("unexpected exact release")
	}
	source.requested = releaseChannelForVersion(version)
	source.requestedVersion = version
	source.release.SelectedChannel = source.requested
	source.release.RequestedVersion = version
	return source.release, nil
}

func (source *memoryReleaseSource) Download(
	_ context.Context,
	_ *verifiedRelease,
	artifact releaseArtifact,
	destination string,
) error {
	value, ok := source.downloads[artifact.Name]
	if !ok {
		return errors.New("missing download")
	}
	digest := sha256.Sum256(value)
	if int64(len(value)) != artifact.Size ||
		"sha256:"+hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return errors.New("fixture digest mismatch")
	}
	return os.WriteFile(destination, value, 0o600)
}

func validManifestFixture(version string, artifacts []releaseArtifact) releaseManifest {
	for index := range artifacts {
		if artifacts[index].Kind == "" {
			artifacts[index].Kind = "local"
			artifacts[index].Platform = &struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			}{Architecture: "arm64", OS: "darwin"}
		}
	}
	manifest := releaseManifest{
		Artifacts: artifacts, Channel: string(releaseChannelForVersion(version)),
		ProductLabel: "Public Preview", PublishedAt: "2026-08-01T00:00:00Z", ReleaseVersion: version,
		SchemaVersion: manifestSchema, Tag: "v" + version,
	}
	manifest.Source.Repository = officialRepository
	manifest.Source.Workflow = officialReleaseWorkflow
	manifest.Source.Commit = strings.Repeat("a", 40)
	manifest.Attestations.Issuer = "https://token.actions.githubusercontent.com"
	manifest.Attestations.Repository = officialRepository
	manifest.Attestations.Workflow = officialReleaseWorkflow
	manifest.Components.May.Version = version
	manifest.Components.May.ClientProtocol = mayClientProtocol
	manifest.Components.SSHAgent.Version = version
	manifest.Components.Gateway.Version = version
	manifest.Components.Gateway.AcceptedClientProtocol = protocolRange{Minimum: 1, Maximum: 1}
	manifest.Components.Gateway.StateSchema = 1
	manifest.Components.Executor.Version = version
	manifest.Components.Executor.AcceptedGatewayProtocol = protocolRange{Minimum: 1, Maximum: 1}
	manifest.Components.Executor.StateSchema = 1
	manifest.Components.PWA.Version = version
	manifest.Components.Skill.Version = version
	manifest.Components.KeychainHelper.Version = "1.0.0"
	manifest.Components.KeychainHelper.SourceDigest = "sha256:" + strings.Repeat("b", 64)
	manifest.Components.KeychainHelper.HelperProtocol = protocolRange{Minimum: 1, Maximum: 1}
	manifest.Requirements.Wrangler = versionRange{Minimum: "4.116.0", MaximumExclusive: "5.0.0"}
	manifest.Requirements.OnePasswordCLI = versionRange{Minimum: "2.34.0", MaximumExclusive: "3.0.0"}
	manifest.Requirements.Node = versionRange{Minimum: "22.12.0", MaximumExclusive: "23.0.0"}
	manifest.Requirements.MacOS.Minimum = "15.0"
	manifest.Requirements.MacOS.Architectures = []string{"arm64", "amd64"}
	manifest.Requirements.OnePasswordRegions = []string{"com", "ca", "eu"}
	manifest.Support.LatestOnly = true
	manifest.Support.MinimumSafeVersion = "0.0.1"
	if version != "0.0.1" {
		manifest.Support.PreviousReleaseVersion = "0.0.1"
	}
	manifest.Upgrade.MinimumUpdaterVersion = "0.0.1"
	manifest.Upgrade.MinimumSafeVersion = "0.0.1"
	manifest.Upgrade.RevokedArtifactDigests = []string{}
	manifest.Upgrade.Order = []string{"executor", "gateway", "local", "skill"}
	manifest.Upgrade.RemoteRollbackSafe = true
	return manifest
}

func canonicalManifestFixture(version string) (releaseManifest, map[string]releaseAsset) {
	manifest := validManifestFixture(version, nil)
	assets := map[string]releaseAsset{
		releaseManifestAssetName:  {Name: releaseManifestAssetName, Size: 100},
		provenanceBundleAssetName: {Name: provenanceBundleAssetName, Size: 100},
		"SHA256SUMS":              {Name: "SHA256SUMS", Size: 100},
	}
	for name, contract := range expectedReleaseArtifactContract(manifest) {
		artifact := releaseArtifact{
			Kind: contract.Kind, Name: name, Size: 12,
			SHA256: "sha256:" + strings.Repeat("a", 64), Subject: contract.Subject,
		}
		if contract.OS != "" {
			artifact.Platform = &struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			}{Architecture: contract.Architecture, OS: contract.OS}
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
		assets[name] = releaseAsset{Name: name, Size: artifact.Size}
	}
	return manifest, assets
}

func TestReleaseManifestRequiresOfficialAtomicStableNMinusOneContract(t *testing.T) {
	manifest, assets := canonicalManifestFixture("0.0.2")
	artifact := manifest.Artifacts[0]
	if err := validateReleaseManifest(manifest, "v0.0.2", assets); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*releaseManifest){
		"repository":      func(value *releaseManifest) { value.Source.Repository = "attacker/fork" },
		"channel":         func(value *releaseManifest) { value.Channel = "preview" },
		"component drift": func(value *releaseManifest) { value.Components.PWA.Version = "0.0.1" },
		"missing N-1":     func(value *releaseManifest) { value.Support.PreviousReleaseVersion = "" },
		"revoked artifact": func(value *releaseManifest) {
			value.RevokedArtifactDigests = []string{artifact.SHA256}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			mutate(&changed)
			if err := validateReleaseManifest(changed, "v0.0.2", assets); err == nil {
				t.Fatal("unsafe release manifest was accepted")
			}
		})
	}
	t.Run("unexpected immutable asset", func(t *testing.T) {
		changedAssets := make(map[string]releaseAsset, len(assets)+1)
		for name, asset := range assets {
			changedAssets[name] = asset
		}
		changedAssets["surprise.txt"] = releaseAsset{Name: "surprise.txt", Size: 1}
		if err := validateReleaseManifest(manifest, "v0.0.2", changedAssets); err == nil {
			t.Fatal("unexpected immutable Release asset was accepted")
		}
	})
	t.Run("missing canonical artifact", func(t *testing.T) {
		changed := manifest
		changed.Artifacts = append([]releaseArtifact(nil), manifest.Artifacts[1:]...)
		if err := validateReleaseManifest(changed, "v0.0.2", assets); err == nil {
			t.Fatal("incomplete canonical artifact set was accepted")
		}
	})
	t.Run("SBOM subject drift", func(t *testing.T) {
		changed := manifest
		changed.Artifacts = append([]releaseArtifact(nil), manifest.Artifacts...)
		for index := range changed.Artifacts {
			if changed.Artifacts[index].Kind == "sbom" {
				changed.Artifacts[index].Subject = "different.tar.gz"
				break
			}
		}
		if err := validateReleaseManifest(changed, "v0.0.2", assets); err == nil {
			t.Fatal("SBOM bound to the wrong archive was accepted")
		}
	})
}

func TestReleaseManifestAcceptsSafePresentationProductLabels(t *testing.T) {
	for _, fixture := range []struct {
		version string
		label   string
	}{
		{version: "0.0.2-alpha.1", label: "Alpha"},
		{version: "0.0.2-beta.1", label: "Beta"},
		{version: "0.0.2", label: "Future Stable Label"},
	} {
		t.Run(fixture.version, func(t *testing.T) {
			manifest, assets := canonicalManifestFixture(fixture.version)
			manifest.ProductLabel = fixture.label
			if err := validateReleaseManifest(manifest, "v"+fixture.version, assets); err != nil {
				t.Fatalf("valid %s manifest rejected: %v", fixture.version, err)
			}
		})
	}

	manifest, assets := canonicalManifestFixture("0.0.2")
	for _, label := range []string{
		"", " leading", "trailing ", "line\nbreak", "nul\x00byte",
		strings.Repeat("a", 65), string([]byte{0xff}),
	} {
		manifest.ProductLabel = label
		if err := validateReleaseManifest(manifest, "v0.0.2", assets); err == nil {
			t.Errorf("unsafe product label %q was accepted", label)
		}
	}
}

func TestRunningReleaseConsumerGate(t *testing.T) {
	manifest := validManifestFixture("0.0.2", nil)
	commit := manifest.Source.Commit
	setBuildIdentity := func(version, tag, source string) func() {
		oldVersion, oldTag, oldSource := productVersion, releaseTag, sourceCommit
		productVersion, releaseTag, sourceCommit = version, tag, source
		return func() { productVersion, releaseTag, sourceCommit = oldVersion, oldTag, oldSource }
	}

	restore := setBuildIdentity("0.0.2", "v0.0.2", commit)
	exact, err := runningReleaseCanConsume(manifest)
	restore()
	if err != nil || !exact {
		t.Fatalf("exact Release identity rejected: exact=%v err=%v", exact, err)
	}

	restore = setBuildIdentity("0.0.1", "v0.0.1", strings.Repeat("b", 40))
	exact, err = runningReleaseCanConsume(manifest)
	restore()
	if err != nil || exact {
		t.Fatalf("supported older updater gate mismatch: exact=%v err=%v", exact, err)
	}

	for name, mutate := range map[string]func(*releaseManifest) func(){
		"development build": func(_ *releaseManifest) func() {
			return setBuildIdentity("0.0.0-dev", "dev", "unknown")
		},
		"below minimum updater": func(value *releaseManifest) func() {
			value.Upgrade.MinimumUpdaterVersion = "0.0.2"
			return setBuildIdentity("0.0.1", "v0.0.1", strings.Repeat("b", 40))
		},
		"newer than latest": func(_ *releaseManifest) func() {
			return setBuildIdentity("0.0.3", "v0.0.3", strings.Repeat("c", 40))
		},
		"same version wrong commit": func(_ *releaseManifest) func() {
			return setBuildIdentity("0.0.2", "v0.0.2", strings.Repeat("c", 40))
		},
		"helper protocol incompatible": func(value *releaseManifest) func() {
			value.Components.KeychainHelper.HelperProtocol = protocolRange{Minimum: 2, Maximum: 2}
			return setBuildIdentity("0.0.1", "v0.0.1", strings.Repeat("b", 40))
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			restore := mutate(&changed)
			defer restore()
			if _, err := runningReleaseCanConsume(changed); err == nil {
				t.Fatal("unsafe running Release identity was accepted")
			}
		})
	}
}

func TestGitHubResolverRequiresTrueImmutableReleaseField(t *testing.T) {
	for _, fixture := range []string{
		`{"draft":false,"prerelease":false,"tag_name":"v0.0.1","assets":[]}`,
		`{"immutable":false,"draft":false,"prerelease":false,"tag_name":"v0.0.1","assets":[]}`,
	} {
		t.Run(fixture, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				response.Header().Set("content-type", "application/json")
				_, _ = io.WriteString(response, fixture)
			}))
			defer server.Close()
			source := &githubReleaseSource{client: server.Client(), latestURL: server.URL}
			if _, err := source.Latest(context.Background(), releaseChannelStable); err == nil || !strings.Contains(err.Error(), "immutable") {
				t.Fatalf("mutable or ambiguous release returned %v", err)
			}
		})
	}
}

func TestProductSemverAndReleaseChannelContract(t *testing.T) {
	for _, version := range []string{
		"0.0.1",
		"0.0.2-alpha.1",
		"0.0.2-beta.12",
		"9007199254740991.9007199254740991.9007199254740991",
		"1.2.3-alpha.9007199254740991",
	} {
		if !validProductVersion(version) {
			t.Errorf("valid product version rejected: %s", version)
		}
	}
	for _, version := range []string{
		"0.0.2-alpha.0",
		"0.0.2-alpha",
		"0.0.2-rc.1",
		"0.0.2+build",
		"01.0.2",
		"0.0.2-Alpha.1",
		"9007199254740992.0.0",
		"0.0.2-alpha.9007199254740992",
	} {
		if validProductVersion(version) {
			t.Errorf("invalid product version accepted: %s", version)
		}
	}

	ordered := []string{
		"0.0.2-alpha.1",
		"0.0.2-alpha.2",
		"0.0.2-beta.1",
		"0.0.2",
		"0.0.3-alpha.1",
	}
	for index := 1; index < len(ordered); index++ {
		if compareProductVersions(ordered[index-1], ordered[index]) >= 0 {
			t.Errorf("SemVer precedence is not increasing: %s, %s", ordered[index-1], ordered[index])
		}
	}

	for _, fixture := range []struct {
		selected  releaseChannel
		candidate releaseChannel
		accepted  bool
	}{
		{releaseChannelStable, releaseChannelStable, true},
		{releaseChannelStable, releaseChannelBeta, false},
		{releaseChannelStable, releaseChannelAlpha, false},
		{releaseChannelBeta, releaseChannelStable, true},
		{releaseChannelBeta, releaseChannelBeta, true},
		{releaseChannelBeta, releaseChannelAlpha, false},
		{releaseChannelAlpha, releaseChannelStable, true},
		{releaseChannelAlpha, releaseChannelBeta, true},
		{releaseChannelAlpha, releaseChannelAlpha, true},
	} {
		if got := releaseChannelAccepts(fixture.selected, fixture.candidate); got != fixture.accepted {
			t.Errorf("channel %s accepting %s = %v, want %v", fixture.selected, fixture.candidate, got, fixture.accepted)
		}
	}
}

func TestExactReleaseSelectionContract(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		channel  string
		version  string
		fallback releaseChannel
		want     releaseSelection
	}{
		{
			name: "fallback channel", fallback: releaseChannelBeta,
			want: releaseSelection{Channel: releaseChannelBeta},
		},
		{
			name: "explicit channel", channel: "alpha", fallback: releaseChannelStable,
			want: releaseSelection{Channel: releaseChannelAlpha},
		},
		{
			name: "exact alpha", version: "0.0.2-alpha.7", fallback: releaseChannelStable,
			want: releaseSelection{Channel: releaseChannelAlpha, Version: "0.0.2-alpha.7"},
		},
		{
			name: "exact stable", version: "0.0.2", fallback: releaseChannelAlpha,
			want: releaseSelection{Channel: releaseChannelStable, Version: "0.0.2"},
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			selection, err := releaseSelectionFromFlags(
				fixture.channel, fixture.version, fixture.fallback,
			)
			if err != nil {
				t.Fatal(err)
			}
			if selection != fixture.want {
				t.Fatalf("selection = %+v, want %+v", selection, fixture.want)
			}
		})
	}

	for _, fixture := range []struct {
		name    string
		channel string
		version string
	}{
		{name: "mutually exclusive", channel: "alpha", version: "0.0.2-alpha.7"},
		{name: "v prefix", version: "v0.0.2-alpha.7"},
		{name: "surrounding whitespace", version: " 0.0.2-alpha.7"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if _, err := releaseSelectionFromFlags(
				fixture.channel, fixture.version, releaseChannelStable,
			); err == nil {
				t.Fatal("invalid release selection was accepted")
			}
		})
	}
}

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

func TestPrereleaseResolverSelectsHighestAcceptedSemver(t *testing.T) {
	releases := []githubReleaseMetadata{
		{Tag: "v0.0.2-beta.2", Immutable: true, Prerelease: true},
		{Tag: "v0.0.2", Immutable: true},
		{Tag: "v0.0.3-alpha.1", Immutable: true, Prerelease: true},
		{Tag: "v0.0.2-beta.12", Immutable: true, Prerelease: true},
		{Tag: "v9.0.0", Immutable: true, Draft: true},
	}
	for _, fixture := range []struct {
		channel releaseChannel
		want    string
	}{
		{releaseChannelStable, "v0.0.2"},
		{releaseChannelBeta, "v0.0.2"},
		{releaseChannelAlpha, "v0.0.3-alpha.1"},
	} {
		selected, err := selectLatestReleaseMetadata(releases, fixture.channel)
		if err != nil {
			t.Fatalf("select %s: %v", fixture.channel, err)
		}
		if selected.Tag != fixture.want {
			t.Errorf("select %s = %s, want %s", fixture.channel, selected.Tag, fixture.want)
		}
	}
}

func TestPrereleaseResolverSkipsHistoricalGitHubMetadataMismatch(t *testing.T) {
	selected, err := selectLatestReleaseMetadata([]githubReleaseMetadata{
		{Tag: "v0.0.2-beta.2", Immutable: true, Prerelease: false},
		{Tag: "v0.0.2-beta.1", Immutable: true, Prerelease: true},
	}, releaseChannelBeta)
	if err != nil || selected.Tag != "v0.0.2-beta.1" {
		t.Fatalf("valid candidate was not selected after bad historical entry: %+v, %v", selected, err)
	}

	_, err = selectLatestReleaseMetadata([]githubReleaseMetadata{
		{Tag: "v0.0.2-beta.2", Immutable: true, Prerelease: false},
	}, releaseChannelBeta)
	if err == nil || !strings.Contains(err.Error(), "no published immutable OneNod release") {
		t.Fatalf("resolver without a compatible candidate returned %v", err)
	}
}

func TestPrereleaseDiscoveryPaginatesPastAnIncompatibleFirstPage(t *testing.T) {
	requestedPages := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/releases" || request.URL.Query().Get("per_page") != "100" {
			http.NotFound(response, request)
			return
		}
		page := request.URL.Query().Get("page")
		requestedPages = append(requestedPages, page)
		response.Header().Set("content-type", "application/json")
		switch page {
		case "1":
			releases := make([]githubReleaseMetadata, 100)
			for index := range releases {
				releases[index] = githubReleaseMetadata{
					Immutable:  true,
					Prerelease: true,
					Tag:        "v0.0.3-alpha.1",
				}
			}
			_ = json.NewEncoder(response).Encode(releases)
		case "2":
			_ = json.NewEncoder(response).Encode([]githubReleaseMetadata{{
				Immutable: true,
				Tag:       "v0.0.2",
			}})
		default:
			_ = json.NewEncoder(response).Encode([]githubReleaseMetadata{})
		}
	}))
	defer server.Close()

	source := &githubReleaseSource{
		client: server.Client(), releasesURL: server.URL + "/releases?per_page=100",
	}
	selected, err := source.discoverLatestReleaseMetadata(
		context.Background(), releaseChannelBeta,
	)
	if err != nil {
		t.Fatal(err)
	}
	if selected.Tag != "v0.0.2" {
		t.Fatalf("paginated beta discovery selected %q", selected.Tag)
	}
	if strings.Join(requestedPages, ",") != "1,2" {
		t.Fatalf("release discovery requested pages %q", requestedPages)
	}
}

func TestPrereleaseDiscoveryStopsAtFirstCompatiblePage(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Query().Get("page") != "1" {
			http.Error(response, "unexpected release page", http.StatusInternalServerError)
			return
		}
		releases := make([]githubReleaseMetadata, 100)
		for index := range releases {
			releases[index] = githubReleaseMetadata{
				Immutable:  true,
				Prerelease: true,
				Tag:        "v0.0.2-beta.1",
			}
		}
		response.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(response).Encode(releases)
	}))
	defer server.Close()

	source := &githubReleaseSource{
		client: server.Client(), releasesURL: server.URL + "/releases",
	}
	selected, err := source.discoverLatestReleaseMetadata(
		context.Background(), releaseChannelBeta,
	)
	if err != nil || selected.Tag != "v0.0.2-beta.1" || requests != 1 {
		t.Fatalf("first compatible release page was not terminal: %+v, requests=%d, err=%v", selected, requests, err)
	}
}

func TestExactResolverUsesTagEndpointAndFullManifestValidation(t *testing.T) {
	const version = "0.0.2-alpha.7"
	manifest, assets := canonicalManifestFixture(version)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	requestedPath := ""
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/releases/tags/v" + version:
			requestedPath = request.URL.Path
			metadataAssets := make([]map[string]any, 0, len(assets))
			for name, asset := range assets {
				size := asset.Size
				if name == releaseManifestAssetName {
					size = int64(len(manifestBytes))
				}
				metadataAssets = append(metadataAssets, map[string]any{
					"name": name,
					"size": size,
					"url":  server.URL + "/assets/" + name,
				})
			}
			response.Header().Set("content-type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{
				"assets": metadataAssets, "draft": false, "immutable": true,
				"prerelease": true, "tag_name": "v" + version,
			})
		case "/assets/" + releaseManifestAssetName:
			response.Header().Set("content-type", "application/octet-stream")
			_, _ = response.Write(manifestBytes)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	source := &githubReleaseSource{
		client: server.Client(), releaseByTagURL: server.URL + "/releases/tags/",
	}
	release, err := source.Exact(context.Background(), version)
	if err != nil {
		t.Fatal(err)
	}
	if requestedPath != "/releases/tags/v"+version {
		t.Fatalf("exact resolver requested %q", requestedPath)
	}
	if release.Manifest.ReleaseVersion != version ||
		release.RequestedVersion != version ||
		release.SelectedChannel != releaseChannelAlpha {
		t.Fatalf("unexpected exact release identity: %+v", release)
	}
}

func TestExactResolverRejectsDifferentTag(t *testing.T) {
	const version = "0.0.2-alpha.7"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{
			"assets": []any{}, "draft": false, "immutable": true,
			"prerelease": true, "tag_name": "v0.0.2-alpha.6",
		})
	}))
	defer server.Close()
	source := &githubReleaseSource{
		client: server.Client(), releaseByTagURL: server.URL + "/releases/tags/",
	}
	if _, err := source.Exact(context.Background(), version); err == nil {
		t.Fatal("different exact release tag was accepted")
	}
}

func TestOfficialSourceSecurityDoesNotDependOnDiscoveryURL(t *testing.T) {
	official := &githubReleaseSource{official: true, latestURL: "https://mirror.invalid/latest"}
	if err := official.validateAddress("http://localhost/release"); err == nil {
		t.Fatal("official source accepted an untrusted asset address")
	}
	custom := &githubReleaseSource{latestURL: officialLatestReleaseAPI}
	if err := custom.validateAddress("http://localhost/release"); err != nil {
		t.Fatalf("non-official test source was incorrectly promoted by URL equality: %v", err)
	}
}

func TestReceiptChannelBackwardCompatibilityAndRiskBinding(t *testing.T) {
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
}

func TestHigherRiskChannelRequiresExplicitApproval(t *testing.T) {
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
	if runtime.GOOS != "darwin" || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") {
		t.Skip("OneNod local receipts are supported on macOS hosts")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
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
	receipt.Helper.Protocol = 1
	receipt.Helper.SourceDigest = digest
	receipt.Helper.Version = "1.0.0"
	receipt.Skill.Artifact = skillArtifactName(currentVersion)
	receipt.Skill.ArtifactSHA = digest
	receipt.Skill.Discovery = []string{"~/.agents/skills/onenod", "~/.claude/skills/onenod"}
	receipt.Skill.TreeSHA256 = digest
	receipt.Skill.Version = currentVersion
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
				"accepted_client_protocol": map[string]int{"min": 1, "max": 1},
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

func TestReleaseProvenancePredicateMatchesSupportedGitHubEvents(t *testing.T) {
	repositoryID := "123456789"
	commit := strings.Repeat("a", 40)
	for _, fixture := range []struct {
		event string
		ref   string
	}{
		{event: "push", ref: "refs/heads/main"},
		{event: "workflow_dispatch", ref: "refs/heads/main"},
		{event: "workflow_dispatch", ref: "refs/tags/v0.0.1"},
	} {
		predicate := releaseProvenanceFixture(repositoryID, commit, fixture.ref, fixture.event)
		if !releaseProvenancePredicateMatches(predicate, repositoryID, commit, fixture.ref) {
			t.Fatalf("valid %s provenance predicate was rejected", fixture.event)
		}
	}
}

func TestOfficialWorkflowCommitIsIndependentFromAttestedReleaseCommit(t *testing.T) {
	repositoryID := "123456789"
	workflowCommit := strings.Repeat("b", 40)
	releaseCommit := strings.Repeat("a", 40)
	sourceRef := "refs/heads/main"
	expectedSAN := "https://github.com/" + officialRepository + "/" +
		officialReleaseWorkflow + "@" + sourceRef
	summary := &certificate.Summary{Extensions: certificate.Extensions{
		BuildConfigDigest:                   workflowCommit,
		BuildConfigURI:                      expectedSAN,
		BuildSignerDigest:                   workflowCommit,
		BuildSignerURI:                      expectedSAN,
		BuildTrigger:                        "workflow_dispatch",
		RunnerEnvironment:                   "github-hosted",
		SourceRepositoryDigest:              workflowCommit,
		SourceRepositoryIdentifier:          repositoryID,
		SourceRepositoryOwnerIdentifier:     "13443193",
		SourceRepositoryOwnerURI:            "https://github.com/Vizards",
		SourceRepositoryRef:                 sourceRef,
		SourceRepositoryURI:                 "https://github.com/" + officialRepository,
		SourceRepositoryVisibilityAtSigning: "public",
	}}

	actual, ok := officialWorkflowCommit(summary, repositoryID, sourceRef, expectedSAN)
	if !ok || actual != workflowCommit || actual == releaseCommit {
		t.Fatalf("trusted retry workflow identity was rejected: commit=%q ok=%v", actual, ok)
	}
	summary.BuildConfigDigest = releaseCommit
	if _, ok := officialWorkflowCommit(summary, repositoryID, sourceRef, expectedSAN); ok {
		t.Fatal("certificate fields bound to different commits were accepted")
	}
}

func TestReleaseProvenancePredicateRejectsIdentityAndShapeDrift(t *testing.T) {
	repositoryID := "123456789"
	commit := strings.Repeat("a", 40)
	ref := "refs/heads/main"
	for name, mutate := range map[string]func(map[string]any){
		"wrong build type": func(predicate map[string]any) {
			predicate["buildDefinition"].(map[string]any)["buildType"] = "attacker/build"
		},
		"wrong builder": func(predicate map[string]any) {
			predicate["runDetails"].(map[string]any)["builder"].(map[string]any)["id"] = "https://github.com/attacker/workflow"
		},
		"self hosted": func(predicate map[string]any) {
			predicate["buildDefinition"].(map[string]any)["internalParameters"].(map[string]any)["github"].(map[string]any)["runner_environment"] = "self-hosted"
		},
		"extra dependency": func(predicate map[string]any) {
			definition := predicate["buildDefinition"].(map[string]any)
			definition["resolvedDependencies"] = append(definition["resolvedDependencies"].([]any), map[string]any{})
		},
	} {
		t.Run(name, func(t *testing.T) {
			predicate := releaseProvenanceFixture(repositoryID, commit, ref, "push")
			mutate(predicate)
			if releaseProvenancePredicateMatches(predicate, repositoryID, commit, ref) {
				t.Fatal("unsafe provenance predicate was accepted")
			}
		})
	}
}

func releaseProvenanceFixture(repositoryID, commit, ref, event string) map[string]any {
	workflowID := "https://github.com/" + officialRepository + "/" + officialReleaseWorkflow + "@" + ref
	return map[string]any{
		"buildDefinition": map[string]any{
			"buildType": "https://actions.github.io/buildtypes/workflow/v1",
			"externalParameters": map[string]any{"workflow": map[string]any{
				"repository": "https://github.com/" + officialRepository,
				"path":       officialReleaseWorkflow,
				"ref":        ref,
			}},
			"internalParameters": map[string]any{"github": map[string]any{
				"event_name":          event,
				"repository_id":       repositoryID,
				"repository_owner_id": "13443193",
				"runner_environment":  "github-hosted",
			}},
			"resolvedDependencies": []any{map[string]any{
				"uri": "git+https://github.com/" + officialRepository + "@" + ref,
				"digest": map[string]any{
					"gitCommit": commit,
				},
			}},
		},
		"runDetails": map[string]any{
			"builder": map[string]any{"id": workflowID},
			"metadata": map[string]any{
				"invocationId": "https://github.com/" + officialRepository + "/actions/runs/123/attempts/1",
			},
		},
	}
}

func TestStatementSubjectMustBeExactAndUnique(t *testing.T) {
	digest := strings.Repeat("a", 64)
	subject := &in_toto.ResourceDescriptor{Name: "release-manifest.json", Digest: map[string]string{"sha256": digest}}
	if !statementHasExactSubject([]*in_toto.ResourceDescriptor{subject}, subject.Name, digest) {
		t.Fatal("exact subject was rejected")
	}
	if statementHasExactSubject([]*in_toto.ResourceDescriptor{subject, subject}, subject.Name, digest) {
		t.Fatal("multi-subject attestation was accepted")
	}
}

func TestGitHubArtifactDownloadChecksExactSizeAndDigest(t *testing.T) {
	content := []byte("verified artifact")
	digest := sha256.Sum256(content)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write(content)
	}))
	defer server.Close()
	artifact := releaseArtifact{
		Name: "artifact.tar.gz", Size: int64(len(content)),
		SHA256: "sha256:" + hex.EncodeToString(digest[:]),
	}
	release := &verifiedRelease{Assets: map[string]releaseAsset{
		artifact.Name: {Name: artifact.Name, Size: artifact.Size, APIURL: server.URL},
	}}
	source := &githubReleaseSource{client: server.Client(), latestURL: server.URL}
	destination := filepath.Join(t.TempDir(), artifact.Name)
	if err := source.Download(context.Background(), release, artifact, destination); err != nil {
		t.Fatal(err)
	}
	artifact.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if err := source.Download(context.Background(), release, artifact, destination+"-bad"); err == nil {
		t.Fatal("bad artifact digest was accepted")
	}
}

type archiveExtractorFixture struct {
	name    string
	entry   string
	extract func(string, string) error
}

func archiveExtractorFixtures() []archiveExtractorFixture {
	return []archiveExtractorFixture{
		{
			name:  "release",
			entry: "onenod/bin/may",
			extract: func(archive, destination string) error {
				return extractReleaseArchive(archive, destination, map[string]os.FileMode{
					"onenod/bin/may": 0o700,
				})
			},
		},
		{name: "Skill", entry: "onenod-skill/onenod/SKILL.md", extract: extractSkillArchive},
		{name: "deployment", entry: "onenod-deployment/gateway/worker.mjs", extract: extractDeploymentBundleArchive},
	}
}

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

func TestReleaseArchiveIgnoresSafeAuxiliaryFiles(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "release.tar.gz")
	writeTestRegularArchive(t, archive, []testArchiveFile{
		{name: "onenod/bin/may", content: []byte("binary")},
		{name: "onenod/THIRD_PARTY_COMPONENTS.json", content: []byte("{}")},
		{name: "onenod/THIRD_PARTY_NOTICES.txt", content: []byte("notices")},
		{name: "onenod/future-metadata.txt"},
	})
	destination := t.TempDir()
	if err := extractReleaseArchive(archive, destination, map[string]os.FileMode{
		"onenod/bin/may": 0o700,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "onenod", "THIRD_PARTY_COMPONENTS.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused auxiliary release file was promoted out of the archive")
	}
}

func TestDeploymentArchiveRequiresRuntimeFilesButIgnoresSafeAuxiliaryFiles(t *testing.T) {
	archive := filepath.Join(t.TempDir(), "deployment.tar.gz")
	entries := []testArchiveFile{
		{name: "onenod-deployment/gateway/assets/index.html", content: []byte("index")},
		{name: "onenod-deployment/THIRD_PARTY_COMPONENTS.json", content: []byte("{}")},
		{name: "onenod-deployment/THIRD_PARTY_NOTICES.txt", content: []byte("notices")},
		{name: "onenod-deployment/executor/third-party/onepassword-sdk-go/LICENSE", content: []byte("MIT")},
		{name: "onenod-deployment/executor/third-party/onepassword-sdk-go/SOURCE.json", content: []byte("{}")},
		{name: "onenod-deployment/future-metadata.txt"},
	}
	for path := range deploymentBundleRequiredFiles() {
		entries = append(entries, testArchiveFile{name: path, content: []byte("runtime")})
	}
	writeTestRegularArchive(t, archive, entries)
	destination := t.TempDir()
	if err := extractDeploymentBundleArchive(archive, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(destination, "onenod-deployment", "gateway", "worker.mjs")); err != nil {
		t.Fatal("required deployment runtime file was not extracted")
	}
	if _, err := os.Stat(filepath.Join(destination, "onenod-deployment", "THIRD_PARTY_COMPONENTS.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused auxiliary deployment file was promoted out of the archive")
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
	if err := verifyReleaseArtifactInstallability(
		manifest, releaseArtifact{Kind: "deployment"}, archive,
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
	if err := verifyReleaseArtifactInstallability(
		manifest, releaseArtifact{Kind: "deployment"}, wrongArchive,
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

func TestVersionParsingAndComparison(t *testing.T) {
	if got := firstStableVersion("wrangler 4.116.0 (update available)"); got != "4.116.0" {
		t.Fatalf("parsed %q", got)
	}
	if compareVersions("0.10.0", "0.9.9") <= 0 || compareVersions("1.0.0", "1.0.0") != 0 {
		t.Fatal("semantic version comparison is incorrect")
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
	receipt.Helper.Protocol = 1
	receipt.Helper.SourceDigest = manifest.Components.KeychainHelper.SourceDigest
	receipt.Helper.Version = manifest.Components.KeychainHelper.Version
	helper := keychainHelperResponse{Protocol: 1, Version: manifest.Components.KeychainHelper.Version}
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

func TestSkillDiscoveryAdoptsRecognizableDifferentBootstrapSkill(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, userAgentDirectoryName, "skill-versions", "0.0.2", "onenod")
	stable := filepath.Join(home, userAgentDirectoryName, "skill")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("verified release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("skill-versions", "0.0.2", "onenod"), stable); err != nil {
		t.Fatal(err)
	}
	bootstrapTarget := filepath.Join(home, "bootstrap-onenod")
	if err := os.MkdirAll(bootstrapTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	bootstrapSkill := "---\nname: onenod\ndescription: bootstrap\n---\n\nOfficial: https://github.com/Vizards/OneNod\nolder bytes\n"
	if err := os.WriteFile(filepath.Join(bootstrapTarget, "SKILL.md"), []byte(bootstrapSkill), 0o600); err != nil {
		t.Fatal(err)
	}
	discovery := filepath.Join(home, ".agents", "skills", "onenod")
	if err := os.MkdirAll(filepath.Dir(discovery), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bootstrapTarget, discovery); err != nil {
		t.Fatal(err)
	}
	digest, err := directoryTreeSHA256(target)
	if err != nil {
		t.Fatal(err)
	}
	_, transaction, err := installSkillDiscoveryLinks(home, stable, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(transaction.backupPaths()) != 1 {
		t.Fatalf("expected one recoverable takeover backup, got %v", transaction.backupPaths())
	}
	if value, err := os.ReadFile(filepath.Join(bootstrapTarget, "SKILL.md")); err != nil || string(value) != bootstrapSkill {
		t.Fatal("external bootstrap symlink target was modified")
	}
	if info, err := os.Lstat(discovery); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("recognizable bootstrap entry was not replaced with managed discovery link")
	}
	if err := transaction.rollback(); err != nil {
		t.Fatal(err)
	}
	restoredTarget, err := os.Readlink(discovery)
	if err != nil || restoredTarget != bootstrapTarget {
		t.Fatalf("bootstrap discovery symlink was not restored exactly: %q %v", restoredTarget, err)
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
