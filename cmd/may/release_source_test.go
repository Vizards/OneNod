package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	value, err := source.Download(context.Background(), release, artifact)
	if err != nil || !bytes.Equal(value, content) {
		t.Fatal(err)
	}
	artifact.SHA256 = "sha256:" + strings.Repeat("0", 64)
	if _, err := source.Download(context.Background(), release, artifact); err == nil {
		t.Fatal("bad artifact digest was accepted")
	}
}

func TestAuthenticatedArtifactSnapshotSurvivesSourceReplacement(t *testing.T) {
	manifest := validManifestFixture("0.0.2-alpha.21", nil)
	mayBytes := []byte("verified may")
	adapterBytes := []byte("verified adapter")
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
	archivePath := filepath.Join(t.TempDir(), "verified.tar.gz")
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
	artifact := releaseArtifact{
		Name: "onenod-darwin-" + runtime.GOARCH + ".tar.gz", Size: int64(len(archive)),
		SHA256: "sha256:" + hex.EncodeToString(digest[:]),
	}
	source := &memoryReleaseSource{downloads: map[string][]byte{artifact.Name: archive}}
	snapshot, err := source.Download(context.Background(), &verifiedRelease{}, artifact)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate replacement of the same-UID writable download/staging source
	// after authentication. Extraction must consume the retained byte snapshot.
	for index := range source.downloads[artifact.Name] {
		source.downloads[artifact.Name][index] ^= 0xff
	}
	if _, err := extractVerifiedLocalArchive(source.downloads[artifact.Name], t.TempDir(), manifest); err == nil {
		t.Fatal("source replacement fixture remained a valid release archive")
	}
	if _, err := extractVerifiedLocalArchive(snapshot, t.TempDir(), manifest); err != nil {
		t.Fatalf("authenticated snapshot was not independent of its mutable source: %v", err)
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
				value, err := os.ReadFile(archive)
				if err != nil {
					return err
				}
				return extractReleaseArchiveSnapshot(value, destination, map[string]os.FileMode{
					"onenod/bin/may": 0o700,
				})
			},
		},
		{name: "Skill", entry: "onenod-skill/onenod/SKILL.md", extract: func(archive, destination string) error {
			value, err := os.ReadFile(archive)
			if err != nil {
				return err
			}
			return extractSkillArchive(value, destination)
		}},
		{name: "deployment", entry: "onenod-deployment/gateway/worker.mjs", extract: func(archive, destination string) error {
			value, err := os.ReadFile(archive)
			if err != nil {
				return err
			}
			return extractDeploymentBundleArchive(value, destination)
		}},
	}
}
