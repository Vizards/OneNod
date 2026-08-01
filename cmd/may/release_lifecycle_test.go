package main

import (
	"archive/tar"
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
)

type memoryReleaseSource struct {
	release   *verifiedRelease
	downloads map[string][]byte
}

func (source *memoryReleaseSource) Latest(context.Context) (*verifiedRelease, error) {
	if source.release == nil {
		return nil, errors.New("no release")
	}
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
		Artifacts: artifacts, Channel: officialReleaseChannel,
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
	manifest.Requirements.OnePasswordCLI = versionRange{Minimum: "2.30.0", MaximumExclusive: "3.0.0"}
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
			if _, err := source.Latest(context.Background()); err == nil || !strings.Contains(err.Error(), "immutable") {
				t.Fatalf("mutable or ambiguous release returned %v", err)
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
		{event: "workflow_dispatch", ref: "refs/tags/v0.0.1"},
	} {
		predicate := releaseProvenanceFixture(repositoryID, commit, fixture.ref, fixture.event)
		if !releaseProvenancePredicateMatches(predicate, repositoryID, commit, fixture.ref) {
			t.Fatalf("valid %s provenance predicate was rejected", fixture.event)
		}
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

func TestReleaseArchiveExtractionRejectsTraversalAndSymlinks(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		typeflag byte
	}{
		{name: "../may", typeflag: tar.TypeReg},
		{name: "onenod/bin/may", typeflag: tar.TypeSymlink},
	} {
		archive := filepath.Join(t.TempDir(), "unsafe.tar.gz")
		writeTestArchive(t, archive, fixture.name, fixture.typeflag, []byte("binary"))
		err := extractReleaseArchive(archive, t.TempDir(), map[string]os.FileMode{
			"onenod/bin/may": 0o700,
		})
		if err == nil {
			t.Fatalf("unsafe archive entry %q was accepted", fixture.name)
		}
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
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), userAgentDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("update check mutated local installation state")
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
