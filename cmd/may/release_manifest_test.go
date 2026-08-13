package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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
			value.Components.KeychainHelper.HelperProtocol = protocolRange{Minimum: 4, Maximum: 4}
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

func TestReleaseManifestMayRequireAnExactPrereleaseBridgeUpdater(t *testing.T) {
	manifest, assets := canonicalManifestFixture("0.0.2-alpha.27")
	manifest.Upgrade.MinimumUpdaterVersion = "0.0.2-alpha.26"
	if err := validateReleaseManifest(
		manifest, "v0.0.2-alpha.27", assets,
	); err != nil {
		t.Fatalf("exact prerelease bridge updater was rejected: %v", err)
	}

	commit := manifest.Source.Commit
	oldVersion, oldTag, oldSource := productVersion, releaseTag, sourceCommit
	t.Cleanup(func() { productVersion, releaseTag, sourceCommit = oldVersion, oldTag, oldSource })
	productVersion, releaseTag, sourceCommit =
		"0.0.2-alpha.25", "v0.0.2-alpha.25", strings.Repeat("b", 40)
	if _, err := runningReleaseCanConsume(manifest); err == nil ||
		!strings.Contains(err.Error(), "below minimum_updater_version") {
		t.Fatalf("pre-bridge updater was not rejected: %v", err)
	}
	productVersion, releaseTag, sourceCommit =
		"0.0.2-alpha.26", "v0.0.2-alpha.26", commit
	if exact, err := runningReleaseCanConsume(manifest); err != nil || exact {
		t.Fatalf("declared bridge updater was rejected: exact=%t error=%v", exact, err)
	}
}

func TestReleaseManifestRequiresExactAdHocHardenedRuntimeIdentity(t *testing.T) {
	manifest, assets := canonicalManifestFixture("0.0.2")
	if err := validateReleaseManifest(manifest, "v0.0.2", assets); err != nil {
		t.Fatalf("valid exact-build identities rejected: %v", err)
	}
	for name, mutate := range map[string]func(*releaseManifest){
		"may lacks Hardened Runtime": func(value *releaseManifest) {
			value.Components.May.CodeIdentity.HardenedRuntime = false
		},
		"may uses a movable signer identity": func(value *releaseManifest) {
			value.Components.May.CodeIdentity.Signing = "developer-id"
		},
		"helper identifier drifts": func(value *releaseManifest) {
			value.Components.KeychainHelper.CodeIdentity.Identifier = "com.example.helper"
		},
		"adapter identity omitted": func(value *releaseManifest) {
			value.Components.May.AdapterCodeIdentity = exactBuildCodeIdentity{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := manifest
			mutate(&changed)
			if err := validateReleaseManifest(changed, "v0.0.2", assets); err == nil {
				t.Fatal("invalid exact-build identity was accepted")
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
