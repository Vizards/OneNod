package main

// Shared fixtures for the release capability tests.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type memoryReleaseSource struct {
	release          *verifiedRelease
	downloads        map[string][]byte
	requested        releaseChannel
	requestedVersion string
}

func testExactBuildRuntimeIdentity() exactBuildRuntimeIdentity {
	return testExactBuildRuntimeIdentityForArchitecture(runtime.GOARCH)
}

func testExactBuildRuntimeIdentityForArchitecture(architecture string) exactBuildRuntimeIdentity {
	return exactBuildRuntimeIdentity{
		Architecture:                    architecture,
		CodeDirectoryHash:               base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 20)),
		DesignatedRequirementDataSHA256: "sha256:" + strings.Repeat("4", 64),
	}
}

func writeTestLocalInstallReceipt(
	t *testing.T,
	home, origin, version string,
) localInstallReceipt {
	t.Helper()
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	localName, err := localArtifactName()
	if err != nil {
		t.Fatal(err)
	}
	helperName, err := helperArtifactName("3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	receipt := localInstallReceipt{
		Artifacts: map[string]string{
			localName: digest, helperName: digest, skillArtifactName(version): digest,
		},
		Channel: string(releaseChannelForVersion(version)),
		Files: map[string]string{
			"bin/may": digest, "bin/" + gitSignAdapterBinaryName: digest,
		},
		Origin: origin, ReleaseVersion: version, SourceCommit: strings.Repeat("b", 40),
	}
	receipt.Helper.Artifact = helperName
	receipt.Helper.ArtifactSHA = digest
	receipt.Helper.BinarySHA256 = digest
	receipt.Helper.Protocol = keychainHelperProtocol
	receipt.Helper.SourceDigest = digest
	receipt.Helper.Version = "3.0.0"
	receipt.ExactCodeIdentities.May = testExactBuildRuntimeIdentity()
	receipt.ExactCodeIdentities.MaySSHSign = testExactBuildRuntimeIdentity()
	receipt.ExactCodeIdentities.Helper = testExactBuildRuntimeIdentity()
	receipt.Skill.Artifact = skillArtifactName(version)
	receipt.Skill.ArtifactSHA = digest
	receipt.Skill.Discovery = []string{"~/.agents/skills/onenod", "~/.claude/skills/onenod"}
	receipt.Skill.TreeSHA256 = digest
	receipt.Skill.Version = version
	if err := writeLocalInstallReceipt(filepath.Join(root, "install.json"), receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
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
) ([]byte, error) {
	value, ok := source.downloads[artifact.Name]
	if !ok {
		return nil, errors.New("missing download")
	}
	digest := sha256.Sum256(value)
	if int64(len(value)) != artifact.Size ||
		"sha256:"+hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return nil, errors.New("fixture digest mismatch")
	}
	return append([]byte(nil), value...), nil
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
	manifest.Components.May.CodeIdentity = exactBuildCodeIdentity{
		HardenedRuntime: true,
		Identifier:      "com.github.vizards.onenod.may",
		Scheme:          "apple-cdhash",
		Signing:         "adhoc",
	}
	manifest.Components.May.AdapterCodeIdentity = exactBuildCodeIdentity{
		HardenedRuntime: true,
		Identifier:      "com.github.vizards.onenod.may-ssh-sign",
		Scheme:          "apple-cdhash",
		Signing:         "adhoc",
	}
	manifest.Components.SSHAgent.Version = version
	manifest.Components.Gateway.Version = version
	manifest.Components.Gateway.AcceptedClientProtocol = protocolRange{Minimum: 1, Maximum: 2}
	manifest.Components.Gateway.StateSchema = 2
	manifest.Components.Executor.Version = version
	manifest.Components.Executor.AcceptedGatewayProtocol = protocolRange{Minimum: 1, Maximum: 1}
	manifest.Components.Executor.StateSchema = 1
	manifest.Components.PWA.Version = version
	manifest.Components.Skill.Version = version
	manifest.Components.KeychainHelper.Version = "1.0.0"
	manifest.Components.KeychainHelper.CodeIdentity = exactBuildCodeIdentity{
		HardenedRuntime: true,
		Identifier:      "com.github.vizards.onenod.keychain-helper",
		Scheme:          "apple-cdhash",
		Signing:         "adhoc",
	}
	manifest.Components.KeychainHelper.SourceDigest = "sha256:" + strings.Repeat("b", 64)
	manifest.Components.KeychainHelper.HelperProtocol = protocolRange{Minimum: 3, Maximum: 3}
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
	manifest.Upgrade.RemoteRollbackSafe = false
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
