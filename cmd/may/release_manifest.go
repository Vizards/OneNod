package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/semver"
)

func validateReleaseManifest(
	manifest releaseManifest,
	tag string,
	assets map[string]releaseAsset,
) error {
	expectedChannel := releaseChannelForVersion(manifest.ReleaseVersion)
	if manifest.SchemaVersion != manifestSchema || !validReleaseChannel(expectedChannel) ||
		manifest.Channel != string(expectedChannel) ||
		!validProductLabel(manifest.ProductLabel) ||
		manifest.Tag != tag || tag != "v"+manifest.ReleaseVersion ||
		!validProductVersion(manifest.ReleaseVersion) || manifest.Source.Repository != officialRepository ||
		manifest.Source.Workflow != officialReleaseWorkflow ||
		!commitPattern.MatchString(manifest.Source.Commit) || !manifest.Support.LatestOnly {
		return errors.New("release manifest does not match the official immutable release identity")
	}
	if manifest.Attestations.Issuer != "https://token.actions.githubusercontent.com" ||
		manifest.Attestations.Repository != officialRepository ||
		manifest.Attestations.Workflow != officialReleaseWorkflow {
		return errors.New("release manifest attestation identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, manifest.PublishedAt); err != nil {
		return errors.New("release manifest published_at is invalid")
	}
	componentVersions := []string{
		manifest.Components.May.Version,
		manifest.Components.SSHAgent.Version,
		manifest.Components.Gateway.Version,
		manifest.Components.Executor.Version,
		manifest.Components.PWA.Version,
		manifest.Components.Skill.Version,
	}
	for _, version := range componentVersions {
		if version != manifest.ReleaseVersion {
			return errors.New("release manifest product component versions are not atomic")
		}
	}
	if manifest.Components.May.ClientProtocol <= 0 ||
		!validExactBuildCodeIdentity(
			manifest.Components.May.CodeIdentity,
			"com.github.vizards.onenod.may",
		) ||
		!validExactBuildCodeIdentity(
			manifest.Components.May.AdapterCodeIdentity,
			"com.github.vizards.onenod.may-ssh-sign",
		) ||
		!protocolContains(manifest.Components.Gateway.AcceptedClientProtocol, manifest.Components.May.ClientProtocol) ||
		manifest.Components.Gateway.StateSchema <= 0 || manifest.Components.Executor.StateSchema <= 0 ||
		manifest.Components.KeychainHelper.Version == "" ||
		!validExactBuildCodeIdentity(
			manifest.Components.KeychainHelper.CodeIdentity,
			"com.github.vizards.onenod.keychain-helper",
		) ||
		!digestPattern.MatchString(manifest.Components.KeychainHelper.SourceDigest) ||
		manifest.Components.KeychainHelper.HelperProtocol.Minimum <= 0 ||
		manifest.Components.KeychainHelper.HelperProtocol.Maximum < manifest.Components.KeychainHelper.HelperProtocol.Minimum {
		return errors.New("release manifest compatibility fields are incomplete")
	}
	if !validStableVersion(manifest.Support.MinimumSafeVersion) ||
		compareProductVersions(manifest.Support.MinimumSafeVersion, manifest.ReleaseVersion) > 0 ||
		!validStableVersion(manifest.Upgrade.MinimumUpdaterVersion) ||
		compareProductVersions(manifest.Upgrade.MinimumUpdaterVersion, manifest.ReleaseVersion) > 0 {
		return errors.New("release manifest update safety versions are invalid")
	}
	if manifest.Support.PreviousReleaseVersion != "" &&
		(!validProductVersion(manifest.Support.PreviousReleaseVersion) ||
			compareProductVersions(manifest.Support.PreviousReleaseVersion, manifest.ReleaseVersion) >= 0) {
		return errors.New("release manifest previous release compatibility is invalid")
	}
	if manifest.ReleaseVersion != "0.0.1" && manifest.Support.PreviousReleaseVersion == "" {
		return errors.New("release manifest does not declare N/N-1 compatibility")
	}
	if len(manifest.Upgrade.Order) != 4 ||
		strings.Join(manifest.Upgrade.Order, ",") != "executor,gateway,local,skill" {
		return errors.New("release manifest has an unsupported deployment order")
	}
	if err := validateVersionRange(manifest.Requirements.Wrangler); err != nil {
		return errors.New("release manifest Wrangler requirement is invalid")
	}
	if err := validateVersionRange(manifest.Requirements.OnePasswordCLI); err != nil {
		return errors.New("release manifest 1Password CLI requirement is invalid")
	}
	if err := validateVersionRange(manifest.Requirements.Node); err != nil {
		return errors.New("release manifest Node.js requirement is invalid")
	}
	if manifest.Requirements.MacOS.Minimum != "15.0" ||
		strings.Join(manifest.Requirements.MacOS.Architectures, ",") != "arm64,amd64" ||
		strings.Join(manifest.Requirements.OnePasswordRegions, ",") != "com,ca,eu" {
		return errors.New("release manifest platform or 1Password region support is invalid")
	}
	if manifest.Upgrade.MinimumSafeVersion != manifest.Support.MinimumSafeVersion ||
		strings.Join(manifest.Upgrade.RevokedArtifactDigests, "\n") !=
			strings.Join(manifest.RevokedArtifactDigests, "\n") {
		return errors.New("release manifest duplicated support policy fields disagree")
	}
	revoked := map[string]struct{}{}
	for _, digest := range manifest.RevokedArtifactDigests {
		if !digestPattern.MatchString(digest) {
			return errors.New("release manifest contains an invalid revoked artifact digest")
		}
		revoked[digest] = struct{}{}
	}
	expectedArtifacts := expectedReleaseArtifactContract(manifest)
	if len(manifest.Artifacts) != len(expectedArtifacts) {
		return errors.New("release manifest does not contain the exact canonical artifact set")
	}
	seen := map[string]struct{}{}
	for _, artifact := range manifest.Artifacts {
		asset, ok := assets[artifact.Name]
		if !ok || asset.Size != artifact.Size || artifact.Size <= 0 ||
			artifact.Size > maxReleaseArtifactBytes || !digestPattern.MatchString(artifact.SHA256) {
			return fmt.Errorf("release artifact %q does not match immutable asset metadata", artifact.Name)
		}
		if _, duplicate := seen[artifact.Name]; duplicate {
			return errors.New("release manifest contains duplicate artifacts")
		}
		expected, expectedName := expectedArtifacts[artifact.Name]
		if !expectedName || !artifactMatchesContract(artifact, expected) {
			return fmt.Errorf("release artifact %q has an invalid kind or platform", artifact.Name)
		}
		seen[artifact.Name] = struct{}{}
		if _, isRevoked := revoked[artifact.SHA256]; isRevoked {
			return fmt.Errorf("release artifact %q is explicitly revoked", artifact.Name)
		}
	}
	if len(seen) != len(expectedArtifacts) {
		return errors.New("release manifest artifact inventory is incomplete")
	}
	expectedAssets := map[string]struct{}{
		releaseManifestAssetName:  {},
		provenanceBundleAssetName: {},
		"SHA256SUMS":              {},
	}
	for name := range expectedArtifacts {
		expectedAssets[name] = struct{}{}
	}
	if len(assets) != len(expectedAssets) {
		return errors.New("immutable OneNod Release does not contain the exact canonical asset set")
	}
	for name := range expectedAssets {
		asset, found := assets[name]
		if !found || asset.Size <= 0 {
			return fmt.Errorf("immutable OneNod Release is missing canonical asset %q", name)
		}
	}
	return nil
}

func validExactBuildCodeIdentity(identity exactBuildCodeIdentity, expectedIdentifier string) bool {
	return identity.Scheme == "apple-cdhash" && identity.Signing == "adhoc" &&
		identity.Identifier == expectedIdentifier && identity.HardenedRuntime
}

func validExactBuildRuntimeIdentity(identity exactBuildRuntimeIdentity) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(identity.CodeDirectoryHash)
	valid := err == nil && len(decoded) >= 20 && len(decoded) <= 64 &&
		identity.Architecture == runtime.GOARCH &&
		digestPattern.MatchString(identity.DesignatedRequirementDataSHA256)
	zeroBytes(decoded)
	return valid
}

func expectedReleaseArtifactContract(manifest releaseManifest) map[string]releaseArtifactContract {
	version := manifest.ReleaseVersion
	helperVersion := manifest.Components.KeychainHelper.Version
	archives := []string{
		"onenod-darwin-arm64.tar.gz",
		"onenod-darwin-amd64.tar.gz",
		fmt.Sprintf("onenod-deployment-%s.tar.gz", version),
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-arm64.tar.gz", helperVersion),
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-amd64.tar.gz", helperVersion),
		fmt.Sprintf("onenod-skill-%s.tar.gz", version),
	}
	contract := map[string]releaseArtifactContract{
		"onenod-darwin-arm64.tar.gz": {Kind: "local", OS: "darwin", Architecture: "arm64"},
		"onenod-darwin-amd64.tar.gz": {Kind: "local", OS: "darwin", Architecture: "amd64"},
		fmt.Sprintf("onenod-deployment-%s.tar.gz", version): {
			Kind: "deployment",
		},
		fmt.Sprintf("onenod-skill-%s.tar.gz", version): {
			Kind: "skill",
		},
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-arm64.tar.gz", helperVersion): {
			Kind: "keychain_helper", OS: "darwin", Architecture: "arm64",
		},
		fmt.Sprintf("onenod-keychain-helper-%s-darwin-amd64.tar.gz", helperVersion): {
			Kind: "keychain_helper", OS: "darwin", Architecture: "amd64",
		},
		"THIRD_PARTY_NOTICES.txt": {Kind: "notices"},
	}
	for _, archive := range archives {
		contract[strings.TrimSuffix(archive, ".tar.gz")+".spdx.json"] =
			releaseArtifactContract{Kind: "sbom", Subject: archive}
	}
	return contract
}

func artifactMatchesContract(artifact releaseArtifact, expected releaseArtifactContract) bool {
	if artifact.Kind != expected.Kind || artifact.Subject != expected.Subject {
		return false
	}
	if expected.OS == "" {
		return artifact.Platform == nil
	}
	return artifact.Platform != nil && artifact.Platform.OS == expected.OS &&
		artifact.Platform.Architecture == expected.Architecture
}

func validReleaseTag(value string) bool {
	return strings.HasPrefix(value, "v") && validProductVersion(strings.TrimPrefix(value, "v"))
}

func validStableVersion(value string) bool { return semverPattern.MatchString(value) }

func validProductVersion(value string) bool {
	match := productSemverPattern.FindStringSubmatch(value)
	if match == nil || !semver.IsValid("v"+value) {
		return false
	}
	for _, component := range []string{match[1], match[2], match[3], match[5]} {
		if component == "" {
			continue
		}
		parsed, err := strconv.ParseUint(component, 10, 64)
		if err != nil || parsed > maxSafeVersionInteger {
			return false
		}
	}
	return true
}

func releaseChannelForVersion(value string) releaseChannel {
	match := productSemverPattern.FindStringSubmatch(value)
	if match == nil {
		return ""
	}
	switch match[4] {
	case "alpha":
		return releaseChannelAlpha
	case "beta":
		return releaseChannelBeta
	default:
		return releaseChannelStable
	}
}

func validProductLabel(value string) bool {
	if value == "" || len(value) > 64 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func parseReleaseChannel(value string) (releaseChannel, error) {
	channel := releaseChannel(strings.TrimSpace(value))
	if !validReleaseChannel(channel) {
		return "", errors.New("release channel must be stable, beta, or alpha")
	}
	return channel, nil
}

func releaseChannelFromFlag(value string, fallback releaseChannel) (releaseChannel, error) {
	if value == "" {
		if validReleaseChannel(fallback) {
			return fallback, nil
		}
		return releaseChannelStable, nil
	}
	return parseReleaseChannel(value)
}

func releaseSelectionFromFlags(
	channelValue string,
	versionValue string,
	fallback releaseChannel,
) (releaseSelection, error) {
	if err := validateExplicitReleaseSelection(channelValue, versionValue); err != nil {
		return releaseSelection{}, err
	}
	if versionValue != "" {
		return releaseSelection{
			Channel: releaseChannelForVersion(versionValue),
			Version: versionValue,
		}, nil
	}
	channel, err := releaseChannelFromFlag(channelValue, fallback)
	if err != nil {
		return releaseSelection{}, err
	}
	return releaseSelection{Channel: channel}, nil
}

func validateExplicitReleaseSelection(channelValue string, versionValue string) error {
	if channelValue != "" && versionValue != "" {
		return errors.New(
			"--channel and --version are mutually exclusive; an exact version determines its release channel",
		)
	}
	if versionValue != "" {
		if strings.TrimSpace(versionValue) != versionValue || !validProductVersion(versionValue) {
			return errors.New(
				"release version must be a canonical X.Y.Z, X.Y.Z-alpha.N, or X.Y.Z-beta.N version without a v prefix",
			)
		}
	}
	if channelValue != "" {
		if _, err := parseReleaseChannel(channelValue); err != nil {
			return err
		}
	}
	return nil
}

func resolveSelectedRelease(
	ctx context.Context,
	source releaseSource,
	selection releaseSelection,
) (*verifiedRelease, error) {
	if selection.Version != "" {
		return source.Exact(ctx, selection.Version)
	}
	return source.Latest(ctx, selection.Channel)
}

func releaseSelectionArguments(selection releaseSelection) []string {
	if selection.Version != "" {
		return []string{"--version", selection.Version}
	}
	return []string{"--channel", string(selection.Channel)}
}

func confirmHigherRiskChannel(
	input io.Reader,
	output io.Writer,
	current releaseChannel,
	selected releaseChannel,
	action string,
) error {
	if releaseChannelRisk(selected) <= releaseChannelRisk(current) {
		return nil
	}
	fmt.Fprintf(output,
		"\nPRERELEASE CHANNEL OPT-IN\n  Current channel: %s\n  Requested channel: %s\n  %s will accept %s prereleases and all safer channels.\n",
		current, selected, action, selected,
	)
	confirmed, err := promptYesNo(input, output, "Continue with this higher-risk release channel?", false)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("higher-risk release channel was not approved; no changes were made")
	}
	return nil
}

func validReleaseChannel(channel releaseChannel) bool {
	return channel == releaseChannelStable || channel == releaseChannelBeta || channel == releaseChannelAlpha
}

func releaseChannelRisk(channel releaseChannel) int {
	switch channel {
	case releaseChannelStable:
		return 0
	case releaseChannelBeta:
		return 1
	case releaseChannelAlpha:
		return 2
	default:
		return -1
	}
}

func releaseChannelAccepts(selected, candidate releaseChannel) bool {
	return validReleaseChannel(selected) && validReleaseChannel(candidate) &&
		releaseChannelRisk(candidate) <= releaseChannelRisk(selected)
}

func awaitingCompatibleRelease(
	currentVersion string,
	currentChannel releaseChannel,
	candidateVersion string,
	selectedChannel releaseChannel,
) bool {
	return validProductVersion(currentVersion) && validProductVersion(candidateVersion) &&
		validReleaseChannel(currentChannel) && validReleaseChannel(selectedChannel) &&
		releaseChannelRisk(selectedChannel) < releaseChannelRisk(currentChannel) &&
		compareProductVersions(candidateVersion, currentVersion) < 0
}

func writeAwaitingCompatibleRelease(
	output io.Writer,
	currentVersion string,
	currentChannel releaseChannel,
	candidateVersion string,
	selectedChannel releaseChannel,
) {
	fmt.Fprintf(output,
		"OneNod update status: awaiting_compatible_release\n  current: %s (channel %s)\n  latest acceptable %s release: %s\n  no receipt or runtime state was changed; retry after %s publishes a release at or above %s.\n",
		currentVersion, currentChannel, selectedChannel, candidateVersion,
		selectedChannel, currentVersion,
	)
}

func compareProductVersions(first, second string) int {
	if !validProductVersion(first) || !validProductVersion(second) {
		return strings.Compare(first, second)
	}
	return semver.Compare("v"+first, "v"+second)
}

func selectedReleaseChannel(release *verifiedRelease) releaseChannel {
	if release != nil && validReleaseChannel(release.SelectedChannel) {
		return release.SelectedChannel
	}
	return releaseChannelStable
}

func normalizedReceiptChannel(value string, version string) (releaseChannel, error) {
	if value == "" {
		value = string(releaseChannelStable)
	}
	channel, err := parseReleaseChannel(value)
	if err != nil || !validProductVersion(version) ||
		!releaseChannelAccepts(channel, releaseChannelForVersion(version)) {
		return "", errors.New("receipt release channel is invalid")
	}
	return channel, nil
}

func compareVersions(first, second string) int {
	left := semverPattern.FindStringSubmatch(first)
	right := semverPattern.FindStringSubmatch(second)
	if left == nil || right == nil {
		return strings.Compare(first, second)
	}
	for index := 1; index <= 3; index++ {
		a, _ := strconv.ParseUint(left[index], 10, 64)
		b, _ := strconv.ParseUint(right[index], 10, 64)
		if a < b {
			return -1
		}
		if a > b {
			return 1
		}
	}
	return 0
}

func validateVersionRange(requirement versionRange) error {
	if !validStableVersion(requirement.Minimum) ||
		(requirement.MaximumExclusive != "" &&
			(!validStableVersion(requirement.MaximumExclusive) ||
				compareVersions(requirement.Minimum, requirement.MaximumExclusive) >= 0)) {
		return errors.New("invalid version range")
	}
	return nil
}

func protocolContains(accepted protocolRange, version int) bool {
	return accepted.Minimum > 0 && accepted.Maximum >= accepted.Minimum &&
		version >= accepted.Minimum && version <= accepted.Maximum
}

func runningReleaseCanConsume(manifest releaseManifest) (bool, error) {
	if !validProductVersion(productVersion) || releaseTag != "v"+productVersion ||
		!commitPattern.MatchString(sourceCommit) {
		return false, errors.New("unsupported_running_binary: use an immutable official OneNod Release binary")
	}
	if !protocolContains(manifest.Components.KeychainHelper.HelperProtocol, keychainHelperProtocol) {
		return false, errors.New("unsupported_update_path: the running may Keychain-helper protocol is outside the latest Release contract")
	}
	if compareProductVersions(productVersion, manifest.Upgrade.MinimumUpdaterVersion) < 0 {
		return false, fmt.Errorf(
			"unsupported_update_path: running may %s is below minimum_updater_version %s; install a supported official bridge or latest Release binary manually",
			productVersion, manifest.Upgrade.MinimumUpdaterVersion,
		)
	}
	comparison := compareProductVersions(productVersion, manifest.ReleaseVersion)
	if comparison > 0 {
		return false, fmt.Errorf(
			"anti_rollback: running may %s is newer than latest official Release %s",
			productVersion, manifest.ReleaseVersion,
		)
	}
	if comparison == 0 {
		if sourceCommit != manifest.Source.Commit {
			return false, errors.New("same_version_identity_mismatch: running may source commit differs from the signed Release")
		}
		return true, nil
	}
	return false, nil
}
