package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func runVersion(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may version [--json]")
	}
	runtimeChannel := releaseChannelForVersion(productVersion)
	runtimeChannelText := string(runtimeChannel)
	if !validReleaseChannel(runtimeChannel) {
		runtimeChannelText = "development"
	}
	selectedChannel := runtimeChannelText
	value := map[string]any{
		"channel": selectedChannel, "release_channel": runtimeChannelText,
		"client_protocol": mayClientProtocol,
		"release_tag":     releaseTag, "repository": officialRepository,
		"source_commit": sourceCommit, "supported_release": validProductVersion(productVersion),
		"version": productVersion,
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if found {
		selectedChannel = receipt.Channel
		value["channel"] = selectedChannel
		value["installed_release"] = receipt.ReleaseVersion
		value["origin"] = receipt.Origin
		value["components"] = map[string]any{
			"may":              map[string]any{"sha256": receipt.Files["bin/may"]},
			"ssh_sign_adapter": map[string]any{"sha256": receipt.Files["bin/"+gitSignAdapterBinaryName]},
			"skill": map[string]any{
				"version": receipt.Skill.Version, "tree_sha256": receipt.Skill.TreeSHA256,
				"discovery": receipt.Skill.Discovery,
			},
		}
	} else if initializer, initializerFound, initializerErr := readInitializerInstallReceipt(); initializerErr != nil {
		return initializerErr
	} else if initializerFound {
		selectedChannel = initializer.Channel
		value["channel"] = selectedChannel
		value["initializer_install"] = map[string]any{
			"release_version": initializer.ReleaseVersion,
			"source_commit":   initializer.SourceCommit,
			"components": map[string]any{
				"may":              map[string]any{"sha256": initializer.Files["bin/may"]},
				"ssh_sign_adapter": map[string]any{"sha256": initializer.Files["bin/"+gitSignAdapterBinaryName]},
				"skill":            map[string]any{"tree_sha256": initializer.SkillTreeSHA},
			},
		}
	}
	if helper, err := inspectInstalledKeychainHelper(); err == nil {
		value["keychain_helper"] = map[string]any{
			"protocol": helper.Protocol, "version": helper.Version,
		}
	}
	if running, err := queryRunningAgentVersion(defaultAgentSocket()); err == nil {
		value["running_ssh_agent"] = map[string]any{
			"running": true, "version": running.Version,
			"source_commit": running.SourceCommit, "client_protocol": running.ClientProtocol,
		}
	} else {
		value["running_ssh_agent"] = map[string]any{"running": false, "status": "unavailable_or_incompatible"}
	}
	if *jsonOutput {
		return writeIndentedValue(deps.stdout, value)
	}
	fmt.Fprintf(deps.stdout, "may %s\n", productVersion)
	fmt.Fprintf(deps.stdout, "channel %s (release %s)\n", selectedChannel, runtimeChannelText)
	fmt.Fprintf(deps.stdout, "repository %s\n", officialRepository)
	if !validProductVersion(productVersion) {
		fmt.Fprintln(deps.stdout, "support unsupported development build (main is not a release channel)")
	}
	return nil
}

func runDevVerifyRelease(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("dev verify-release", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	directory := flags.String("directory", "", "release-set directory")
	var selectedArtifacts repeatedStringFlag
	flags.Var(&selectedArtifacts, "artifact", "declared artifact basename to verify (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*directory) == "" {
		return errors.New("usage: may dev verify-release --directory <dist/release> [--artifact <basename>]...")
	}
	if err := requireOfficialRepositoryID(); err != nil {
		return err
	}
	rootPath, err := filepath.Abs(*directory)
	if err != nil {
		return errors.New("resolve release verification directory failed")
	}
	info, err := os.Lstat(rootPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("release verification directory is unsafe or unavailable")
	}
	manifestPath := filepath.Join(rootPath, releaseManifestAssetName)
	manifestBytes, err := readBoundedRegularFile(manifestPath, maxManifestBytes)
	if err != nil {
		return fmt.Errorf("read release manifest: %w", err)
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("release manifest is invalid")
	}
	// The developer verifier intentionally supports a selected-artifact subset
	// (used to reuse the prior immutable helper). Build a virtual view of the
	// complete canonical Release from the signed manifest, then verify every
	// selected local byte stream below. Only the GitHub resolver is responsible
	// for proving that the remote Release itself exposes this exact asset set.
	assets := make(map[string]releaseAsset, len(manifest.Artifacts)+3)
	assets[releaseManifestAssetName] = releaseAsset{
		Name: releaseManifestAssetName, Size: int64(len(manifestBytes)),
	}
	assets[provenanceBundleAssetName] = releaseAsset{Name: provenanceBundleAssetName, Size: 1}
	assets["SHA256SUMS"] = releaseAsset{Name: "SHA256SUMS", Size: 1}
	declared := make(map[string]releaseArtifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		if filepath.Base(artifact.Name) != artifact.Name {
			return fmt.Errorf("release artifact name %q is not a basename", artifact.Name)
		}
		assets[artifact.Name] = releaseAsset{Name: artifact.Name, Size: artifact.Size}
		declared[artifact.Name] = artifact
	}
	toVerify := append([]string(nil), selectedArtifacts...)
	if len(toVerify) == 0 {
		toVerify = sortedArtifactNames(manifest)
	}
	seenSelected := map[string]struct{}{}
	for _, name := range toVerify {
		if filepath.Base(name) != name {
			return fmt.Errorf("selected artifact %q is not a basename", name)
		}
		artifact, ok := declared[name]
		if !ok {
			return fmt.Errorf("selected artifact %q is not declared by the signed manifest", name)
		}
		if _, duplicate := seenSelected[name]; duplicate {
			return fmt.Errorf("selected artifact %q was repeated", name)
		}
		seenSelected[name] = struct{}{}
		path := filepath.Join(rootPath, name)
		value, err := readBoundedRegularFile(path, maxReleaseArtifactBytes)
		if err != nil {
			return fmt.Errorf("read release artifact %q: %w", artifact.Name, err)
		}
		digest := sha256.Sum256(value)
		if int64(len(value)) != artifact.Size ||
			"sha256:"+hex.EncodeToString(digest[:]) != artifact.SHA256 {
			return fmt.Errorf("release artifact %q does not match its manifest entry", artifact.Name)
		}
		if err := verifyReleaseArtifactInstallability(manifest, artifact, value); err != nil {
			return fmt.Errorf("release artifact %q cannot be consumed by may: %w", artifact.Name, err)
		}
	}
	if err := validateReleaseManifest(manifest, manifest.Tag, assets); err != nil {
		return err
	}
	provenanceBytes, err := readBoundedRegularFile(
		filepath.Join(rootPath, provenanceBundleAssetName), maxAttestationBytes,
	)
	if err != nil {
		return fmt.Errorf("read release provenance: %w", err)
	}
	bundles, err := parseProvenanceBundles(provenanceBytes)
	if err != nil {
		return err
	}
	release := &verifiedRelease{
		Assets: assets, Manifest: manifest, ProvenanceBundles: bundles,
		RepositoryID: officialRepositoryID, Tag: manifest.Tag,
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	source := &githubReleaseSource{}
	if err := source.verifyArtifactAttestation(
		context.Background(), release, releaseManifestAssetName,
		manifestDigest[:], manifest.Source.Commit,
	); err != nil {
		return fmt.Errorf("verify release manifest provenance: %w", err)
	}
	fmt.Fprintf(deps.stdout, "Verified OneNod %s release manifest, provenance, and %d selected artifacts.\n",
		manifest.ReleaseVersion, len(toVerify))
	return nil
}

func verifyReleaseArtifactInstallability(
	manifest releaseManifest,
	artifact releaseArtifact,
	snapshot []byte,
) error {
	if artifact.Kind != "local" && artifact.Kind != "keychain_helper" &&
		artifact.Kind != "deployment" && artifact.Kind != "skill" {
		return nil
	}
	destination, err := os.MkdirTemp("", "onenod-release-contract-")
	if err != nil {
		return errors.New("create release contract verification directory failed")
	}
	defer os.RemoveAll(destination)
	switch artifact.Kind {
	case "local":
		expectedArchitecture, err := releaseArtifactDarwinArchitecture(artifact)
		if err != nil {
			return err
		}
		_, err = extractVerifiedLocalArchiveForArchitecture(
			snapshot, destination, manifest, expectedArchitecture,
		)
		return err
	case "keychain_helper":
		expectedArchitecture, err := releaseArtifactDarwinArchitecture(artifact)
		if err != nil {
			return err
		}
		_, err = extractVerifiedHelperArchiveForArchitecture(
			snapshot, destination, manifest, expectedArchitecture,
		)
		return err
	case "deployment":
		var descriptor deploymentBundleDescriptor
		if err := decodeAuthenticatedArchiveJSON(
			snapshot, "onenod-deployment/deployment.json", &descriptor,
		); err != nil {
			return err
		}
		var releaseFile deploymentReleaseMetadata
		if err := decodeAuthenticatedArchiveJSON(
			snapshot, "onenod-deployment/RELEASE.json", &releaseFile,
		); err != nil {
			return err
		}
		if err := extractDeploymentBundleArchive(snapshot, destination); err != nil {
			return err
		}
		return validateStagedDeploymentBundle(
			filepath.Join(destination, "onenod-deployment"), manifest,
			descriptor, releaseFile,
		)
	case "skill":
		return extractSkillArchive(snapshot, destination)
	default:
		return nil
	}
}

func releaseArtifactDarwinArchitecture(artifact releaseArtifact) (string, error) {
	if artifact.Platform == nil || artifact.Platform.OS != "darwin" ||
		(artifact.Platform.Architecture != "arm64" && artifact.Platform.Architecture != "amd64") {
		return "", errors.New("native release artifact platform is invalid")
	}
	return artifact.Platform.Architecture, nil
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string { return strings.Join(*values, ",") }

func (values *repeatedStringFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("artifact name cannot be empty")
	}
	*values = append(*values, value)
	return nil
}

func readBoundedRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("file is missing, unsafe, empty, or oversized")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open file failed")
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(value)) != info.Size() || int64(len(value)) > limit {
		return nil, errors.New("read bounded file failed")
	}
	return value, nil
}

func runUpdate(args []string, deps dependencies) error {
	if len(args) > 0 && args[0] == "check" {
		return runUpdateCheck(args[1:], deps)
	}
	return runLocalUpdate(args, deps)
}

func runUpdateCheck(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("update check", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may update check [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] [--json]")
	}
	fallback := releaseChannelStable
	if receipt, found, err := readLocalInstallReceipt(); err != nil {
		return err
	} else if found {
		fallback = releaseChannel(receipt.Channel)
	}
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, fallback)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), releaseRequestTimeout)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	report, err := buildUpdateCheckReport(release, deps)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeIndentedValue(deps.stdout, report)
	}
	writeHumanUpdateReport(deps.stdout, report)
	return nil
}

func buildUpdateCheckReport(release *verifiedRelease, deps dependencies) (updateCheckReport, error) {
	manifest := release.Manifest
	report := updateCheckReport{
		Assurance: "verified_release_and_runtime_self_report",
		Channel:   string(selectedReleaseChannel(release)), LatestVersion: manifest.ReleaseVersion,
		MinimumSafeVersion: manifest.Support.MinimumSafeVersion,
		Plan:               []string{}, RequestedVersion: release.RequestedVersion,
		Warnings: []string{},
	}
	platform, platformErr := currentHostPlatform(deps)
	report.Platform = platform
	if platformErr == nil {
		platformErr = validateReleaseHostPlatform(manifest, platform)
	}
	if platformErr != nil {
		report.Status = "unsupported_platform"
		report.Warnings = append(report.Warnings, platformErr.Error())
		report.Plan = append(report.Plan, "use a supported macOS host before installing or updating OneNod")
		return report, nil
	}
	receipt, installed, err := readLocalInstallReceipt()
	if err != nil {
		return report, err
	}
	if !installed {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "install the verified local OneNod release")
		return report, nil
	}
	report.CurrentVersion = receipt.ReleaseVersion
	report.CurrentChannel = receipt.Channel
	report.Origin = receipt.Origin
	if compareProductVersions(manifest.ReleaseVersion, receipt.ReleaseVersion) < 0 {
		if awaitingCompatibleRelease(
			receipt.ReleaseVersion, releaseChannel(receipt.Channel),
			manifest.ReleaseVersion, selectedReleaseChannel(release),
		) {
			report.Status = "awaiting_compatible_release"
			report.Plan = append(report.Plan, fmt.Sprintf(
				"wait for the %s channel to publish version %s or newer; do not change local or remote state",
				report.Channel, receipt.ReleaseVersion,
			))
			return report, nil
		}
		return report, fmt.Errorf(
			"anti_rollback: latest official release %s is older than installed release %s",
			manifest.ReleaseVersion, receipt.ReleaseVersion,
		)
	}
	if manifest.ReleaseVersion == receipt.ReleaseVersion {
		if err := validateReceiptReleaseIdentity(receipt, manifest); err != nil {
			return report, fmt.Errorf("same_version_identity_mismatch: %w", err)
		}
	}
	if err := validateInstalledReceiptState(receipt); err != nil {
		report.Status = "mixed_installation"
		report.Warnings = append(report.Warnings, err.Error())
		report.Plan = append(report.Plan, "reconcile this Mac from the verified release")
		return report, nil
	}
	for name, digest := range receipt.Artifacts {
		for _, revoked := range manifest.RevokedArtifactDigests {
			if digest == revoked {
				report.Status = "incompatible"
				report.Warnings = append(report.Warnings, "installed artifact is revoked: "+name)
				report.Plan = append(report.Plan, "replace the revoked local release immediately")
				return report, nil
			}
		}
	}
	if compareProductVersions(receipt.ReleaseVersion, manifest.Support.MinimumSafeVersion) < 0 {
		report.Warnings = append(report.Warnings, "installed release is below minimum_safe_version")
	}
	if compareProductVersions(productVersion, manifest.Upgrade.MinimumUpdaterVersion) < 0 &&
		validProductVersion(productVersion) {
		report.Status = "unsupported_update_path"
		report.Plan = append(report.Plan, "install a supported bridge updater before continuing")
		return report, nil
	}
	helper, helperErr := inspectInstalledKeychainHelper()
	if helperErr != nil {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "install the independently versioned Keychain helper")
		return report, nil
	}
	if !protocolContains(manifest.Components.KeychainHelper.HelperProtocol, helper.Protocol) {
		report.Status = "incompatible"
		report.Plan = append(report.Plan, "perform the explicit Keychain helper security-component update")
		return report, nil
	}
	if !helperMatchesRelease(release, receipt, helper) {
		report.Status = "mixed_installation"
		report.Plan = append(report.Plan, "reconcile the Keychain helper from the exact verified release")
		return report, nil
	}
	remote, complete := readRemoteRuntimeVersion(receipt.Origin, deps.httpClient)
	report.Remote = remote
	if !complete {
		report.Status = "check_incomplete"
		report.Warnings = append(report.Warnings, "Gateway does not expose complete release metadata")
	} else if remote.AcceptedClientProtocol.Minimum > 0 &&
		!protocolContains(remote.AcceptedClientProtocol, manifest.Components.May.ClientProtocol) {
		report.Status = "incompatible"
		report.Plan = append(report.Plan, "deploy a compatible Gateway before updating local clients")
		return report, nil
	}
	localCurrent := receipt.ReleaseVersion == manifest.ReleaseVersion &&
		receipt.Channel == string(selectedReleaseChannel(release))
	remoteCurrent := remote.GatewayVersion == manifest.ReleaseVersion &&
		remote.ExecutorVersion == manifest.ReleaseVersion && remote.PwaVersion == manifest.ReleaseVersion
	if localCurrent && remoteCurrent {
		report.Status = "up_to_date"
		return report, nil
	}
	if report.Status == "" || report.Status == "check_incomplete" {
		if !localCurrent {
			report.Plan = append(report.Plan,
				"update this Mac to "+manifest.ReleaseVersion+" on the "+report.Channel+" channel")
		}
		if complete && !remoteCurrent {
			report.Plan = append(report.Plan, "run may operator update from the operator Mac")
		}
		if len(report.Plan) > 0 && report.Status != "check_incomplete" {
			report.Status = "update_available"
		}
	}
	return report, nil
}

func validateInstalledReceiptState(receipt *localInstallReceipt) error {
	if receipt == nil {
		return errors.New("local install receipt is unavailable")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	versionRoot := filepath.Join(root, "versions", receipt.ReleaseVersion)
	for relative, digest := range receipt.Files {
		name := strings.TrimPrefix(relative, "bin/")
		actual, err := regularFileSHA256(filepath.Join(versionRoot, name), maxReleaseArtifactBytes)
		if err != nil || actual != digest {
			return fmt.Errorf("installed %s bytes differ from the receipt", relative)
		}
		stable := filepath.Join(root, relative)
		if err := stableSymlinkResolvesTo(stable, filepath.Join(versionRoot, name)); err != nil {
			return err
		}
	}
	running, err := queryRunningAgentVersion(filepath.Join(root, "agent.sock"))
	if err != nil || running.Version != receipt.ReleaseVersion || running.SourceCommit != receipt.SourceCommit ||
		running.ClientProtocol != mayClientProtocol {
		return errors.New("running SSH Agent identity differs from the installed release receipt")
	}
	helper, err := inspectInstalledKeychainHelper()
	if err != nil || !installedHelperMatchesReceipt(receipt, helper) {
		return errors.New("installed Keychain helper identity differs from the receipt")
	}
	skillRoot := filepath.Join(root, "skill-versions", receipt.Skill.Version, "onenod")
	digest, err := directoryTreeSHA256(skillRoot)
	if err != nil || digest != receipt.Skill.TreeSHA256 {
		return errors.New("installed managed Skill bytes differ from the receipt")
	}
	if err := stableSymlinkResolvesTo(filepath.Join(root, "skill"), skillRoot); err != nil {
		return err
	}
	for _, relative := range receipt.Skill.Discovery {
		path := filepath.Join(home, strings.TrimPrefix(relative, "~/"))
		if err := stableSymlinkResolvesTo(path, filepath.Join(root, "skill")); err != nil {
			return err
		}
	}
	return nil
}

func stableSymlinkResolvesTo(path, expected string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("managed stable path %s is missing or not a symlink", path)
	}
	target, err := os.Readlink(path)
	if err != nil {
		return errors.New("read managed stable symlink failed")
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(path), target))
	if resolved != filepath.Clean(expected) {
		return fmt.Errorf("managed stable path %s resolves outside its recorded version", path)
	}
	return nil
}

func validateReceiptReleaseIdentity(receipt *localInstallReceipt, manifest releaseManifest) error {
	if receipt == nil || receipt.SourceCommit != manifest.Source.Commit {
		return errors.New("installed source commit differs from the signed release manifest")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil || !releaseChannelAccepts(channel, releaseChannel(manifest.Channel)) {
		return errors.New("installed release channel does not accept the signed release manifest")
	}
	if len(receipt.Artifacts) == 0 {
		return errors.New("installed receipt contains no artifact digests")
	}
	manifestDigests := make(map[string]string, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		manifestDigests[artifact.Name] = artifact.SHA256
	}
	for name, digest := range receipt.Artifacts {
		if manifestDigests[name] != digest {
			return fmt.Errorf("installed artifact %q differs from the signed release manifest", name)
		}
	}
	return nil
}

func readRemoteRuntimeVersion(origin string, client *http.Client) (runtimeVersion, bool) {
	var response remoteRuntimeVersionResponse
	if err := readPublicGatewayJSON(safePublicHTTPClient(client), origin, "/api/version", &response); err == nil {
		return parseRemoteRuntimeVersion(response)
	}
	return runtimeVersion{}, false
}

func requireRemoteGatewayCompatibility(
	origin string,
	clientProtocol int,
	client *http.Client,
) error {
	remote, complete := readRemoteRuntimeVersion(origin, client)
	if !complete {
		return errors.New("local update blocked: the Gateway release and accepted client protocol could not be verified; deploy or repair the Gateway from the operator Mac first")
	}
	if !protocolContains(remote.AcceptedClientProtocol, clientProtocol) {
		return errors.New("local update blocked: deploy a Gateway that accepts the target may client protocol from the operator Mac first")
	}
	return nil
}

func parseRemoteRuntimeVersion(response remoteRuntimeVersionResponse) (runtimeVersion, bool) {
	expectedChannel := releaseChannelForVersion(response.ReleaseVersion)
	remote := runtimeVersion{
		AcceptedClientProtocol: response.Components.Gateway.AcceptedClientProtocol,
		Channel:                response.ReleaseChannel,
		ExecutorVersion:        response.Components.Executor.Version,
		GatewayProtocol:        response.Components.Gateway.Protocol,
		GatewayVersion:         response.Components.Gateway.Version,
		PwaVersion:             response.Components.PWA.Version,
	}
	return remote, validProductVersion(response.ReleaseVersion) && validReleaseChannel(expectedChannel) &&
		releaseChannel(response.ReleaseChannel) == expectedChannel &&
		releaseChannel(response.Components.Gateway.Channel) == expectedChannel &&
		releaseChannel(response.Components.Executor.Channel) == expectedChannel &&
		releaseChannel(response.Components.PWA.Channel) == expectedChannel &&
		remote.GatewayVersion == response.ReleaseVersion &&
		remote.ExecutorVersion == response.ReleaseVersion &&
		remote.PwaVersion == response.ReleaseVersion
}

func writeHumanUpdateReport(output io.Writer, report updateCheckReport) {
	fmt.Fprintf(output, "OneNod update status: %s\n", report.Status)
	fmt.Fprintf(output, "  channel: %s (official repository %s)\n", report.Channel, officialRepository)
	if report.CurrentVersion != "" {
		fmt.Fprintf(output, "  this Mac: %s (channel %s)\n", report.CurrentVersion, report.CurrentChannel)
	} else {
		fmt.Fprintln(output, "  this Mac: not installed from a verified release")
	}
	if report.RequestedVersion != "" {
		fmt.Fprintf(output, "  selected: %s (exact immutable release)\n", report.LatestVersion)
	} else {
		fmt.Fprintf(output, "  latest: %s\n", report.LatestVersion)
	}
	fmt.Fprintf(output, "  minimum safe: %s\n", report.MinimumSafeVersion)
	for _, warning := range report.Warnings {
		fmt.Fprintf(output, "  warning: %s\n", warning)
	}
	for _, step := range report.Plan {
		fmt.Fprintf(output, "  next: %s\n", step)
	}
}
