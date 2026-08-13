package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func runLocalUpdate(args []string, deps dependencies) error {
	if err := reconcileInterruptedTransportUpdate(deps); err != nil {
		return err
	}
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]")
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("OneNod is not installed; run may install --origin https://<worker>.<account>.workers.dev")
	}
	currentChannel := releaseChannel(receipt.Channel)
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, currentChannel)
	if err != nil {
		return err
	}
	channel := selection.Channel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	if compareProductVersions(release.Manifest.ReleaseVersion, receipt.ReleaseVersion) < 0 {
		if awaitingCompatibleRelease(
			receipt.ReleaseVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				deps.stdout, receipt.ReleaseVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return fmt.Errorf("anti_rollback: latest official release %s is older than installed release %s",
			release.Manifest.ReleaseVersion, receipt.ReleaseVersion)
	}
	if _, err := runningReleaseCanConsume(release.Manifest); err != nil {
		return err
	}
	if receipt.ReleaseVersion == release.Manifest.ReleaseVersion {
		if err := validateReceiptReleaseIdentity(receipt, release.Manifest); err != nil {
			return fmt.Errorf("same_version_identity_mismatch: %w", err)
		}
	}
	if err := requireRemoteGatewayCompatibility(
		receipt.Origin,
		release.Manifest.Components.May.ClientProtocol,
		deps.httpClient,
	); err != nil {
		return err
	}
	if err := confirmHigherRiskChannel(
		deps.stdin, deps.stdout, currentChannel, channel, "Local updates",
	); err != nil {
		return err
	}
	helperPlan := buildKeychainHelperUpdatePlan(release, receipt)
	includeHelper := helperPlan.Replace
	if includeHelper {
		writeKeychainHelperUpdatePlan(deps.stdout, helperPlan)
		confirmed, err := promptYesNo(deps.stdin, deps.stdout, "Update the OneNod Keychain helper now?", false)
		if err != nil {
			return err
		}
		if !confirmed {
			return errors.New("Keychain helper update was not approved; no local components were changed")
		}
	}
	return installVerifiedRelease(ctx, release, receipt.Origin, deps, includeHelper)
}

func buildKeychainHelperUpdatePlan(
	release *verifiedRelease,
	receipt *localInstallReceipt,
) keychainHelperUpdatePlan {
	plan := keychainHelperUpdatePlan{
		TargetProtocol:     release.Manifest.Components.KeychainHelper.HelperProtocol,
		TargetSourceDigest: release.Manifest.Components.KeychainHelper.SourceDigest,
		TargetVersion:      release.Manifest.Components.KeychainHelper.Version,
	}
	if receipt != nil {
		plan.CurrentProtocol = receipt.Helper.Protocol
		plan.CurrentSourceDigest = receipt.Helper.SourceDigest
		plan.CurrentVersion = receipt.Helper.Version
	}
	helper, err := inspectInstalledKeychainHelper()
	plan.Replace = err != nil || !helperMatchesRelease(release, receipt, helper)
	return plan
}

func writeKeychainHelperUpdatePlan(output io.Writer, plan keychainHelperUpdatePlan) {
	if !plan.Replace {
		fmt.Fprintf(output, "  Keychain helper: unchanged at %s (protocol %d; source %s)\n",
			plan.CurrentVersion, plan.CurrentProtocol, plan.CurrentSourceDigest)
		return
	}
	currentVersion := plan.CurrentVersion
	currentSource := plan.CurrentSourceDigest
	currentProtocol := "not installed"
	if currentVersion == "" {
		currentVersion = "not installed"
	}
	if currentSource == "" {
		currentSource = "not recorded"
	}
	if plan.CurrentProtocol > 0 {
		currentProtocol = strconv.Itoa(plan.CurrentProtocol)
	}
	fmt.Fprintf(output,
		"  Keychain helper: replace %s -> %s\n  Helper protocol: %s -> %d-%d\n  Helper source: %s -> %s\n  SECURITY CEREMONY: pause every Agent harness running as this macOS user before continuing.\n  Keep them paused while macOS presents any Keychain confirmation for this independently versioned security component.\n",
		currentVersion, plan.TargetVersion, currentProtocol,
		plan.TargetProtocol.Minimum, plan.TargetProtocol.Maximum,
		currentSource, plan.TargetSourceDigest,
	)
}

func runBinaryInstall(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	origin := flags.String("origin", "", "public workers.dev Gateway origin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 || *origin == "" {
		return errors.New("usage: may install --origin https://<worker>.<account>.workers.dev [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]")
	}
	parsed, err := parseGatewayOrigin(*origin)
	if err != nil || !workersDevHostPattern.MatchString(parsed.Host) {
		return errors.New("install Origin must be a normalized workers.dev HTTPS origin")
	}
	existing, found, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	if found && existing.Origin != *origin {
		return fmt.Errorf("existing OneNod installation targets %s; refusing to switch to %s", existing.Origin, *origin)
	}
	if found {
		return errors.New("OneNod is already installed; use may update so any Keychain helper change receives its dedicated security review")
	}
	currentChannel := releaseChannelStable
	currentVersion := ""
	if initializer, initializerFound, initializerErr := readInitializerInstallReceipt(); initializerErr != nil {
		return initializerErr
	} else if initializerFound {
		currentChannel = releaseChannel(initializer.Channel)
		currentVersion = initializer.ReleaseVersion
	} else if err := confirmFirstExecutionCeremony(
		deps.stdin,
		deps.stdout,
		firstExecutionInstall,
		fmt.Sprintf("may install will install the exact local runtime, Keychain helper, and managed Skill for %s", *origin),
	); err != nil {
		return err
	}
	if err := reconcileInterruptedTransportUpdate(deps); err != nil {
		return err
	}
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, currentChannel)
	if err != nil {
		return err
	}
	channel := selection.Channel
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	if currentVersion != "" && compareProductVersions(release.Manifest.ReleaseVersion, currentVersion) < 0 {
		if awaitingCompatibleRelease(
			currentVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				deps.stdout, currentVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return fmt.Errorf("anti_rollback: selected official release %s is older than installed release %s",
			release.Manifest.ReleaseVersion, currentVersion)
	}
	if _, err := runningReleaseCanConsume(release.Manifest); err != nil {
		return err
	}
	if err := requireRemoteGatewayCompatibility(
		*origin,
		release.Manifest.Components.May.ClientProtocol,
		deps.httpClient,
	); err != nil {
		return err
	}
	if err := confirmHigherRiskChannel(
		deps.stdin, deps.stdout, currentChannel, channel, "Local installation",
	); err != nil {
		return err
	}
	return installVerifiedRelease(ctx, release, *origin, deps, true)
}

func installVerifiedRelease(
	ctx context.Context,
	release *verifiedRelease,
	origin string,
	deps dependencies,
	includeHelper bool,
) error {
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	localName, err := localArtifactName()
	if err != nil {
		return err
	}
	localArtifact, err := artifactFor(release, localName)
	if err != nil {
		return err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	localArchive, err := downloadVerifiedArtifact(ctx, release, localArtifact)
	if err != nil {
		return err
	}
	localExtract := filepath.Join(stage, "local")
	if err := os.Mkdir(localExtract, 0o700); err != nil {
		return errors.New("create local release extraction directory failed")
	}
	localMetadata, err := extractVerifiedLocalArchive(localArchive, localExtract, release.Manifest)
	if err != nil {
		return err
	}
	skillArtifact, err := artifactFor(release, skillArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return err
	}
	skillArchive, err := downloadVerifiedArtifact(ctx, release, skillArtifact)
	if err != nil {
		return err
	}
	skillExtract := filepath.Join(stage, "skill")
	if err := os.Mkdir(skillExtract, 0o700); err != nil {
		return errors.New("create Skill release extraction directory failed")
	}
	if err := extractSkillArchive(skillArchive, skillExtract); err != nil {
		return err
	}
	previous, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	helperResponse, helperErr := inspectInstalledKeychainHelper()
	helperCompatible := helperErr == nil && helperMatchesRelease(release, previous, helperResponse)
	var helperSource string
	var helperArtifact releaseArtifact
	verifiedTransport := verifiedLocalTransportDescriptor{
		MaySHA256:       localMetadata.BinarySHA256.May,
		MayIdentity:     localMetadata.ExactCodeIdentities.May,
		AdapterSHA256:   localMetadata.BinarySHA256.MaySSHSign,
		AdapterIdentity: localMetadata.ExactCodeIdentities.MaySSHSign,
	}
	if !helperCompatible {
		if !includeHelper {
			return errors.New("verified release requires an explicit Keychain helper update; rerun may install after reviewing the helper change")
		}
		helperName, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
		if err != nil {
			return err
		}
		helperArtifact, err = artifactFor(release, helperName)
		if err != nil {
			return err
		}
		helperArchive, err := downloadVerifiedArtifact(ctx, release, helperArtifact)
		if err != nil {
			return err
		}
		helperExtract := filepath.Join(stage, "helper")
		if err := os.Mkdir(helperExtract, 0o700); err != nil {
			return errors.New("create helper release extraction directory failed")
		}
		helperMetadata, err := extractVerifiedHelperArchive(helperArchive, helperExtract, release.Manifest)
		if err != nil {
			return err
		}
		verifiedTransport.HelperSHA256 = helperMetadata.BinarySHA256
		verifiedTransport.HelperIdentity = helperMetadata.ExactCodeIdentity
		helperSource = filepath.Join(helperExtract, "onenod-keychain-helper", "bin", keychainHelperBinaryName)
	} else if previous != nil {
		verifiedTransport.HelperSHA256 = previous.Helper.BinarySHA256
		verifiedTransport.HelperIdentity = previous.ExactCodeIdentities.Helper
	}
	return activateVerifiedLocalRelease(
		release, origin,
		filepath.Join(localExtract, "onenod", "bin", "may"),
		filepath.Join(localExtract, "onenod", "bin", gitSignAdapterBinaryName),
		filepath.Join(skillExtract, "onenod-skill", "onenod"),
		helperSource, localArtifact, helperArtifact, skillArtifact, helperResponse, previous,
		verifiedTransport, deps,
	)
}

func installVerifiedInitializer(
	ctx context.Context,
	release *verifiedRelease,
	deps dependencies,
) error {
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	localName, err := localArtifactName()
	if err != nil {
		return err
	}
	localArtifact, err := artifactFor(release, localName)
	if err != nil {
		return err
	}
	skillArtifact, err := artifactFor(release, skillArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return err
	}
	helperName, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
	if err != nil {
		return err
	}
	helperArtifact, err := artifactFor(release, helperName)
	if err != nil {
		return err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	localArchive, err := downloadVerifiedArtifact(ctx, release, localArtifact)
	if err != nil {
		return err
	}
	localExtract := filepath.Join(stage, "local")
	if err := os.Mkdir(localExtract, 0o700); err != nil {
		return errors.New("create initializer release extraction directory failed")
	}
	if _, err := extractVerifiedLocalArchive(localArchive, localExtract, release.Manifest); err != nil {
		return err
	}

	skillArchive, err := downloadVerifiedArtifact(ctx, release, skillArtifact)
	if err != nil {
		return err
	}
	skillExtract := filepath.Join(stage, "skill")
	if err := os.Mkdir(skillExtract, 0o700); err != nil {
		return errors.New("create initializer Skill extraction directory failed")
	}
	if err := extractSkillArchive(skillArchive, skillExtract); err != nil {
		return err
	}

	helperArchive, err := downloadVerifiedArtifact(ctx, release, helperArtifact)
	if err != nil {
		return err
	}
	helperExtract := filepath.Join(stage, "helper")
	if err := os.Mkdir(helperExtract, 0o700); err != nil {
		return errors.New("create initializer helper extraction directory failed")
	}
	if _, err := extractVerifiedHelperArchive(helperArchive, helperExtract, release.Manifest); err != nil {
		return err
	}

	return activateVerifiedInitializer(
		release,
		filepath.Join(localExtract, "onenod", "bin", "may"),
		filepath.Join(localExtract, "onenod", "bin", gitSignAdapterBinaryName),
		filepath.Join(skillExtract, "onenod-skill", "onenod"),
		filepath.Join(helperExtract, "onenod-keychain-helper", "bin", keychainHelperBinaryName),
		localArtifact, skillArtifact, helperArtifact, deps,
	)
}

func activateVerifiedInitializer(
	release *verifiedRelease,
	maySource, adapterSource, skillSource, helperSource string,
	localArtifact, skillArtifact, helperArtifact releaseArtifact,
	deps dependencies,
) (returnErr error) {
	if !protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, keychainHelperProtocol) {
		return errors.New("verified initializer helper protocol is incompatible with the running may")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for initializer activation failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		root, filepath.Join(root, "bin"), filepath.Join(root, "libexec"),
		filepath.Join(root, "versions"), filepath.Join(root, "helper-versions"),
		filepath.Join(root, "skill-versions"),
	} {
		if err := ensurePrivateInstallDirectory(directory); err != nil {
			return err
		}
	}
	previousLocal, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	previousInitializer, initializerFound, err := readInitializerInstallReceipt()
	if err != nil {
		return err
	}
	if previousLocal == nil && initializerFound {
		previousLocal = &localInstallReceipt{}
		previousLocal.Helper.Version = previousInitializer.HelperVersion
		previousLocal.Helper.BinarySHA256 = previousInitializer.Files["libexec/"+keychainHelperBinaryName]
	}
	versionDirectory := filepath.Join(root, "versions", release.Manifest.ReleaseVersion)
	if err := installVersionDirectory(versionDirectory, map[string]string{
		"may": maySource, gitSignAdapterBinaryName: adapterSource,
	}); err != nil {
		return err
	}
	skillDirectory := filepath.Join(root, "skill-versions", release.Manifest.ReleaseVersion, "onenod")
	if err := installTreeDirectory(skillDirectory, skillSource); err != nil {
		return err
	}
	helperDirectory := filepath.Join(root, "helper-versions", release.Manifest.Components.KeychainHelper.Version)
	if err := installVersionDirectory(helperDirectory, map[string]string{
		keychainHelperBinaryName: helperSource,
	}); err != nil {
		return err
	}

	var helperRollback *helperReplacement
	defer func() {
		if returnErr == nil || helperRollback == nil {
			return
		}
		if rollbackErr := helperRollback.rollback(); rollbackErr != nil {
			returnErr = fmt.Errorf("%w; initializer helper rollback also failed: %v", returnErr, rollbackErr)
		}
	}()
	helperRollback, err = activateStableHelper(
		filepath.Join(root, "libexec", keychainHelperBinaryName),
		filepath.Join(helperDirectory, keychainHelperBinaryName), previousLocal,
	)
	if err != nil {
		return err
	}
	helper, err := inspectInstalledKeychainHelper()
	if err != nil || helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		helper.Protocol != keychainHelperProtocol {
		return errors.New("verified initializer Keychain helper failed exact identity verification")
	}

	managedLinks := []string{
		filepath.Join(root, "bin", "may"),
		filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join(root, "skill"),
	}
	previousLinks, err := captureManagedSymlinks(managedLinks)
	if err != nil {
		return err
	}
	promotionStarted := true
	var discoveryTransaction *skillDiscoveryTransaction
	defer func() {
		if returnErr == nil || !promotionStarted {
			return
		}
		var failures []error
		if rollbackErr := restoreManagedSymlinks(previousLinks); rollbackErr != nil {
			failures = append(failures, rollbackErr)
		}
		if rollbackErr := discoveryTransaction.rollback(); rollbackErr != nil {
			failures = append(failures, rollbackErr)
		}
		if len(failures) > 0 {
			returnErr = fmt.Errorf("%w; initializer stable-path rollback also failed: %v", returnErr, errors.Join(failures...))
		}
	}()
	if err := replaceStableSymlink(filepath.Join(root, "bin", "may"),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, "may")); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "bin", gitSignAdapterBinaryName),
		filepath.Join("..", "versions", release.Manifest.ReleaseVersion, gitSignAdapterBinaryName)); err != nil {
		return err
	}
	if err := replaceStableSymlink(filepath.Join(root, "skill"),
		filepath.Join("skill-versions", release.Manifest.ReleaseVersion, "onenod")); err != nil {
		return err
	}
	skillDigest, err := directoryTreeSHA256(skillSource)
	if err != nil {
		return err
	}
	_, discoveryTransaction, err = installSkillDiscoveryLinks(home, filepath.Join(root, "skill"), skillDigest)
	if err != nil {
		return err
	}
	receipt := initializerInstallReceipt{
		AdoptedBackups: discoveryTransaction.backupPaths(),
		Artifacts: map[string]string{
			localArtifact.Name:  localArtifact.SHA256,
			skillArtifact.Name:  skillArtifact.SHA256,
			helperArtifact.Name: helperArtifact.SHA256,
		},
		Channel: string(selectedReleaseChannel(release)), Files: map[string]string{}, HelperProtocol: helper.Protocol,
		HelperVersion: helper.Version, InstalledAt: time.Now().UTC().Format(time.RFC3339),
		ReleaseVersion: release.Manifest.ReleaseVersion, SchemaVersion: initializerReceiptSchema,
		SkillTreeSHA: skillDigest, SourceCommit: release.Manifest.Source.Commit,
	}
	if initializerFound {
		receipt.AdoptedBackups = append(previousInitializer.AdoptedBackups, receipt.AdoptedBackups...)
	}
	for relative, path := range map[string]string{
		"bin/may":                             maySource,
		"bin/" + gitSignAdapterBinaryName:     adapterSource,
		"libexec/" + keychainHelperBinaryName: filepath.Join(root, "libexec", keychainHelperBinaryName),
	} {
		receipt.Files[relative], err = regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return err
		}
	}
	receiptPath, err := initializerReceiptPath()
	if err != nil {
		return err
	}
	if err := writeAtomicPrivateJSON(receiptPath, receipt); err != nil {
		return err
	}
	promotionStarted = false
	fmt.Fprintf(deps.stdout, "Installed verified OneNod initializer %s before production authorization.\n", release.Manifest.ReleaseVersion)
	return nil
}
