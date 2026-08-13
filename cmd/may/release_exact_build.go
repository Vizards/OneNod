package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type exactBuildUpdateTransaction struct {
	capability []byte
	committed  bool
	journal    transportUpdateJournal
	newMayPath string
}

var errTransportFinalizeUncertain = errors.New("exact-build transport finalize outcome is uncertain")

var (
	queryTransportAgentVersion    = queryRunningAgentVersion
	runTransportFinalizeChild     = runStagedTransportFinalize
	queryFinalizedTransportStatus = runExactTransportStatus
)

func prepareExactBuildUpdateTransaction(
	release *verifiedRelease,
	origin, maySource, adapterSource, helperSource string,
	previous *localInstallReceipt,
	expected verifiedLocalTransportDescriptor,
) (*exactBuildUpdateTransaction, error) {
	if previous == nil {
		return nil, nil
	}
	slot, selected, err := selectedRequesterSlot(origin)
	if err != nil {
		return nil, err
	}
	if !selected {
		return nil, nil
	}
	status, err := queryTransportUpdateStatus(origin, slot)
	if err != nil {
		return nil, fmt.Errorf("inspect current exact-build transport trust failed: %w", err)
	}
	if status.Role == "none" {
		return nil, nil
	}
	if status.Role != "current" || status.TransactionState == "staged" {
		return nil, errors.New("exact-build transport trust is not in an updatable current state")
	}
	stableHelper, err := installedKeychainHelperPath()
	if err != nil {
		return nil, err
	}
	candidateHelper := helperSource
	if candidateHelper == "" {
		candidateHelper = stableHelper
	}
	if !digestPattern.MatchString(expected.MaySHA256) ||
		!digestPattern.MatchString(expected.AdapterSHA256) ||
		!digestPattern.MatchString(expected.HelperSHA256) ||
		!validExactBuildRuntimeIdentity(expected.MayIdentity) ||
		!validExactBuildRuntimeIdentity(expected.AdapterIdentity) ||
		!validExactBuildRuntimeIdentity(expected.HelperIdentity) {
		return nil, errors.New("verified exact-build transport descriptor is incomplete")
	}
	for path, expectedDigest := range map[string]string{
		maySource:       expected.MaySHA256,
		adapterSource:   expected.AdapterSHA256,
		candidateHelper: expected.HelperSHA256,
	} {
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil || digest != expectedDigest {
			return nil, errors.New("exact-build transport candidate changed after verified extraction")
		}
	}
	if previous.Files["bin/may"] == expected.MaySHA256 &&
		previous.Files["bin/"+gitSignAdapterBinaryName] == expected.AdapterSHA256 &&
		previous.Helper.BinarySHA256 == expected.HelperSHA256 {
		return nil, nil
	}
	transactionID, err := newTransportTransactionID()
	if err != nil {
		return nil, err
	}
	journal := transportUpdateJournal{
		HelperChanged:    helperSource != "",
		NewHelperVersion: release.Manifest.Components.KeychainHelper.Version,
		NewRelease:       release.Manifest.ReleaseVersion,
		NewTargets:       managedReleaseTargets(release.Manifest.ReleaseVersion, release.Manifest.ReleaseVersion),
		OldHelperVersion: previous.Helper.Version,
		OldRelease:       previous.ReleaseVersion,
		OldTargets:       managedReleaseTargets(previous.ReleaseVersion, previous.Skill.Version),
		Origin:           origin, Phase: "prepared", Slot: slot, TransactionID: transactionID,
	}
	if err := writeTransportUpdateJournal(journal); err != nil {
		return nil, err
	}
	capability, err := stageVerifiedTransport(
		origin, slot, transactionID, maySource, adapterSource, candidateHelper,
		expected.MaySHA256, expected.AdapterSHA256, expected.HelperSHA256,
		expected.MayIdentity, expected.AdapterIdentity, expected.HelperIdentity,
	)
	if err != nil {
		status, statusErr := queryTransportUpdateStatus(origin, slot)
		if statusErr != nil {
			return nil, fmt.Errorf("%w: stage failed and exact-build state could not be authenticated", errTransportFinalizeUncertain)
		}
		if status.TransactionID == transactionID && status.TransactionState == "staged" &&
			status.Role == "current" {
			if abortErr := abortStagedTransport(origin, slot, transactionID); abortErr != nil {
				return nil, fmt.Errorf("%w: partial exact-build stage could not be aborted", errTransportFinalizeUncertain)
			}
			_ = removeTransportUpdateJournal()
			return nil, fmt.Errorf("stage exact-build transport trust failed and its partial state was safely aborted: %w", err)
		}
		if status.TransactionState != "staged" {
			_ = removeTransportUpdateJournal()
			return nil, fmt.Errorf("stage exact-build transport trust failed before persistence: %w", err)
		}
		return nil, fmt.Errorf("%w: stage failed with an inconsistent authenticated state", errTransportFinalizeUncertain)
	}
	transaction := &exactBuildUpdateTransaction{
		capability: capability,
		newMayPath: maySource,
		journal:    journal,
	}
	transaction.journal.Phase = "staged"
	if err := writeTransportUpdateJournal(transaction.journal); err != nil {
		abortErr := abortStagedTransport(origin, slot, transactionID)
		zeroBytes(capability)
		if abortErr != nil {
			return nil, fmt.Errorf("%w; staged transport abort also failed: %v", err, abortErr)
		}
		_ = removeTransportUpdateJournal()
		return nil, err
	}
	transaction.journal.Phase = "promoting"
	if err := writeTransportUpdateJournal(transaction.journal); err != nil {
		abortErr := abortStagedTransport(origin, slot, transactionID)
		zeroBytes(capability)
		if abortErr != nil {
			return nil, fmt.Errorf("%w; staged transport abort also failed: %v", err, abortErr)
		}
		_ = removeTransportUpdateJournal()
		return nil, err
	}
	return transaction, nil
}

func (transaction *exactBuildUpdateTransaction) abortAfterRollback(root string) error {
	if transaction == nil || transaction.committed {
		return nil
	}
	oldMay := filepath.Join(root, "versions", transaction.journal.OldRelease, "may")
	err := runCurrentTransportAbort(
		oldMay, transaction.journal.Origin, transaction.journal.Slot,
		transaction.journal.TransactionID,
	)
	if err == nil {
		err = removeTransportUpdateJournal()
	}
	return err
}

func (transaction *exactBuildUpdateTransaction) finalize(
	plan *userCLIInstallPlan,
	release *verifiedRelease,
	deps dependencies,
) error {
	version, err := queryTransportAgentVersion(plan.socketPath)
	if err != nil || version.Version != release.Manifest.ReleaseVersion ||
		version.SourceCommit != release.Manifest.Source.Commit ||
		version.ClientProtocol != release.Manifest.Components.May.ClientProtocol {
		return errors.New("promoted may SSH Agent failed exact no-Keychain version health check")
	}
	transaction.journal.Phase = "health_checked"
	if err := writeTransportUpdateJournal(transaction.journal); err != nil {
		return err
	}
	if err := runTransportFinalizeChild(
		transaction.newMayPath,
		transaction.journal.Origin,
		transaction.journal.Slot,
		transaction.journal.TransactionID,
		transaction.journal.HelperChanged,
		transaction.capability,
	); err != nil {
		status, statusErr := queryFinalizedTransportStatus(
			transaction.newMayPath,
			transaction.journal.Origin,
			transaction.journal.Slot,
			transaction.journal.TransactionID,
		)
		if statusErr != nil {
			return fmt.Errorf("%w: finalize failed and the staged exact may could not authenticate commit state", errTransportFinalizeUncertain)
		}
		if status.TransactionState == "committed" && status.Role == "current" {
			transaction.committed = true
			if removeErr := removeTransportUpdateJournal(); removeErr != nil {
				fmt.Fprintln(deps.stderr, "OneNod exact-build update committed; its private recovery journal will be cleaned on the next update check.")
			}
			return nil
		}
		if status.TransactionState != "staged" || status.Role != "staged" {
			return fmt.Errorf("%w: finalize failed with an inconsistent authenticated state", errTransportFinalizeUncertain)
		}
		return errors.New("staged exact-build may did not commit transport trust")
	}
	transaction.committed = true
	// Commit is the final trust mutation. Journal removal is intentionally the
	// only operation after it and is idempotently reconciled after a crash.
	if err := removeTransportUpdateJournal(); err != nil {
		fmt.Fprintln(deps.stderr, "OneNod exact-build update committed; its private recovery journal will be cleaned on the next update check.")
	}
	return nil
}

func activateVerifiedLocalRelease(
	release *verifiedRelease,
	origin, maySource, adapterSource, skillSource, helperSource string,
	localArtifact, helperArtifact, skillArtifact releaseArtifact,
	existingHelper keychainHelperResponse,
	previous *localInstallReceipt,
	verifiedTransport verifiedLocalTransportDescriptor,
	deps dependencies,
) (returnErr error) {
	transaction, err := prepareExactBuildUpdateTransaction(
		release, origin, maySource, adapterSource, helperSource, previous, verifiedTransport,
	)
	if err != nil {
		return err
	}
	if transaction != nil {
		defer zeroBytes(transaction.capability)
	}
	returnErr = activateVerifiedLocalReleaseCore(
		release, origin, maySource, adapterSource, skillSource, helperSource,
		localArtifact, helperArtifact, skillArtifact, existingHelper, previous,
		verifiedTransport, deps,
		func(plan *userCLIInstallPlan) error {
			if transaction == nil {
				return nil
			}
			return transaction.finalize(plan, release, deps)
		},
	)
	if returnErr != nil && transaction != nil && !transaction.committed &&
		!errors.Is(returnErr, errTransportFinalizeUncertain) {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return fmt.Errorf("%w; resolve transport rollback root failed", returnErr)
		}
		if abortErr := transaction.abortAfterRollback(filepath.Join(home, userAgentDirectoryName)); abortErr != nil {
			return fmt.Errorf("%w; exact-build transport abort also failed: %v", returnErr, abortErr)
		}
	}
	return returnErr
}

func activateVerifiedLocalReleaseCore(
	release *verifiedRelease,
	origin, maySource, adapterSource, skillSource, helperSource string,
	localArtifact, helperArtifact, skillArtifact releaseArtifact,
	existingHelper keychainHelperResponse,
	previous *localInstallReceipt,
	verifiedTransport verifiedLocalTransportDescriptor,
	deps dependencies,
	finalize func(*userCLIInstallPlan) error,
) (returnErr error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for OneNod activation failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		root, filepath.Join(root, "bin"), filepath.Join(root, "libexec"),
		filepath.Join(root, "versions"), filepath.Join(root, "helper-versions"),
		filepath.Join(root, "skill-versions"),
		filepath.Join(root, "logs"), filepath.Join(root, "ssh"),
	} {
		if err := ensurePrivateInstallDirectory(directory); err != nil {
			return err
		}
	}
	var helperRollback *helperReplacement
	defer func() {
		if returnErr == nil || helperRollback == nil || errors.Is(returnErr, errTransportFinalizeUncertain) {
			return
		}
		if rollbackErr := helperRollback.rollback(); rollbackErr != nil {
			returnErr = fmt.Errorf("%w; Keychain helper rollback also failed: %v", returnErr, rollbackErr)
		}
	}()
	versionDirectory := filepath.Join(root, "versions", release.Manifest.ReleaseVersion)
	if err := installVersionDirectory(versionDirectory, map[string]string{
		"may": maySource, gitSignAdapterBinaryName: adapterSource,
	}); err != nil {
		return err
	}
	for path, expected := range map[string]string{
		filepath.Join(versionDirectory, "may"):                    verifiedTransport.MaySHA256,
		filepath.Join(versionDirectory, gitSignAdapterBinaryName): verifiedTransport.AdapterSHA256,
	} {
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil || digest != expected {
			return errors.New("installed exact-build transport differs from its verified Release descriptor")
		}
	}
	skillDirectory := filepath.Join(root, "skill-versions", release.Manifest.ReleaseVersion, "onenod")
	if err := installTreeDirectory(skillDirectory, skillSource); err != nil {
		return err
	}
	skillTreeDigest, err := directoryTreeSHA256(skillSource)
	if err != nil {
		return err
	}
	helperVersion := existingHelper.Version
	helperProtocol := existingHelper.Protocol
	if helperSource != "" {
		helperVersion = release.Manifest.Components.KeychainHelper.Version
		helperProtocol = release.Manifest.Components.KeychainHelper.HelperProtocol.Minimum
		helperDirectory := filepath.Join(root, "helper-versions", helperVersion)
		if err := installVersionDirectory(helperDirectory, map[string]string{
			keychainHelperBinaryName: helperSource,
		}); err != nil {
			return err
		}
		installedHelperDigest, err := regularFileSHA256(
			filepath.Join(helperDirectory, keychainHelperBinaryName), maxReleaseArtifactBytes,
		)
		if err != nil || installedHelperDigest != verifiedTransport.HelperSHA256 {
			return errors.New("installed exact-build Keychain helper differs from its verified Release descriptor")
		}
		helperRollback, err = activateStableHelper(
			filepath.Join(root, "libexec", keychainHelperBinaryName),
			filepath.Join(helperDirectory, keychainHelperBinaryName),
			previous,
		)
		if err != nil {
			return err
		}
		activated, err := inspectInstalledKeychainHelper()
		if err != nil {
			return fmt.Errorf("activated Keychain helper inspection failed: %w", err)
		}
		if activated.Version != helperVersion {
			return fmt.Errorf(
				"activated Keychain helper version mismatch: expected %s, got %s",
				helperVersion, activated.Version,
			)
		}
		if !protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, activated.Protocol) {
			return fmt.Errorf(
				"activated Keychain helper protocol %d is outside the verified Release range %d-%d",
				activated.Protocol,
				release.Manifest.Components.KeychainHelper.HelperProtocol.Minimum,
				release.Manifest.Components.KeychainHelper.HelperProtocol.Maximum,
			)
		}
		helperProtocol = activated.Protocol
	}
	commandPlan, err := planCommandDiscovery(
		home, filepath.Join(root, "bin", "may"), deps,
	)
	if err != nil {
		return err
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
	managedFiles := []string{
		filepath.Join(root, userAgentEnvFileName),
		filepath.Join(root, "install.json"),
		filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
	}
	previousFiles, err := captureManagedFiles(managedFiles)
	if err != nil {
		return err
	}
	promotionStarted := true
	agentActivationStarted := false
	var commandTransaction *commandDiscoveryTransaction
	var discoveryTransaction *skillDiscoveryTransaction
	defer func() {
		if returnErr == nil || !promotionStarted || errors.Is(returnErr, errTransportFinalizeUncertain) {
			return
		}
		var rollbackErrors []error
		if agentActivationStarted {
			domain := fmt.Sprintf("gui/%d", os.Getuid())
			output, rollbackErr := runLaunchctl("bootout", domain+"/"+oneNodAgentLabel)
			zeroBytes(output)
			if rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, errors.New("stop partially activated SSH Agent failed"))
			}
		}
		if rollbackErr := commandTransaction.rollback(); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if rollbackErr := restoreManagedSymlinks(previousLinks); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if rollbackErr := discoveryTransaction.rollback(); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if rollbackErr := restoreManagedFiles(previousFiles); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, rollbackErr)
		}
		if agentActivationStarted && previous != nil {
			oldPlan := &userCLIInstallPlan{
				binaryPath:      filepath.Join(root, "bin", "may"),
				adapterPath:     filepath.Join(root, "bin", gitSignAdapterBinaryName),
				launchAgentPath: filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
				socketPath:      filepath.Join(root, "agent.sock"),
			}
			if rollbackErr := activateApprovalAgent(oldPlan); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("prior SSH Agent restart failed: %w", rollbackErr))
			}
		}
		if len(rollbackErrors) > 0 {
			returnErr = fmt.Errorf("%w; local activation rollback also failed: %v", returnErr, errors.Join(rollbackErrors...))
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
	commandTransaction, err = commandPlan.apply()
	if err != nil {
		return err
	}
	discovery, discoveryTransaction, err := installSkillDiscoveryLinks(
		home, filepath.Join(root, "skill"), skillTreeDigest,
	)
	if err != nil {
		return err
	}
	if err := installOriginAndLaunchAgent(root, origin, home); err != nil {
		return err
	}
	receiptPath, err := localReceiptPath()
	if err != nil {
		return err
	}
	receipt := localInstallReceipt{
		Artifacts: map[string]string{
			localArtifact.Name: localArtifact.SHA256,
			skillArtifact.Name: skillArtifact.SHA256,
		},
		Channel:     string(selectedReleaseChannel(release)),
		Files:       map[string]string{},
		InstalledAt: time.Now().UTC().Format(time.RFC3339), Origin: origin,
		ReleaseVersion: release.Manifest.ReleaseVersion, SourceCommit: release.Manifest.Source.Commit,
	}
	for relative, path := range map[string]string{
		"bin/may": maySource, "bin/" + gitSignAdapterBinaryName: adapterSource,
	} {
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return err
		}
		receipt.Files[relative] = digest
	}
	receipt.Skill.Artifact = skillArtifact.Name
	receipt.Skill.ArtifactSHA = skillArtifact.SHA256
	receipt.Skill.Discovery = discovery
	if previous != nil {
		receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, previous.Skill.AdoptedBackups...)
	} else if initializer, found, readErr := readInitializerInstallReceipt(); readErr != nil {
		return readErr
	} else if found {
		receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, initializer.AdoptedBackups...)
	}
	receipt.Skill.AdoptedBackups = append(receipt.Skill.AdoptedBackups, discoveryTransaction.backupPaths()...)
	receipt.Skill.Version = release.Manifest.Components.Skill.Version
	receipt.Skill.TreeSHA256 = skillTreeDigest
	if helperArtifact.Name != "" {
		receipt.Artifacts[helperArtifact.Name] = helperArtifact.SHA256
		receipt.Helper.Artifact = helperArtifact.Name
		receipt.Helper.ArtifactSHA = helperArtifact.SHA256
	} else if previous != nil {
		receipt.Helper.Artifact = previous.Helper.Artifact
		receipt.Helper.ArtifactSHA = previous.Helper.ArtifactSHA
		if receipt.Helper.Artifact != "" {
			receipt.Artifacts[receipt.Helper.Artifact] = receipt.Helper.ArtifactSHA
		}
	}
	receipt.Helper.Protocol = helperProtocol
	receipt.Helper.SourceDigest = release.Manifest.Components.KeychainHelper.SourceDigest
	receipt.Helper.Version = helperVersion
	receipt.Helper.BinarySHA256, err = regularFileSHA256(
		filepath.Join(root, "libexec", keychainHelperBinaryName), maxReleaseArtifactBytes,
	)
	if err != nil {
		return err
	}
	receipt.ExactCodeIdentities.May = verifiedTransport.MayIdentity
	receipt.ExactCodeIdentities.MaySSHSign = verifiedTransport.AdapterIdentity
	if helperSource != "" {
		receipt.ExactCodeIdentities.Helper = verifiedTransport.HelperIdentity
	} else if previous != nil {
		receipt.ExactCodeIdentities.Helper = previous.ExactCodeIdentities.Helper
	}
	if !validExactBuildRuntimeIdentity(receipt.ExactCodeIdentities.Helper) {
		return errors.New("verified exact-build Keychain helper identity is unavailable for the install receipt")
	}
	plan := &userCLIInstallPlan{
		binaryPath:      filepath.Join(root, "bin", "may"),
		adapterPath:     filepath.Join(root, "bin", gitSignAdapterBinaryName),
		launchAgentPath: filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
		socketPath:      filepath.Join(root, "agent.sock"),
	}
	agentActivationStarted = true
	if err := activateApprovalAgent(plan); err != nil {
		return err
	}
	if err := writeLocalInstallReceipt(receiptPath, receipt); err != nil {
		return err
	}
	if err := preserveImmutableReceipt(receipt); err != nil {
		return err
	}
	if finalize != nil {
		if err := finalize(plan); err != nil {
			return err
		}
	}
	promotionStarted = false
	fmt.Fprintf(deps.stdout, "Installed OneNod %s for %s.\n", release.Manifest.ReleaseVersion, origin)
	fmt.Fprintf(deps.stdout, "Requester CLI: %s\n", plan.binaryPath)
	if commandPlan.manageLink {
		if pathContainsDirectory(os.Getenv("PATH"), filepath.Dir(commandPlan.linkPath)) {
			fmt.Fprintln(deps.stdout, "Short command on the current PATH: may")
		} else if commandPlan.writeProfile {
			fmt.Fprintln(deps.stdout, "Short command in new zsh login sessions: may")
		} else {
			fmt.Fprintln(deps.stdout, "Shell PATH unchanged; use ~/.onenod/bin/may until ~/.local/bin is added to PATH.")
		}
	}
	fmt.Fprintf(deps.stdout, "Keychain helper %s (protocol %d) remains independently versioned.\n", helperVersion, helperProtocol)
	if previous == nil {
		fmt.Fprintln(deps.stdout, "OpenSSH and Git signing configuration were not changed.")
		fmt.Fprintln(deps.stdout, "Optional integrations (each requires a separate human confirmation):")
		fmt.Fprintf(deps.stdout, "  %s configure ssh apply\n", plan.binaryPath)
		fmt.Fprintf(deps.stdout, "  %s configure git-signing apply --signing-key <SSH-public-key-or-path>\n", plan.binaryPath)
		fmt.Fprintln(deps.stdout, "Local quota fallback is not enabled automatically because it grants this Mac a separate 1Password approval path.")
		fmt.Fprintln(deps.stdout, "After signing in to the 1Password desktop app, configure it with:")
		fmt.Fprintf(deps.stdout, "  %s configure local-fallback apply\n", plan.binaryPath)
		fmt.Fprintln(deps.stdout, "That guided flow requires the Agent Vault to be included in ~/.config/1Password/ssh/agent.toml and verifies its SSH public fingerprints.")
		fmt.Fprintln(deps.stdout, "The requester Mac does not need 1Password CLI for this fallback; it uses the official Desktop SDK and native 1Password SSH Agent.")
	}
	return nil
}
