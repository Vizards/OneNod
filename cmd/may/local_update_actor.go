package main

import (
	"errors"
	"os"
	"path/filepath"
)

func installedLocalUpdateActor(
	operatorOrigin, targetVersion, targetSourceCommit string,
) (string, error) {
	if parsed, err := parseGatewayOrigin(operatorOrigin); err != nil ||
		parsed.String() != operatorOrigin || !validProductVersion(targetVersion) {
		return "", errors.New("operator local update selection is invalid")
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil || !found {
		return "", errors.New("verified local install receipt is required for operator local update handoff")
	}
	if receipt.Origin != operatorOrigin {
		return "", errors.New("operator and local install Origins differ; refusing local update handoff")
	}
	journal, found, err := readTransportUpdateJournal()
	if err != nil {
		return "", err
	}
	if !found {
		actor, err := verifiedInstalledMayActor(receipt.ReleaseVersion, receipt.Files["bin/may"])
		if err != nil {
			return "", err
		}
		if err := stableMayMatchesRelease(receipt.ReleaseVersion); err != nil {
			return "", err
		}
		if err := stableMayIsActor(actor); err != nil {
			return "", err
		}
		return actor, nil
	}
	if journal.Origin != operatorOrigin || journal.NewRelease != targetVersion {
		return "", errors.New("operator update and interrupted local transport transaction differ; recover that exact transaction first")
	}
	oldReceipt, err := readImmutableLocalReceipt(journal.OldRelease)
	if err != nil || oldReceipt.Origin != operatorOrigin {
		return "", errors.New("interrupted local update has no matching immutable old receipt")
	}
	oldActor, err := verifyTransportRollbackMaterial(journal, oldReceipt)
	if err != nil {
		return "", err
	}
	stableSide, err := stableMayTargetSide(journal)
	if err != nil {
		return "", err
	}
	if !journal.HelperChanged {
		if err := verifyStableHelperDigest(oldReceipt.Helper.BinarySHA256); err != nil {
			return "", errors.New("unchanged stable helper is unavailable for interrupted local update")
		}
	}
	// With the old may active, recovery restores the old helper before status.
	if stableSide == "old" {
		if err := stableMayIsActor(oldActor); err != nil {
			return "", err
		}
		return oldActor, nil
	}
	if !journal.HelperChanged {
		newActor, err := verifiedRunningNewActor(journal.NewRelease, targetSourceCommit)
		if err != nil || stableMayMatchesActorBytes(newActor) != nil {
			return "", errors.New("stable may does not match the verified target actor")
		}
		return newActor, nil
	}
	helperSide, err := stableHelperSide(journal, oldReceipt)
	if err != nil {
		return "", err
	}
	// Recovery can crash after restoring the old helper but before the old link.
	if helperSide == "old" {
		// The operator target performs a pre-CF proof that stable new still has
		// its exact bytes. Once recovery has exec'd old (empty source commit), old
		// may must be able to finish the same rollback without claiming new's role.
		if targetSourceCommit != "" {
			newActor, err := verifiedRunningNewActor(journal.NewRelease, targetSourceCommit)
			if err != nil || stableMayMatchesActorBytes(newActor) != nil {
				return "", errors.New("stable may does not match the verified target actor")
			}
		}
		return oldActor, nil
	}
	newActor, err := verifiedRunningNewActor(journal.NewRelease, targetSourceCommit)
	if err != nil || stableMayMatchesActorBytes(newActor) != nil {
		return "", errors.New("stable may does not match the verified target actor")
	}
	return newActor, nil
}

func verifyStableHelperDigest(expectedDigest string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home for stable helper verification failed")
	}
	return verifyExecutableDigest(
		filepath.Join(home, userAgentDirectoryName, "libexec", keychainHelperBinaryName),
		expectedDigest,
	)
}

func verifyTransportRollbackMaterial(
	journal *transportUpdateJournal,
	receipt *localInstallReceipt,
) (string, error) {
	oldActor, err := verifiedInstalledMayActor(journal.OldRelease, receipt.Files["bin/may"])
	if err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve home for interrupted local rollback material failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	adapter := filepath.Join(root, "versions", journal.OldRelease, gitSignAdapterBinaryName)
	if err := verifyExecutableDigest(adapter, receipt.Files["bin/"+gitSignAdapterBinaryName]); err != nil {
		return "", errors.New("interrupted local update old signing adapter is unavailable")
	}
	if receipt.Skill.Version != journal.OldRelease {
		return "", errors.New("interrupted local update old Skill receipt differs from its rollback target")
	}
	skill := filepath.Join(root, "skill-versions", journal.OldRelease, "onenod")
	if digest, err := directoryTreeSHA256(skill); err != nil || digest != receipt.Skill.TreeSHA256 {
		return "", errors.New("interrupted local update old Skill is unavailable")
	}
	if journal.HelperChanged {
		helper := filepath.Join(
			root, "helper-versions", journal.OldHelperVersion, keychainHelperBinaryName,
		)
		if err := verifyExecutableDigest(helper, receipt.Helper.BinarySHA256); err != nil ||
			receipt.Helper.Version != journal.OldHelperVersion {
			return "", errors.New("interrupted local update old helper rollback source is unavailable")
		}
	}
	return oldActor, nil
}

func readImmutableLocalReceipt(version string) (*localInstallReceipt, error) {
	if !validProductVersion(version) {
		return nil, errors.New("immutable local receipt version is invalid")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("resolve home for immutable local receipt failed")
	}
	path := filepath.Join(home, userAgentDirectoryName, "receipt-versions", version+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("immutable local receipt is unsafe")
	}
	var receipt localInstallReceipt
	if err := readStrictPrivateJSON(path, &receipt); err != nil ||
		validateLocalInstallReceiptShape(&receipt) != nil || receipt.ReleaseVersion != version {
		return nil, errors.New("immutable local receipt is invalid")
	}
	return &receipt, nil
}

func verifiedInstalledMayActor(version, expectedDigest string) (string, error) {
	if !validProductVersion(version) || !digestPattern.MatchString(expectedDigest) {
		return "", errors.New("installed local update actor receipt is invalid")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve home for local update actor failed")
	}
	path := filepath.Join(home, userAgentDirectoryName, "versions", version, "may")
	if err := verifyExecutableDigest(path, expectedDigest); err != nil {
		return "", errors.New("installed local update actor differs from its immutable receipt")
	}
	return path, nil
}

func verifyExecutableDigest(path, expectedDigest string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 ||
		!digestPattern.MatchString(expectedDigest) {
		return errors.New("verified executable is missing or unsafe")
	}
	digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
	if err != nil || digest != expectedDigest {
		return errors.New("verified executable digest differs")
	}
	return nil
}

func verifiedRunningNewActor(version, expectedSourceCommit string) (string, error) {
	if productVersion != version || releaseTag != "v"+version ||
		!commitPattern.MatchString(sourceCommit) ||
		(expectedSourceCommit != "" && sourceCommit != expectedSourceCommit) {
		return "", errors.New("running updater is not the exact staged release required by the interrupted transaction")
	}
	path, err := currentLocalUpdateExecutable()
	if err != nil {
		return "", errors.New("resolve running staged local update actor failed")
	}
	actor, err := resolveLocalUpdateActor(path)
	if err != nil {
		return "", err
	}
	return actor.path, nil
}

func stableMayMatchesRelease(version string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home for stable local update actor failed")
	}
	target, err := os.Readlink(filepath.Join(home, userAgentDirectoryName, "bin", "may"))
	if err != nil || target != managedReleaseTargets(version, version)["may"] {
		return errors.New("stable may does not match the verified local install receipt")
	}
	return nil
}

func stableMayIsActor(expectedPath string) error {
	stable, expected, err := stableAndExpectedActors(expectedPath)
	if err != nil {
		return err
	}
	if !os.SameFile(stable.info, expected.info) {
		return errors.New("stable may does not resolve to the verified exact actor")
	}
	return nil
}

func stableMayMatchesActorBytes(expectedPath string) error {
	stable, expected, err := stableAndExpectedActors(expectedPath)
	if err != nil {
		return err
	}
	stableDigest, stableErr := regularFileSHA256(stable.path, maxReleaseArtifactBytes)
	expectedDigest, expectedErr := regularFileSHA256(expected.path, maxReleaseArtifactBytes)
	if stableErr != nil || expectedErr != nil || stableDigest != expectedDigest {
		return errors.New("stable may bytes differ from the verified target actor")
	}
	return nil
}

func stableAndExpectedActors(
	expectedPath string,
) (*resolvedLocalUpdateActor, *resolvedLocalUpdateActor, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, errors.New("resolve home for stable local update actor failed")
	}
	stable, err := resolveLocalUpdateActor(
		filepath.Join(home, userAgentDirectoryName, "bin", "may"),
	)
	if err != nil {
		return nil, nil, err
	}
	expected, err := resolveLocalUpdateActor(expectedPath)
	if err != nil {
		return nil, nil, err
	}
	return stable, expected, nil
}

func stableMayTargetSide(journal *transportUpdateJournal) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve home for stable local update actor failed")
	}
	target, err := os.Readlink(filepath.Join(home, userAgentDirectoryName, "bin", "may"))
	if err != nil {
		return "", errors.New("inspect stable may during local update handoff failed")
	}
	switch target {
	case journal.OldTargets["may"]:
		return "old", nil
	case journal.NewTargets["may"]:
		return "new", nil
	default:
		return "", errors.New("stable may does not match the interrupted local update")
	}
}

func stableHelperSide(journal *transportUpdateJournal, oldReceipt *localInstallReceipt) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve home for stable helper inspection failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	stablePath := filepath.Join(root, "libexec", keychainHelperBinaryName)
	stableInfo, err := os.Lstat(stablePath)
	if err != nil || !stableInfo.Mode().IsRegular() || stableInfo.Mode().Perm() != 0o700 {
		return "", errors.New("stable helper during local update handoff is unsafe")
	}
	stableDigest, err := regularFileSHA256(stablePath, maxReleaseArtifactBytes)
	if err != nil {
		return "", errors.New("inspect stable helper during local update handoff failed")
	}
	oldDigest := oldReceipt.Helper.BinarySHA256
	if stableDigest == oldDigest {
		return "old", nil
	}
	newPath := filepath.Join(root, "helper-versions", journal.NewHelperVersion, keychainHelperBinaryName)
	newInfo, err := os.Lstat(newPath)
	if err != nil || !newInfo.Mode().IsRegular() || newInfo.Mode().Perm() != 0o700 {
		return "", errors.New("interrupted local update new helper is unavailable or unsafe")
	}
	newDigest, err := regularFileSHA256(newPath, maxReleaseArtifactBytes)
	if err != nil || newDigest == oldDigest || stableDigest != newDigest {
		return "", errors.New("stable helper does not unambiguously match the interrupted new helper")
	}
	return "new", nil
}
