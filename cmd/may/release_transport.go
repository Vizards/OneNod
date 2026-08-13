package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func localReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for install receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "install.json"), nil
}

func initializerReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for initializer receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "initializer.json"), nil
}

func transportUpdateJournalPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for transport update journal failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "transport-update.json"), nil
}

func newTransportTransactionID() (string, error) {
	value := make([]byte, 24)
	if _, err := rand.Read(value); err != nil {
		return "", errors.New("generate transport update transaction failed")
	}
	defer zeroBytes(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func writeTransportUpdateJournal(journal transportUpdateJournal) error {
	path, err := transportUpdateJournalPath()
	if err != nil {
		return err
	}
	journal.SchemaVersion = transportJournalSchema
	if !validTransportUpdateJournal(journal) {
		return errors.New("refusing to write an invalid transport update journal")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home for transport update journal failed")
	}
	if err := ensurePrivateInstallDirectory(filepath.Join(home, userAgentDirectoryName)); err != nil {
		return err
	}
	return writeAtomicPrivateJSON(path, journal)
}

func readTransportUpdateJournal() (*transportUpdateJournal, bool, error) {
	path, err := transportUpdateJournalPath()
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("transport update journal is unsafe or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read transport update journal failed")
	}
	var journal transportUpdateJournal
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || ensureDecoderEOF(decoder) != nil ||
		!validTransportUpdateJournal(journal) {
		return nil, false, errors.New("transport update journal is invalid")
	}
	return &journal, true, nil
}

func validTransportUpdateJournal(journal transportUpdateJournal) bool {
	if journal.SchemaVersion != transportJournalSchema ||
		!transportTransactionPattern.MatchString(journal.TransactionID) ||
		!validProductVersion(journal.NewRelease) ||
		!validProductVersion(journal.OldRelease) ||
		journal.Origin == "" || journal.Slot == "" ||
		journal.NewHelperVersion == "" || journal.OldHelperVersion == "" {
		return false
	}
	switch journal.Phase {
	case "prepared", "staged", "promoting", "health_checked":
	default:
		return false
	}
	return sameStringMap(
		journal.OldTargets, managedReleaseTargets(journal.OldRelease, journal.OldRelease),
	) && sameStringMap(
		journal.NewTargets, managedReleaseTargets(journal.NewRelease, journal.NewRelease),
	)
}

func sameStringMap(first, second map[string]string) bool {
	if len(first) != len(second) {
		return false
	}
	for key, value := range second {
		if first[key] != value {
			return false
		}
	}
	return true
}

func removeTransportUpdateJournal() error {
	path, err := transportUpdateJournalPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove completed transport update journal failed")
	}
	return nil
}

// reconcileInterruptedTransportUpdate asks the exact helper state which side of
// the transaction is authoritative. A crash after commit keeps the new local
// state. A pre-commit crash has lost its one-time capability, so it restores the
// old exact helper, links, and receipt before the old may aborts the transaction.
func reconcileInterruptedTransportUpdate(deps dependencies) error {
	journal, found, err := readTransportUpdateJournal()
	if err != nil || !found {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home while reconciling transport update failed")
	}
	root := filepath.Join(home, userAgentDirectoryName)
	oldMay := filepath.Join(root, "versions", journal.OldRelease, "may")
	stableMay := filepath.Join(root, "bin", "may")
	stableTarget, linkErr := os.Readlink(stableMay)
	if linkErr != nil {
		return errors.New("inspect stable may during transport recovery failed")
	}
	// If promotion never switched may but did replace the helper, put the old
	// helper back before asking for authenticated status. This is determined only
	// from our private journal and managed symlink; helper authentication remains
	// the actual trust decision.
	if journal.HelperChanged && stableTarget == journal.OldTargets["may"] {
		if err := restoreTransportHelper(root, journal.OldRelease, journal.OldHelperVersion); err != nil {
			return err
		}
	}
	status, err := queryTransportUpdateStatus(journal.Origin, journal.Slot)
	if err != nil {
		return fmt.Errorf("authenticate interrupted exact-build state failed: %w", err)
	}
	if status.TransactionID != journal.TransactionID {
		if journal.Phase == "prepared" && status.TransactionState != "staged" {
			if err := removeTransportUpdateJournal(); err != nil {
				return err
			}
			return nil
		}
		return errors.New("interrupted exact-build state does not match its private journal")
	}
	if status.TransactionState == "committed" {
		if stableTarget != journal.NewTargets["may"] {
			return errors.New("committed exact-build state does not match the promoted may link")
		}
		if err := removeTransportUpdateJournal(); err != nil {
			return err
		}
		fmt.Fprintln(deps.stdout, "Recovered a committed OneNod exact-build update; the new local release remains active.")
		return nil
	}
	if status.TransactionState != "staged" && status.TransactionState != "aborted" {
		return errors.New("interrupted exact-build state is neither staged nor finalized")
	}
	if journal.HelperChanged {
		if err := restoreTransportHelper(root, journal.OldRelease, journal.OldHelperVersion); err != nil {
			return err
		}
	}
	for name, path := range map[string]string{
		"may":                    stableMay,
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		if err := replaceStableSymlink(path, journal.OldTargets[name]); err != nil {
			return fmt.Errorf("restore %s during transport recovery failed: %w", name, err)
		}
	}
	if journal.OldRelease != "" {
		oldReceiptPath := filepath.Join(root, "receipt-versions", journal.OldRelease+".json")
		oldReceipt, exists, readErr := readOptionalRegularFile(oldReceiptPath, maxManifestBytes)
		if readErr != nil || !exists {
			return errors.New("transport recovery has no immutable old receipt")
		}
		receiptPath, pathErr := localReceiptPath()
		if pathErr != nil || writeAtomicUserConfig(receiptPath, oldReceipt, 0o600) != nil {
			return errors.New("restore old install receipt during transport recovery failed")
		}
	}
	if status.TransactionState == "staged" {
		if err := runTransportUpdateAbort(
			oldMay, journal.Origin, journal.Slot, journal.TransactionID,
		); err != nil {
			return fmt.Errorf("abort interrupted exact-build transport update failed: %w", err)
		}
	}
	plan := &userCLIInstallPlan{
		binaryPath:      stableMay,
		adapterPath:     filepath.Join(root, "bin", gitSignAdapterBinaryName),
		launchAgentPath: filepath.Join(home, "Library", "LaunchAgents", oneNodAgentLabel+".plist"),
		socketPath:      filepath.Join(root, "agent.sock"),
	}
	if err := restartTransportAgent(plan); err != nil {
		return errors.New("restart prior may SSH Agent during transport recovery failed")
	}
	if err := removeTransportUpdateJournal(); err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Recovered an interrupted OneNod exact-build update by restoring the prior local release.")
	return nil
}

func restoreTransportHelper(root, releaseVersion, helperVersion string) error {
	receiptPath := filepath.Join(root, "receipt-versions", releaseVersion+".json")
	encoded, exists, err := readOptionalRegularFile(receiptPath, maxManifestBytes)
	if err != nil || !exists {
		return errors.New("transport recovery has no immutable helper receipt")
	}
	var receipt localInstallReceipt
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || ensureDecoderEOF(decoder) != nil ||
		receipt.ReleaseVersion != releaseVersion || receipt.Helper.Version != helperVersion ||
		!digestPattern.MatchString(receipt.Helper.BinarySHA256) {
		return errors.New("transport recovery helper receipt is invalid")
	}
	source := filepath.Join(root, "helper-versions", helperVersion, keychainHelperBinaryName)
	digest, err := regularFileSHA256(source, maxReleaseArtifactBytes)
	if err != nil || digest != receipt.Helper.BinarySHA256 {
		return errors.New("transport recovery helper differs from its immutable receipt")
	}
	if err := replaceStableRegularFile(filepath.Join(root, "libexec", keychainHelperBinaryName), source); err != nil {
		return errors.New("restore prior exact-build Keychain helper failed")
	}
	return nil
}

// These narrow lifecycle adapters are intentionally implemented here rather
// than exposing transport mutation as a user command. The helper client owns
// the wire protocol; the verified release installer is the only caller.
var abortTransportUpdate = abortTransportUpdateWithHelper

var (
	queryTransportUpdateStatus = queryTransportHelperStatus
	runTransportUpdateAbort    = runCurrentTransportAbort
	restartTransportAgent      = activateApprovalAgent
	stageVerifiedTransport     = stageTransportUpdateExpected
	abortStagedTransport       = abortTransportUpdateWithHelper
)

func readInitializerInstallReceipt() (*initializerInstallReceipt, bool, error) {
	path, err := initializerReceiptPath()
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("initializer receipt is unsafe or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read initializer receipt failed")
	}
	var receipt initializerInstallReceipt
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || ensureDecoderEOF(decoder) != nil ||
		receipt.SchemaVersion != initializerReceiptSchema ||
		!validProductVersion(receipt.ReleaseVersion) || !commitPattern.MatchString(receipt.SourceCommit) ||
		len(receipt.Artifacts) != 3 || len(receipt.Files) != 3 ||
		receipt.HelperProtocol <= 0 || receipt.HelperVersion == "" ||
		!digestPattern.MatchString(receipt.SkillTreeSHA) {
		return nil, false, errors.New("initializer receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return nil, false, errors.New("initializer receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	for _, digest := range receipt.Artifacts {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("initializer receipt contains an invalid artifact digest")
		}
	}
	for _, digest := range receipt.Files {
		if !digestPattern.MatchString(digest) {
			return nil, false, errors.New("initializer receipt contains an invalid file digest")
		}
	}
	home, homeErr := os.UserHomeDir()
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, backup := range receipt.AdoptedBackups {
		relative, relativeErr := filepath.Rel(backupRoot, backup)
		if homeErr != nil || relativeErr != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, false, errors.New("initializer receipt contains an unsafe Skill adoption backup")
		}
	}
	return &receipt, true, nil
}

func readLocalInstallReceipt() (*localInstallReceipt, bool, error) {
	path, err := localReceiptPath()
	if err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return nil, false, errors.New("local OneNod install receipt is unsafe or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, false, errors.New("read local OneNod install receipt failed")
	}
	var receipt localInstallReceipt
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || ensureDecoderEOF(decoder) != nil {
		return nil, false, errors.New("local OneNod install receipt is invalid")
	}
	if err := validateLocalInstallReceiptShape(&receipt); err != nil {
		return nil, false, err
	}
	return &receipt, true, nil
}

func validateLocalInstallReceiptShape(receipt *localInstallReceipt) error {
	if receipt == nil || receipt.SchemaVersion != localReceiptSchema ||
		!validProductVersion(receipt.ReleaseVersion) ||
		!commitPattern.MatchString(receipt.SourceCommit) {
		return errors.New("local OneNod install receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return errors.New("local OneNod install receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	if parsed, err := parseGatewayOrigin(receipt.Origin); err != nil || parsed.String() != receipt.Origin {
		return errors.New("local OneNod install receipt Origin is invalid")
	}
	localName, localErr := localArtifactName()
	if localErr != nil || len(receipt.Artifacts) != 3 ||
		receipt.Artifacts[localName] == "" ||
		receipt.Skill.Artifact != skillArtifactName(receipt.ReleaseVersion) ||
		receipt.Skill.Version != receipt.ReleaseVersion ||
		strings.Join(receipt.Skill.Discovery, ",") != "~/.agents/skills/onenod,~/.claude/skills/onenod" ||
		receipt.Artifacts[receipt.Skill.Artifact] != receipt.Skill.ArtifactSHA ||
		receipt.Helper.Artifact == "" ||
		receipt.Artifacts[receipt.Helper.Artifact] != receipt.Helper.ArtifactSHA ||
		receipt.Helper.Version == "" || receipt.Helper.Protocol <= 0 ||
		!digestPattern.MatchString(receipt.Helper.SourceDigest) ||
		len(receipt.Files) != 2 || receipt.Files["bin/may"] == "" ||
		receipt.Files["bin/"+gitSignAdapterBinaryName] == "" ||
		!validExactBuildRuntimeIdentity(receipt.ExactCodeIdentities.May) ||
		!validExactBuildRuntimeIdentity(receipt.ExactCodeIdentities.MaySSHSign) ||
		!validExactBuildRuntimeIdentity(receipt.ExactCodeIdentities.Helper) {
		return errors.New("local OneNod install receipt has an incomplete component shape")
	}
	for _, digest := range receipt.Artifacts {
		if !digestPattern.MatchString(digest) {
			return errors.New("local OneNod install receipt contains an invalid digest")
		}
	}
	for _, digest := range []string{
		receipt.Helper.ArtifactSHA, receipt.Helper.BinarySHA256,
		receipt.Helper.SourceDigest,
		receipt.Skill.ArtifactSHA, receipt.Skill.TreeSHA256,
		receipt.Files["bin/may"], receipt.Files["bin/"+gitSignAdapterBinaryName],
	} {
		if !digestPattern.MatchString(digest) {
			return errors.New("local OneNod install receipt contains an invalid component digest")
		}
	}
	home, homeErr := os.UserHomeDir()
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, backup := range receipt.Skill.AdoptedBackups {
		relative, err := filepath.Rel(backupRoot, backup)
		if homeErr != nil || err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("local OneNod install receipt contains an unsafe Skill adoption backup")
		}
	}
	return nil
}

func writeLocalInstallReceipt(path string, receipt localInstallReceipt) error {
	receipt.SchemaVersion = localReceiptSchema
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	receipt.Channel = string(channel)
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return errors.New("encode local OneNod install receipt failed")
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	staged, err := os.CreateTemp(directory, ".install-receipt-")
	if err != nil {
		return errors.New("stage local OneNod install receipt failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := staged.Chmod(0o600); err != nil {
		staged.Close()
		return errors.New("secure local OneNod install receipt failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write local OneNod install receipt failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("activate local OneNod install receipt failed")
	}
	return nil
}
