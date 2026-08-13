package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

func preserveImmutableReceipt(receipt localInstallReceipt) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home for immutable install receipt failed")
	}
	directory := filepath.Join(home, userAgentDirectoryName, "receipt-versions")
	if err := ensurePrivateInstallDirectory(directory); err != nil {
		return err
	}
	path := filepath.Join(directory, receipt.ReleaseVersion+".json")
	if encoded, exists, err := readOptionalRegularFile(path, maxManifestBytes); err != nil {
		return err
	} else if exists {
		var current localInstallReceipt
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&current) != nil || ensureDecoderEOF(decoder) != nil ||
			current.ReleaseVersion != receipt.ReleaseVersion ||
			current.SourceCommit != receipt.SourceCommit {
			return errors.New("immutable install receipt differs from the exact Release")
		}
		return nil
	}
	return writeAtomicPrivateJSON(path, receipt)
}

func managedReleaseTargets(version, skillVersion string) map[string]string {
	return map[string]string{
		"may": filepath.Join("..", "versions", version, "may"),
		gitSignAdapterBinaryName: filepath.Join(
			"..", "versions", version, gitSignAdapterBinaryName,
		),
		"skill": filepath.Join("skill-versions", skillVersion, "onenod"),
	}
}

func installVersionDirectory(destination string, sources map[string]string) error {
	if info, err := os.Stat(destination); err == nil && info.IsDir() {
		entries, err := os.ReadDir(destination)
		if err != nil || len(entries) != len(sources) {
			return errors.New("existing version directory does not exactly match the verified release")
		}
		for name, source := range sources {
			target := filepath.Join(destination, name)
			fileInfo, err := os.Lstat(target)
			if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 ||
				fileInfo.Mode().Perm() != 0o700 {
				return errors.New("existing version directory is incomplete or unsafe")
			}
			sourceDigest, err := regularFileSHA256(source, maxReleaseArtifactBytes)
			if err != nil {
				return err
			}
			targetDigest, err := regularFileSHA256(target, maxReleaseArtifactBytes)
			if err != nil || targetDigest != sourceDigest {
				return errors.New("existing version directory bytes differ from the verified release")
			}
		}
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect version directory failed")
	}
	parent := filepath.Dir(destination)
	stage, err := os.MkdirTemp(parent, ".version-")
	if err != nil {
		return errors.New("stage version directory failed")
	}
	defer os.RemoveAll(stage)
	for name, source := range sources {
		target := filepath.Join(stage, name)
		input, err := os.Open(source)
		if err != nil {
			return errors.New("open verified release binary failed")
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
		if err != nil {
			input.Close()
			return errors.New("stage verified release binary failed")
		}
		_, copyErr := io.Copy(output, io.LimitReader(input, maxReleaseArtifactBytes+1))
		input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil {
			return errors.New("copy verified release binary failed")
		}
	}
	if err := os.Rename(stage, destination); err != nil {
		return errors.New("activate immutable version directory failed")
	}
	return nil
}

func installTreeDirectory(destination, source string) error {
	sourceDigest, err := directoryTreeSHA256(source)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("existing Skill version path is unsafe")
		}
		destinationDigest, err := directoryTreeSHA256(destination)
		if err != nil || destinationDigest != sourceDigest {
			return errors.New("existing Skill version bytes differ from the verified release")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect Skill version directory failed")
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errors.New("create Skill version parent failed")
	}
	stage, err := os.MkdirTemp(parent, ".skill-")
	if err != nil {
		return errors.New("stage Skill version failed")
	}
	defer os.RemoveAll(stage)
	if err := copyRegularTree(source, stage); err != nil {
		return err
	}
	if err := os.Rename(stage, destination); err != nil {
		return errors.New("activate immutable Skill version failed")
	}
	return nil
}

func copyRegularTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk verified Skill tree failed")
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("verified Skill tree contains a symlink")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("verified Skill tree contains a non-regular file")
		}
		input, err := os.Open(path)
		if err != nil {
			return errors.New("open verified Skill file failed")
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			input.Close()
			return errors.New("stage verified Skill file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, maxReleaseArtifactBytes+1))
		input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != info.Size() {
			return errors.New("copy verified Skill file failed")
		}
		return nil
	})
}

func regularFileSHA256(path string, limit int64) (string, error) {
	value, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func directoryTreeSHA256(root string) (string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("tree contains a symlink")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReleaseArtifactBytes {
				return errors.New("tree contains an unsafe file")
			}
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil || len(paths) == 0 || len(paths) > 4096 {
		return "", errors.New("inspect verified tree failed")
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		relative, _ := filepath.Rel(root, path)
		digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
		if err != nil {
			return "", err
		}
		_, _ = io.WriteString(hash, filepath.ToSlash(relative))
		_, _ = hash.Write([]byte{0})
		_, _ = io.WriteString(hash, digest)
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func installedHelperMatchesReceipt(receipt *localInstallReceipt, helper keychainHelperResponse) bool {
	if receipt == nil || receipt.Helper.Version != helper.Version ||
		receipt.Helper.Protocol != helper.Protocol || receipt.Helper.Artifact == "" ||
		!digestPattern.MatchString(receipt.Helper.ArtifactSHA) ||
		!digestPattern.MatchString(receipt.Helper.BinarySHA256) {
		return false
	}
	path, err := installedKeychainHelperPath()
	if err != nil {
		return false
	}
	digest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
	return err == nil && digest == receipt.Helper.BinarySHA256 &&
		receipt.Artifacts[receipt.Helper.Artifact] == receipt.Helper.ArtifactSHA
}

func helperMatchesRelease(
	release *verifiedRelease,
	receipt *localInstallReceipt,
	helper keychainHelperResponse,
) bool {
	if release == nil || receipt == nil ||
		helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		receipt.Helper.Version != release.Manifest.Components.KeychainHelper.Version ||
		receipt.Helper.SourceDigest != release.Manifest.Components.KeychainHelper.SourceDigest ||
		!protocolContains(release.Manifest.Components.KeychainHelper.HelperProtocol, helper.Protocol) ||
		!installedHelperMatchesReceipt(receipt, helper) {
		return false
	}
	name, err := helperArtifactName(release.Manifest.Components.KeychainHelper.Version)
	if err != nil || receipt.Helper.Artifact != name {
		return false
	}
	artifact, err := artifactFor(release, name)
	return err == nil && artifact.SHA256 == receipt.Helper.ArtifactSHA
}

func replaceStableSymlink(path, target string) error {
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to replace unmanaged non-symlink path %s", path)
		}
		oldTarget, err := os.Readlink(path)
		home, homeErr := os.UserHomeDir()
		managedRoot := filepath.Join(home, userAgentDirectoryName)
		resolved := filepath.Clean(filepath.Join(filepath.Dir(path), oldTarget))
		relative, relativeErr := filepath.Rel(managedRoot, resolved)
		if err != nil || homeErr != nil || filepath.IsAbs(oldTarget) || relativeErr != nil ||
			relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return fmt.Errorf("refusing to replace unsafe managed symlink %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect stable OneNod path failed")
	}
	directory := filepath.Dir(path)
	temporary := filepath.Join(directory, ".link-"+filepath.Base(path)+"-new")
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return errors.New("stage stable OneNod path failed")
	}
	defer os.Remove(temporary)
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("activate stable OneNod path failed")
	}
	return nil
}

type managedSymlinkSnapshot struct {
	Exists bool
	Path   string
	Target string
}

type managedFileSnapshot struct {
	Content []byte
	Exists  bool
	Mode    os.FileMode
	Path    string
}

func captureManagedFiles(paths []string) ([]managedFileSnapshot, error) {
	result := make([]managedFileSnapshot, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, managedFileSnapshot{Path: path})
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Size() <= 0 || info.Size() > maxManifestBytes {
			return nil, fmt.Errorf("managed file %s is unsafe", path)
		}
		content, err := readBoundedRegularFile(path, maxManifestBytes)
		if err != nil {
			return nil, fmt.Errorf("capture managed file %s failed", path)
		}
		result = append(result, managedFileSnapshot{
			Content: content, Exists: true, Mode: info.Mode().Perm(), Path: path,
		})
	}
	return result, nil
}

func restoreManagedFiles(snapshots []managedFileSnapshot) error {
	var failures []error
	for _, snapshot := range snapshots {
		if !snapshot.Exists {
			if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				failures = append(failures, fmt.Errorf("remove newly created managed file %s failed", snapshot.Path))
			}
			continue
		}
		if err := writeAtomicUserConfig(snapshot.Path, snapshot.Content, snapshot.Mode); err != nil {
			failures = append(failures, fmt.Errorf("restore managed file %s failed: %w", snapshot.Path, err))
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

func captureManagedSymlinks(paths []string) ([]managedSymlinkSnapshot, error) {
	result := make([]managedSymlinkSnapshot, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, managedSymlinkSnapshot{Path: path})
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return nil, fmt.Errorf("managed path %s is occupied by non-OneNod content", path)
		}
		target, err := os.Readlink(path)
		if err != nil {
			return nil, errors.New("read managed symlink before activation failed")
		}
		result = append(result, managedSymlinkSnapshot{Exists: true, Path: path, Target: target})
	}
	return result, nil
}

func restoreManagedSymlinks(snapshots []managedSymlinkSnapshot) error {
	for _, snapshot := range snapshots {
		if err := os.Remove(snapshot.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove promoted managed symlink failed")
		}
		if !snapshot.Exists {
			continue
		}
		if err := os.Symlink(snapshot.Target, snapshot.Path); err != nil {
			return errors.New("restore prior managed symlink failed")
		}
	}
	return nil
}

type skillDiscoveryChange struct {
	Backup string
	Path   string
}

type skillDiscoveryTransaction struct {
	changes []skillDiscoveryChange
}

func (transaction *skillDiscoveryTransaction) rollback() error {
	if transaction == nil {
		return nil
	}
	for index := len(transaction.changes) - 1; index >= 0; index-- {
		change := transaction.changes[index]
		if err := os.Remove(change.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove managed Skill discovery link during rollback failed")
		}
		if change.Backup != "" {
			if err := os.Rename(change.Backup, change.Path); err != nil {
				return errors.New("restore adopted Skill during rollback failed")
			}
		}
	}
	return nil
}

func (transaction *skillDiscoveryTransaction) backupPaths() []string {
	var result []string
	if transaction == nil {
		return result
	}
	for _, change := range transaction.changes {
		if change.Backup != "" {
			result = append(result, change.Backup)
		}
	}
	return result
}

func installSkillDiscoveryLinks(
	home, stableSkill, expectedTreeDigest string,
) ([]string, *skillDiscoveryTransaction, error) {
	entries := []string{"~/.agents/skills/onenod", "~/.claude/skills/onenod"}
	type candidate struct {
		adopt bool
		path  string
	}
	var candidates []candidate
	for _, entry := range entries {
		path := filepath.Join(home, strings.TrimPrefix(entry, "~/"))
		if err := ensureSkillDiscoveryDirectory(home, filepath.Dir(path)); err != nil {
			return nil, nil, err
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			candidates = append(candidates, candidate{path: path})
			continue
		}
		if err != nil {
			return nil, nil, errors.New("inspect managed Skill discovery path failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil, nil, errors.New("read existing Skill discovery link failed")
			}
			resolved := target
			if !filepath.IsAbs(resolved) {
				resolved = filepath.Join(filepath.Dir(path), resolved)
			}
			resolved = filepath.Clean(resolved)
			if resolved == filepath.Clean(stableSkill) {
				continue
			}
			digest, err := directoryTreeSHA256(resolved)
			if (err != nil || digest != expectedTreeDigest) && !isRecognizableOneNodBootstrapSkill(resolved) {
				return nil, nil, fmt.Errorf("Skill discovery path %s points to different content; refusing to overwrite it", path)
			}
			candidates = append(candidates, candidate{adopt: true, path: path})
			continue
		}
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("Skill discovery path %s is occupied by non-directory content", path)
		}
		digest, err := directoryTreeSHA256(path)
		if (err != nil || digest != expectedTreeDigest) && !isRecognizableOneNodBootstrapSkill(path) {
			return nil, nil, fmt.Errorf("Skill discovery path %s differs from the verified OneNod Skill; refusing to overwrite it", path)
		}
		candidates = append(candidates, candidate{adopt: true, path: path})
	}
	transaction := &skillDiscoveryTransaction{}
	rollbackFailure := func(cause error) ([]string, *skillDiscoveryTransaction, error) {
		if err := transaction.rollback(); err != nil {
			return nil, nil, fmt.Errorf("%w; discovery rollback also failed: %v", cause, err)
		}
		return nil, nil, cause
	}
	backupRoot := filepath.Join(home, userAgentDirectoryName, "skill-adoption-backups")
	for _, candidate := range candidates {
		change := skillDiscoveryChange{Path: candidate.path}
		if candidate.adopt {
			if err := ensurePrivateInstallDirectory(backupRoot); err != nil {
				return rollbackFailure(err)
			}
			id, err := newUUIDv4()
			if err != nil {
				return rollbackFailure(err)
			}
			change.Backup = filepath.Join(backupRoot, id)
			if err := os.Rename(candidate.path, change.Backup); err != nil {
				return rollbackFailure(errors.New("move recognized OneNod bootstrap Skill to private adoption backup failed"))
			}
		}
		relative, err := filepath.Rel(filepath.Dir(candidate.path), stableSkill)
		if err != nil || filepath.IsAbs(relative) {
			if change.Backup != "" {
				_ = os.Rename(change.Backup, candidate.path)
			}
			return rollbackFailure(errors.New("derive managed Skill discovery link failed"))
		}
		if err := os.Symlink(relative, candidate.path); err != nil {
			if change.Backup != "" {
				_ = os.Rename(change.Backup, candidate.path)
			}
			return rollbackFailure(errors.New("activate managed Skill discovery link failed"))
		}
		transaction.changes = append(transaction.changes, change)
	}
	return entries, transaction, nil
}

func isRecognizableOneNodBootstrapSkill(root string) bool {
	path := filepath.Join(root, "SKILL.md")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maxManifestBytes {
		return false
	}
	content, err := readBoundedRegularFile(path, maxManifestBytes)
	if err != nil || !bytes.HasPrefix(content, []byte("---\n")) {
		return false
	}
	frontmatterEnd := bytes.Index(content[len("---\n"):], []byte("\n---\n"))
	if frontmatterEnd < 0 {
		return false
	}
	frontmatter := string(content[len("---\n") : len("---\n")+frontmatterEnd])
	nameIsOneNod := false
	for _, line := range strings.Split(frontmatter, "\n") {
		if strings.TrimSpace(line) == "name: onenod" {
			nameIsOneNod = true
			break
		}
	}
	return nameIsOneNod && bytes.Contains(content, []byte("https://github.com/Vizards/OneNod"))
}

func ensureSkillDiscoveryDirectory(home, path string) error {
	relative, err := filepath.Rel(home, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Skill discovery directory is outside the current user home")
	}
	current := home
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return errors.New("create Skill discovery directory failed")
			}
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("Skill discovery parent must be a directory, not a symlink")
		}
	}
	return nil
}

func replaceStableRegularFile(path, source string) error {
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 ||
			existing.Mode().Perm()&0o022 != 0 {
			return errors.New("refusing to replace an unsafe Keychain helper path")
		}
		existingDigest, existingDigestErr := regularFileSHA256(path, maxReleaseArtifactBytes)
		sourceDigest, sourceDigestErr := regularFileSHA256(source, maxReleaseArtifactBytes)
		if existingDigestErr != nil || sourceDigestErr != nil {
			return errors.New("hash Keychain helper before activation failed")
		}
		if existingDigest == sourceDigest {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("inspect stable Keychain helper path failed")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".helper-")
	if err != nil {
		return errors.New("stage stable Keychain helper failed")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	input, err := os.Open(source)
	if err != nil {
		temporary.Close()
		return errors.New("open verified Keychain helper failed")
	}
	written, copyErr := io.Copy(temporary, io.LimitReader(input, maxReleaseArtifactBytes+1))
	input.Close()
	if copyErr != nil || written <= 0 || written > maxReleaseArtifactBytes ||
		temporary.Chmod(0o700) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("stage verified Keychain helper failed")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("activate stable Keychain helper failed")
	}
	return nil
}

type helperReplacement struct {
	Changed        bool
	Path           string
	PreviousExists bool
	PreviousSource string
}

func activateStableHelper(path, source string, previous *localInstallReceipt) (*helperReplacement, error) {
	sourceDigest, err := regularFileSHA256(source, maxReleaseArtifactBytes)
	if err != nil {
		return nil, errors.New("hash verified Keychain helper failed")
	}
	transaction := &helperReplacement{Path: path}
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		if err := replaceStableRegularFile(path, source); err != nil {
			return nil, err
		}
		transaction.Changed = true
		return transaction, nil
	}
	if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("refusing to replace an unsafe Keychain helper path")
	}
	existingDigest, err := regularFileSHA256(path, maxReleaseArtifactBytes)
	if err != nil {
		return nil, errors.New("hash installed Keychain helper failed")
	}
	if existingDigest == sourceDigest {
		return transaction, nil
	}
	if previous == nil || existingDigest != previous.Helper.BinarySHA256 {
		return nil, errors.New("installed Keychain helper differs from the verified source and has no exact rollback receipt")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("resolve Keychain helper rollback source failed")
	}
	rollbackSource := filepath.Join(home, userAgentDirectoryName, "helper-versions", previous.Helper.Version, keychainHelperBinaryName)
	rollbackDigest, err := regularFileSHA256(rollbackSource, maxReleaseArtifactBytes)
	if err != nil || rollbackDigest != previous.Helper.BinarySHA256 {
		return nil, errors.New("prior Keychain helper rollback source differs from its receipt")
	}
	if err := replaceStableRegularFile(path, source); err != nil {
		return nil, err
	}
	transaction.Changed = true
	transaction.PreviousExists = true
	transaction.PreviousSource = rollbackSource
	return transaction, nil
}

func (replacement *helperReplacement) rollback() error {
	if replacement == nil || !replacement.Changed {
		return nil
	}
	if !replacement.PreviousExists {
		if err := os.Remove(replacement.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("remove newly activated Keychain helper failed")
		}
		return nil
	}
	if err := replaceStableRegularFile(replacement.Path, replacement.PreviousSource); err != nil {
		return errors.New("restore prior Keychain helper failed")
	}
	return nil
}

func installOriginAndLaunchAgent(root, origin, home string) error {
	envPath := filepath.Join(root, userAgentEnvFileName)
	if existing, err := readInstalledUserOrigin(envPath); err != nil {
		return err
	} else if existing != "" && existing != origin {
		return errors.New("refusing to change an installed OneNod Origin")
	}
	envStage, err := os.CreateTemp(root, ".env-")
	if err != nil {
		return errors.New("stage installed OneNod Origin failed")
	}
	envStagePath := envStage.Name()
	defer os.Remove(envStagePath)
	if err := envStage.Chmod(0o600); err != nil {
		envStage.Close()
		return errors.New("secure installed OneNod Origin failed")
	}
	if _, err := io.WriteString(envStage, userAgentOriginKey+"="+origin+"\n"); err != nil ||
		envStage.Sync() != nil || envStage.Close() != nil {
		return errors.New("write installed OneNod Origin failed")
	}
	if err := os.Rename(envStagePath, envPath); err != nil {
		return errors.New("activate installed OneNod Origin failed")
	}
	launchDirectory := filepath.Join(home, "Library", "LaunchAgents")
	if err := ensureLaunchAgentDirectory(launchDirectory); err != nil {
		return err
	}
	launchPath := filepath.Join(launchDirectory, oneNodAgentLabel+".plist")
	staged, err := os.CreateTemp(launchDirectory, ".onenod-agent-")
	if err != nil {
		return errors.New("stage OneNod LaunchAgent failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if err := staged.Chmod(0o600); err != nil {
		staged.Close()
		return errors.New("secure OneNod LaunchAgent failed")
	}
	plist := renderApprovalAgentPlist(filepath.Join(root, "bin", "may"), filepath.Join(root, "logs"))
	if _, err := io.WriteString(staged, plist); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write OneNod LaunchAgent failed")
	}
	if err := os.Rename(stagedPath, launchPath); err != nil {
		return errors.New("activate OneNod LaunchAgent failed")
	}
	return nil
}

func checkExternalTool(name string, requirement versionRange, capabilityArgs [][]string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("required external tool %s is not installed", name)
	}
	command := exec.Command(path, "--version")
	command.Env = operatorEnvironment(nil)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("required external tool %s cannot report its version", name)
	}
	version := firstStableVersion(string(output))
	zeroBytes(output)
	if version == "" || compareVersions(version, requirement.Minimum) < 0 ||
		(requirement.MaximumExclusive != "" && compareVersions(version, requirement.MaximumExclusive) >= 0) {
		return "", fmt.Errorf("%s version %q is outside supported range [%s, %s)",
			name, version, requirement.Minimum, requirement.MaximumExclusive)
	}
	for _, arguments := range capabilityArgs {
		command := exec.Command(path, arguments...)
		command.Env = operatorEnvironment(nil)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return "", fmt.Errorf("%s lacks required capability %s", name, strings.Join(arguments, " "))
		}
	}
	return path, nil
}

func firstStableVersion(output string) string {
	search := regexp.MustCompile(`(?:^|[^0-9])([0-9]+\.[0-9]+\.[0-9]+)(?:[^0-9]|$)`)
	match := search.FindStringSubmatch(output)
	if len(match) != 2 || !validStableVersion(match[1]) {
		return ""
	}
	return match[1]
}

func promptYesNo(input io.Reader, output io.Writer, prompt string, defaultYes bool) (bool, error) {
	if file, ok := input.(*os.File); ok {
		info, err := file.Stat()
		if err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return false, errors.New("security confirmation requires an interactive terminal")
		}
	}
	suffix := "[y/N]"
	if defaultYes {
		suffix = "[Y/n]"
	}
	fmt.Fprintf(output, "%s %s ", prompt, suffix)
	line, err := readPromptLine(input)
	if err != nil {
		return false, errors.New("read security confirmation failed")
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer == "" {
		return defaultYes, nil
	}
	if answer == "y" || answer == "yes" {
		return true, nil
	}
	if answer == "n" || answer == "no" {
		return false, nil
	}
	return false, errors.New("confirmation must be y or n")
}

func readPromptLine(input io.Reader) (string, error) {
	if input == nil {
		return "", io.EOF
	}
	var line strings.Builder
	var next [1]byte
	for {
		count, err := input.Read(next[:])
		if count == 1 {
			if next[0] == '\n' {
				return line.String(), nil
			}
			line.WriteByte(next[0])
		}
		if err != nil {
			return line.String(), err
		}
		if count == 0 {
			return line.String(), io.ErrNoProgress
		}
	}
}

func sortedArtifactNames(manifest releaseManifest) []string {
	names := make([]string, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		names = append(names, artifact.Name)
	}
	sort.Strings(names)
	return names
}
