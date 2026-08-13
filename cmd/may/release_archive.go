package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

func artifactFor(release *verifiedRelease, name string) (releaseArtifact, error) {
	for _, artifact := range release.Manifest.Artifacts {
		if artifact.Name == name {
			return artifact, nil
		}
	}
	return releaseArtifact{}, fmt.Errorf("verified release does not contain required artifact %q", name)
}

func localArtifactName() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("OneNod requester binaries support macOS only")
	}
	switch runtime.GOARCH {
	case "arm64", "amd64":
		return fmt.Sprintf("onenod-darwin-%s.tar.gz", runtime.GOARCH), nil
	default:
		return "", fmt.Errorf("unsupported macOS architecture %s", runtime.GOARCH)
	}
}

func helperArtifactName(version string) (string, error) {
	if _, err := localArtifactName(); err != nil {
		return "", err
	}
	return fmt.Sprintf("onenod-keychain-helper-%s-darwin-%s.tar.gz", version, runtime.GOARCH), nil
}

func skillArtifactName(version string) string {
	return fmt.Sprintf("onenod-skill-%s.tar.gz", version)
}

func deploymentArtifactName(version string) string {
	return fmt.Sprintf("onenod-deployment-%s.tar.gz", version)
}

func privateStagingDirectory() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for release staging failed")
	}
	root := filepath.Join(home, userAgentDirectoryName, "update")
	if err := ensurePrivateInstallDirectory(filepath.Join(home, userAgentDirectoryName)); err != nil {
		return "", err
	}
	if err := ensurePrivateInstallDirectory(root); err != nil {
		return "", err
	}
	return os.MkdirTemp(root, ".stage-")
}

func downloadVerifiedArtifact(
	ctx context.Context,
	release *verifiedRelease,
	artifact releaseArtifact,
) ([]byte, error) {
	if release == nil || release.Source == nil {
		return nil, errors.New("verified release source is unavailable")
	}
	snapshot, err := release.Source.Download(ctx, release, artifact)
	if err != nil {
		return nil, err
	}
	if int64(len(snapshot)) != artifact.Size || int64(len(snapshot)) > maxReleaseArtifactBytes {
		return nil, errors.New("authenticated release artifact snapshot has an invalid size")
	}
	digest := sha256.Sum256(snapshot)
	if "sha256:"+hex.EncodeToString(digest[:]) != artifact.SHA256 {
		return nil, errors.New("authenticated release artifact snapshot digest changed")
	}
	return snapshot, nil
}

func extractReleaseArchiveSnapshot(
	snapshot []byte,
	destination string,
	allowed map[string]os.FileMode,
) error {
	if len(snapshot) == 0 || int64(len(snapshot)) > maxReleaseArtifactBytes {
		return errors.New("authenticated release artifact snapshot is empty or oversized")
	}
	return extractReleaseArchiveReader(bytes.NewReader(snapshot), destination, allowed)
}

func authenticatedArchiveFile(snapshot []byte, wanted string, limit int64) ([]byte, error) {
	if len(snapshot) == 0 || int64(len(snapshot)) > maxReleaseArtifactBytes {
		return nil, errors.New("authenticated release artifact snapshot is empty or oversized")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(snapshot))
	if err != nil {
		return nil, errors.New("authenticated release artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	var found []byte
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("read authenticated release artifact failed")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return nil, errors.New("authenticated release artifact contains an unsafe path")
		}
		if clean != wanted {
			continue
		}
		if found != nil || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > limit {
			return nil, errors.New("authenticated release descriptor is duplicate or invalid")
		}
		found, err = io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil || int64(len(found)) != header.Size {
			return nil, errors.New("read authenticated release descriptor failed")
		}
	}
	if found == nil {
		return nil, errors.New("authenticated release descriptor is missing")
	}
	return found, nil
}

func decodeAuthenticatedArchiveJSON(snapshot []byte, path string, target any) error {
	encoded, err := authenticatedArchiveFile(snapshot, path, maxManifestBytes)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("authenticated release descriptor is invalid")
	}
	return nil
}

func extractReleaseArchiveReader(
	input io.Reader,
	destination string,
	allowed map[string]os.FileMode,
) error {
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return errors.New("verified release artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open release extraction root failed")
	}
	defer root.Close()
	seen := map[string]struct{}{}
	var totalBytes int64
	entryCount := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified release archive failed")
		}
		entryCount++
		if entryCount > 4096 {
			return errors.New("verified release archive contains too many entries")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified release archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified release archive contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes {
			return fmt.Errorf("verified release archive entry %q exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified release archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		mode, required := allowed[clean]
		if !required {
			continue
		}
		if header.Size <= 0 {
			return fmt.Errorf("verified release archive entry %q is not a bounded regular file", clean)
		}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create release extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return errors.New("create extracted release file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified release file failed")
		}
	}
	for path := range allowed {
		if _, ok := seen[path]; !ok {
			return fmt.Errorf("verified release archive omitted %q", path)
		}
	}
	return nil
}

func extractVerifiedLocalArchive(
	archiveSnapshot []byte, destination string,
	manifest releaseManifest,
) (localReleaseMetadata, error) {
	return extractVerifiedLocalArchiveForArchitecture(
		archiveSnapshot, destination, manifest, runtime.GOARCH,
	)
}

func extractVerifiedLocalArchiveForArchitecture(
	archiveSnapshot []byte, destination string,
	manifest releaseManifest,
	expectedArchitecture string,
) (localReleaseMetadata, error) {
	var metadata localReleaseMetadata
	if err := decodeAuthenticatedArchiveJSON(
		archiveSnapshot, "onenod/RELEASE.json", &metadata,
	); err != nil {
		return localReleaseMetadata{}, errors.New("verified local archive metadata is invalid")
	}
	allowed := map[string]os.FileMode{
		"onenod/RELEASE.json":                    0o600,
		"onenod/bin/may":                         0o700,
		"onenod/bin/" + gitSignAdapterBinaryName: 0o700,
	}
	if err := extractReleaseArchiveSnapshot(archiveSnapshot, destination, allowed); err != nil {
		return localReleaseMetadata{}, err
	}
	root := filepath.Join(destination, "onenod")
	if metadata.SchemaVersion != 1 || metadata.Repository != officialRepository ||
		metadata.ArtifactKind != "local" || metadata.Architecture != expectedArchitecture ||
		metadata.ReleaseVersion != manifest.ReleaseVersion ||
		metadata.SourceCommit != manifest.Source.Commit ||
		metadata.CodeIdentities.May != manifest.Components.May.CodeIdentity ||
		metadata.CodeIdentities.MaySSHSign != manifest.Components.May.AdapterCodeIdentity ||
		!validExactBuildRuntimeIdentityForArchitecture(
			metadata.ExactCodeIdentities.May, expectedArchitecture,
		) ||
		!validExactBuildRuntimeIdentityForArchitecture(
			metadata.ExactCodeIdentities.MaySSHSign, expectedArchitecture,
		) ||
		!digestPattern.MatchString(metadata.BinarySHA256.May) ||
		!digestPattern.MatchString(metadata.BinarySHA256.MaySSHSign) {
		return localReleaseMetadata{}, errors.New("verified local archive exact-build metadata does not match the Release")
	}
	mayDigest, err := regularFileSHA256(
		filepath.Join(root, "bin", "may"), maxReleaseArtifactBytes,
	)
	if err != nil || mayDigest != metadata.BinarySHA256.May {
		return localReleaseMetadata{}, errors.New("verified may exact-build digest does not match its archive metadata")
	}
	adapterDigest, err := regularFileSHA256(
		filepath.Join(root, "bin", gitSignAdapterBinaryName), maxReleaseArtifactBytes,
	)
	if err != nil || adapterDigest != metadata.BinarySHA256.MaySSHSign {
		return localReleaseMetadata{}, errors.New("verified may SSH adapter digest does not match its archive metadata")
	}
	return metadata, nil
}

func extractVerifiedHelperArchive(
	archiveSnapshot []byte, destination string,
	manifest releaseManifest,
) (helperReleaseMetadata, error) {
	return extractVerifiedHelperArchiveForArchitecture(
		archiveSnapshot, destination, manifest, runtime.GOARCH,
	)
}

func extractVerifiedHelperArchiveForArchitecture(
	archiveSnapshot []byte, destination string,
	manifest releaseManifest,
	expectedArchitecture string,
) (helperReleaseMetadata, error) {
	var metadata helperReleaseMetadata
	if err := decodeAuthenticatedArchiveJSON(
		archiveSnapshot, "onenod-keychain-helper/RELEASE.json", &metadata,
	); err != nil {
		return helperReleaseMetadata{}, errors.New("verified helper archive metadata is invalid")
	}
	if err := extractReleaseArchiveSnapshot(archiveSnapshot, destination, map[string]os.FileMode{
		"onenod-keychain-helper/RELEASE.json":               0o600,
		"onenod-keychain-helper/bin/onenod-keychain-helper": 0o700,
	}); err != nil {
		return helperReleaseMetadata{}, err
	}
	root := filepath.Join(destination, "onenod-keychain-helper")
	// The helper is independently versioned and an unchanged helper archive is
	// reused byte-for-byte by later product releases. Its source commit therefore
	// belongs to that immutable helper artifact, not necessarily to this product
	// manifest. The outer attested artifact digest binds the complete archive.
	if metadata.SchemaVersion != 1 || metadata.Repository != officialRepository ||
		metadata.ArtifactKind != "keychain_helper" || metadata.Architecture != expectedArchitecture ||
		metadata.HelperVersion != manifest.Components.KeychainHelper.Version ||
		!commitPattern.MatchString(metadata.SourceCommit) ||
		metadata.CodeIdentity != manifest.Components.KeychainHelper.CodeIdentity ||
		!validExactBuildRuntimeIdentityForArchitecture(
			metadata.ExactCodeIdentity, expectedArchitecture,
		) ||
		metadata.HelperSourceDigest != manifest.Components.KeychainHelper.SourceDigest ||
		!protocolContains(manifest.Components.KeychainHelper.HelperProtocol, metadata.HelperProtocol) ||
		!digestPattern.MatchString(metadata.BinarySHA256) {
		return helperReleaseMetadata{}, errors.New("verified helper exact-build metadata does not match the Release")
	}
	digest, err := regularFileSHA256(
		filepath.Join(root, "bin", keychainHelperBinaryName), maxReleaseArtifactBytes,
	)
	if err != nil || digest != metadata.BinarySHA256 {
		return helperReleaseMetadata{}, errors.New("verified helper exact-build digest does not match its archive metadata")
	}
	return metadata, nil
}

func extractSkillArchive(archiveSnapshot []byte, destination string) error {
	if len(archiveSnapshot) == 0 || int64(len(archiveSnapshot)) > maxReleaseArtifactBytes {
		return errors.New("authenticated Skill artifact snapshot is empty or oversized")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(archiveSnapshot))
	if err != nil {
		return errors.New("verified Skill artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open Skill extraction root failed")
	}
	defer root.Close()
	seen := map[string]struct{}{}
	var totalBytes int64
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified Skill archive failed")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified Skill archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified Skill archive contains an unsafe path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		allowed := strings.HasPrefix(clean, "onenod-skill/onenod/") ||
			clean == "onenod-skill/RELEASE.json" || clean == "onenod-skill/LICENSE"
		if !allowed || header.Typeflag != tar.TypeReg || header.Size <= 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes || len(seen) >= 4096 {
			return fmt.Errorf("verified Skill archive entry %q is unsafe or exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified Skill archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create Skill extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("create extracted Skill file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified Skill file failed")
		}
	}
	if _, ok := seen["onenod-skill/onenod/SKILL.md"]; !ok {
		return errors.New("verified Skill archive omitted onenod/SKILL.md")
	}
	if _, ok := seen["onenod-skill/RELEASE.json"]; !ok {
		return errors.New("verified Skill archive omitted RELEASE.json")
	}
	return nil
}

func stageVerifiedDeploymentBundle(
	ctx context.Context,
	release *verifiedRelease,
) (*stagedDeploymentBundle, error) {
	artifact, err := artifactFor(release, deploymentArtifactName(release.Manifest.ReleaseVersion))
	if err != nil {
		return nil, err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return nil, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stage)
		}
	}()
	archiveSnapshot, err := downloadVerifiedArtifact(ctx, release, artifact)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(stage, "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, errors.New("create deployment bundle directory failed")
	}
	var authenticatedDescriptor deploymentBundleDescriptor
	if err := decodeAuthenticatedArchiveJSON(
		archiveSnapshot, "onenod-deployment/deployment.json", &authenticatedDescriptor,
	); err != nil {
		return nil, err
	}
	var authenticatedRelease deploymentReleaseMetadata
	if err := decodeAuthenticatedArchiveJSON(
		archiveSnapshot, "onenod-deployment/RELEASE.json", &authenticatedRelease,
	); err != nil {
		return nil, err
	}
	if err := extractDeploymentBundleArchive(archiveSnapshot, root); err != nil {
		return nil, err
	}
	bundleRoot := filepath.Join(root, "onenod-deployment")
	if err := validateStagedDeploymentBundle(
		bundleRoot, release.Manifest, authenticatedDescriptor, authenticatedRelease,
	); err != nil {
		return nil, err
	}
	cleanup = false
	return &stagedDeploymentBundle{
		Artifact: artifact, Descriptor: authenticatedDescriptor, Root: bundleRoot, Stage: stage,
	}, nil
}

func stageVerifiedReleaseMay(
	ctx context.Context,
	release *verifiedRelease,
) (string, string, error) {
	if release == nil {
		return "", "", errors.New("verified release is unavailable")
	}
	artifactName, err := localArtifactName()
	if err != nil {
		return "", "", err
	}
	artifact, err := artifactFor(release, artifactName)
	if err != nil {
		return "", "", err
	}
	stage, err := privateStagingDirectory()
	if err != nil {
		return "", "", err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stage)
		}
	}()
	archive, err := downloadVerifiedArtifact(ctx, release, artifact)
	if err != nil {
		return "", "", err
	}
	extracted := filepath.Join(stage, "updater")
	if err := os.Mkdir(extracted, 0o700); err != nil {
		return "", "", errors.New("create verified updater extraction directory failed")
	}
	if _, err := extractVerifiedLocalArchive(archive, extracted, release.Manifest); err != nil {
		return "", "", err
	}
	path := filepath.Join(extracted, "onenod", "bin", "may")
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() ||
		info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", "", errors.New("verified updater binary is missing or unsafe")
	}
	cleanup = false
	return path, stage, nil
}

func validateStagedDeploymentBundle(
	bundleRoot string,
	manifest releaseManifest,
	descriptor deploymentBundleDescriptor,
	releaseFile deploymentReleaseMetadata,
) error {
	if descriptor.SchemaVersion != 1 || descriptor.ReleaseVersion != manifest.ReleaseVersion ||
		descriptor.SourceCommit != manifest.Source.Commit ||
		descriptor.Gateway.Config != "gateway/wrangler.jsonc" ||
		descriptor.Gateway.Entrypoint != "gateway/worker.mjs" ||
		descriptor.Gateway.Assets != "gateway/assets" ||
		descriptor.Executor.Config != "executor/wrangler.jsonc" ||
		descriptor.Executor.Entrypoint != "executor/worker.mjs" ||
		descriptor.Executor.Plugin != "executor/plugin.wasm" {
		return errors.New("deployment bundle descriptor does not match the verified release contract")
	}
	expectedTokens := []string{
		"__ACCOUNT_ID__", "__ACCOUNT_SUBDOMAIN__", "__EXECUTOR_NAME__", "__GATEWAY_NAME__",
		"__OP_ACCOUNT__", "__OP_VAULT_ID__", "__ORIGIN__", "__RELEASE_VERSION__",
		"__RP_ID__", "__SOURCE_COMMIT__", "__VAPID_PUBLIC_KEY__",
	}
	actualTokens := append([]string(nil), descriptor.TemplateTokens...)
	sort.Strings(expectedTokens)
	sort.Strings(actualTokens)
	if strings.Join(expectedTokens, "\n") != strings.Join(actualTokens, "\n") {
		return errors.New("deployment bundle template token contract is incomplete")
	}
	if releaseFile.SchemaVersion != 1 || releaseFile.ArtifactKind != "deployment" ||
		releaseFile.Repository != officialRepository ||
		releaseFile.ReleaseVersion != manifest.ReleaseVersion ||
		releaseFile.SourceCommit != manifest.Source.Commit {
		return errors.New("deployment bundle RELEASE.json does not match the verified manifest")
	}
	var materializedDescriptor deploymentBundleDescriptor
	if err := readStrictJSONFile(
		filepath.Join(bundleRoot, "deployment.json"), maxManifestBytes, &materializedDescriptor,
	); err != nil {
		return err
	}
	var materializedRelease deploymentReleaseMetadata
	if err := readStrictJSONFile(
		filepath.Join(bundleRoot, "RELEASE.json"), maxManifestBytes, &materializedRelease,
	); err != nil {
		return err
	}
	if !reflect.DeepEqual(materializedDescriptor, descriptor) || materializedRelease != releaseFile {
		return errors.New("materialized deployment bundle differs from its authenticated descriptor")
	}
	return nil
}

func extractDeploymentBundleArchive(archiveSnapshot []byte, destination string) error {
	if len(archiveSnapshot) == 0 || int64(len(archiveSnapshot)) > maxReleaseArtifactBytes {
		return errors.New("authenticated deployment artifact snapshot is empty or oversized")
	}
	compressed, err := gzip.NewReader(bytes.NewReader(archiveSnapshot))
	if err != nil {
		return errors.New("verified deployment artifact is not gzip")
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	root, err := os.OpenRoot(destination)
	if err != nil {
		return errors.New("open deployment extraction root failed")
	}
	defer root.Close()
	required := deploymentBundleRequiredFiles()
	seen := map[string]struct{}{}
	var totalBytes int64
	entryCount := 0
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("read verified deployment archive failed")
		}
		entryCount++
		if entryCount > 4096 {
			return errors.New("verified deployment archive contains too many entries")
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		relative := filepath.FromSlash(clean)
		if clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(header.Name) {
			return errors.New("verified deployment archive contains an unsafe path")
		}
		if !filepath.IsLocal(relative) {
			return errors.New("verified deployment archive contains an unsafe path")
		}
		if clean != "onenod-deployment" && !strings.HasPrefix(clean, "onenod-deployment/") {
			return errors.New("verified deployment archive contains an unexpected top-level path")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 ||
			header.Size > maxReleaseArtifactBytes-totalBytes {
			return fmt.Errorf("verified deployment archive entry %q exceeds the extraction budget", clean)
		}
		totalBytes += header.Size
		_, exact := required[clean]
		asset := strings.HasPrefix(clean, "onenod-deployment/gateway/assets/")
		if _, duplicate := seen[clean]; duplicate {
			return errors.New("verified deployment archive contains duplicate files")
		}
		seen[clean] = struct{}{}
		if !exact && !asset {
			continue
		}
		if header.Size == 0 {
			return fmt.Errorf("verified deployment archive entry %q is empty", clean)
		}
		if exact {
			required[clean] = true
		}
		if err := root.MkdirAll(filepath.Dir(relative), 0o700); err != nil {
			return errors.New("create deployment extraction directory failed")
		}
		output, err := root.OpenFile(relative, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("create deployment extraction file failed")
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.New("extract verified deployment file failed")
		}
	}
	for path, found := range required {
		if !found {
			return fmt.Errorf("verified deployment archive omitted %q", path)
		}
	}
	assetsRoot := filepath.Join(destination, "onenod-deployment", "gateway", "assets")
	if info, err := os.Stat(assetsRoot); err != nil || !info.IsDir() {
		return errors.New("verified deployment archive contains no Gateway assets")
	}
	return nil
}

func deploymentBundleRequiredFiles() map[string]bool {
	return map[string]bool{
		"onenod-deployment/deployment.json":         false,
		"onenod-deployment/RELEASE.json":            false,
		"onenod-deployment/gateway/wrangler.jsonc":  false,
		"onenod-deployment/gateway/worker.mjs":      false,
		"onenod-deployment/executor/wrangler.jsonc": false,
		"onenod-deployment/executor/worker.mjs":     false,
		"onenod-deployment/executor/plugin.wasm":    false,
	}
}

func readStrictJSONFile(path string, limit int64, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > limit {
		return fmt.Errorf("verified release metadata %s is unsafe", filepath.Base(path))
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read verified release metadata failed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("verified release metadata is invalid")
	}
	return nil
}

func renderDeploymentConfigs(
	bundle *stagedDeploymentBundle,
	manifest releaseManifest,
	material *productionInitializationMaterial,
) error {
	values := map[string]string{
		"__ACCOUNT_ID__":        material.AccountID,
		"__ACCOUNT_SUBDOMAIN__": material.AccountSubdomain,
		"__EXECUTOR_NAME__":     material.ExecutorName,
		"__GATEWAY_NAME__":      material.GatewayName,
		"__OP_ACCOUNT__":        material.OnePasswordAccount,
		"__OP_VAULT_ID__":       material.AgentVaultID,
		"__ORIGIN__":            material.Origin,
		"__RELEASE_VERSION__":   manifest.ReleaseVersion,
		"__RP_ID__":             material.RPID,
		"__SOURCE_COMMIT__":     manifest.Source.Commit,
		"__VAPID_PUBLIC_KEY__":  material.VAPID.PublicKey,
	}
	unknownToken := regexp.MustCompile(`__[A-Z][A-Z0-9_]*__`)
	for _, relative := range []string{
		bundle.Descriptor.Executor.Config,
		bundle.Descriptor.Gateway.Config,
	} {
		path := filepath.Join(bundle.Root, filepath.FromSlash(relative))
		encoded, exists, err := readOptionalRegularFile(path, 4<<20)
		if err != nil || !exists {
			return errors.New("read deployment Wrangler template failed")
		}
		rendered := string(encoded)
		for token, value := range values {
			if strings.ContainsAny(value, "\x00\r\n\"") {
				return errors.New("deployment template value contains unsafe characters")
			}
			rendered = strings.ReplaceAll(rendered, token, value)
		}
		if unknownToken.MatchString(rendered) {
			return errors.New("deployment Wrangler template contains an unresolved token")
		}
		if err := writeAtomicUserConfig(path, []byte(rendered), 0o600); err != nil {
			return err
		}
	}
	return nil
}
