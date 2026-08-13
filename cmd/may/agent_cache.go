package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maximumCachedIdentities          = 64
	sshIdentityCacheVersion          = 2
	sshIdentityCacheLegacyVersion    = 1
	sshIdentityRefreshRequestTimeout = 15 * time.Second
)

type servedSSHIdentity struct {
	catalog sshCatalogIdentity
	keyBlob []byte
}

type sshIdentityCache struct {
	Identities []cachedSSHIdentity `json:"identities"`
	Version    int                 `json:"version"`
}

type cachedSSHIdentity struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	ItemID        string `json:"item_id"`
	PublicKey     string `json:"public_key"`
	PublicKeyBlob string `json:"public_key_blob"`
	Version       int64  `json:"version"`
}

type legacySSHIdentityCache struct {
	Identities []sshCatalogIdentity `json:"identities"`
	Version    int                  `json:"version"`
}

func sshIdentityCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, userAgentDirectoryName, "ssh", "identities.json")
}

func refreshSSHIdentityCache(
	config cliConfig,
	deps dependencies,
) ([]servedSSHIdentity, error) {
	return refreshSSHIdentityCacheAt(sshIdentityCachePath(), config, deps, true)
}

func refreshSSHIdentityCacheAt(
	cachePath string,
	config cliConfig,
	deps dependencies,
	allowLocalFallback bool,
) ([]servedSSHIdentity, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshIdentityRefreshRequestTimeout)
	defer cancel()
	var response catalogSearchResponse
	if allowLocalFallback {
		response, err = searchCatalogWithLocalFallback(ctx, client, "", deps)
	} else {
		response, err = searchCatalog(ctx, client, "")
	}
	if err != nil {
		return nil, err
	}
	catalogIdentities := make([]sshCatalogIdentity, 0)
	for _, item := range response.Items {
		if item.SSH == nil {
			continue
		}
		catalogIdentities = append(catalogIdentities, sshCatalogIdentity{
			ItemID: item.ItemID, Metadata: *item.SSH, Title: item.Title, Version: item.Version,
		})
	}
	identities, err := validateServedSSHIdentities(catalogIdentities)
	if err != nil {
		return nil, err
	}
	if err := writeSSHIdentityCache(cachePath, catalogIdentities); err != nil {
		return nil, err
	}
	return identities, nil
}

func newSSHIdentityLoader(
	cachePath string,
	config cliConfig,
	deps dependencies,
) func() ([]servedSSHIdentity, error) {
	var mutex sync.Mutex
	return func() ([]servedSSHIdentity, error) {
		mutex.Lock()
		defer mutex.Unlock()
		identities, err := readSSHIdentityCache(cachePath)
		if errors.Is(err, os.ErrNotExist) {
			return refreshSSHIdentityCacheAt(cachePath, config, deps, false)
		}
		return identities, err
	}
}

func validateServedSSHIdentities(
	catalogIdentities []sshCatalogIdentity,
) ([]servedSSHIdentity, error) {
	if len(catalogIdentities) > maximumCachedIdentities {
		return nil, fmt.Errorf("Agent vault contains more than %d SSH keys", maximumCachedIdentities)
	}
	seenItems := make(map[string]struct{}, len(catalogIdentities))
	seenKeys := make(map[string]struct{}, len(catalogIdentities))
	identities := make([]servedSSHIdentity, 0, len(catalogIdentities))
	for _, catalog := range catalogIdentities {
		if err := validateIdentifier(catalog.ItemID, "item"); err != nil {
			return nil, err
		}
		if catalog.Version <= 0 {
			return nil, errors.New("catalog returned an invalid SSH item version")
		}
		if _, exists := seenItems[catalog.ItemID]; exists {
			return nil, errors.New("catalog returned a duplicate SSH item")
		}
		seenItems[catalog.ItemID] = struct{}{}
		if _, err := verifiedOpenSSHPublicLine(catalog.ItemID, catalog.Metadata); err != nil {
			return nil, err
		}
		blob, err := base64.RawURLEncoding.Strict().DecodeString(catalog.Metadata.PublicKeyBlob)
		if err != nil {
			return nil, errors.New("catalog returned an invalid SSH key blob")
		}
		keyID := base64.RawStdEncoding.EncodeToString(blob)
		if _, exists := seenKeys[keyID]; exists {
			return nil, errors.New("more than one item contains the same SSH public key")
		}
		seenKeys[keyID] = struct{}{}
		identities = append(identities, servedSSHIdentity{catalog: catalog, keyBlob: blob})
	}
	return identities, nil
}

func writeSSHIdentityCache(path string, identities []sshCatalogIdentity) error {
	if path == "" {
		return errors.New("resolve SSH identity cache path failed")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create SSH identity cache directory failed")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("secure SSH identity cache directory failed")
	}
	cached := make([]cachedSSHIdentity, 0, len(identities))
	for _, identity := range identities {
		cached = append(cached, cachedSSHIdentity{
			Algorithm: identity.Metadata.Algorithm, Fingerprint: identity.Metadata.Fingerprint,
			ItemID: identity.ItemID, PublicKey: identity.Metadata.PublicKey,
			PublicKeyBlob: identity.Metadata.PublicKeyBlob, Version: identity.Version,
		})
	}
	encoded, err := json.Marshal(sshIdentityCache{
		Identities: cached,
		Version:    sshIdentityCacheVersion,
	})
	if err != nil {
		return errors.New("encode SSH identity cache failed")
	}
	staged, err := os.CreateTemp(directory, ".identities-stage-*")
	if err != nil {
		return errors.New("create staged SSH identity cache failed")
	}
	stagedPath := staged.Name()
	complete := false
	defer func() {
		_ = staged.Close()
		if !complete {
			_ = os.Remove(stagedPath)
		}
	}()
	if err := staged.Chmod(0o600); err != nil {
		return errors.New("secure staged SSH identity cache failed")
	}
	if _, err := staged.Write(encoded); err != nil {
		return errors.New("write staged SSH identity cache failed")
	}
	if err := staged.Sync(); err != nil {
		return errors.New("sync staged SSH identity cache failed")
	}
	if err := staged.Close(); err != nil {
		return errors.New("close staged SSH identity cache failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("install SSH identity cache failed")
	}
	complete = true
	return nil
}

func readSSHIdentityCache(path string) ([]servedSSHIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 512*1024 {
		return nil, errors.New("SSH identity cache must be a bounded mode-0600 regular file")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("read SSH identity cache failed")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("read SSH identity cache failed")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) ||
		!openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 {
		return nil, errors.New("SSH identity cache changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 512*1024+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 512*1024 {
		return nil, errors.New("read SSH identity cache failed")
	}
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(encoded, &header) != nil {
		return nil, errors.New("SSH identity cache is invalid")
	}
	if header.Version == sshIdentityCacheLegacyVersion {
		var legacy legacySSHIdentityCache
		if err := decodeStrictSSHIdentityCache(encoded, &legacy); err != nil || legacy.Version != sshIdentityCacheLegacyVersion {
			return nil, errors.New("SSH identity cache is invalid")
		}
		if _, err := validateServedSSHIdentities(legacy.Identities); err != nil {
			return nil, err
		}
		stripped := make([]sshCatalogIdentity, 0, len(legacy.Identities))
		for _, identity := range legacy.Identities {
			identity.Title = ""
			stripped = append(stripped, identity)
		}
		if err := writeSSHIdentityCache(path, stripped); err != nil {
			return nil, errors.New("migrate legacy SSH identity cache failed")
		}
		return validateServedSSHIdentities(stripped)
	}
	var cache sshIdentityCache
	if err := decodeStrictSSHIdentityCache(encoded, &cache); err != nil || cache.Version != sshIdentityCacheVersion {
		return nil, errors.New("SSH identity cache is invalid")
	}
	catalog := make([]sshCatalogIdentity, 0, len(cache.Identities))
	for _, identity := range cache.Identities {
		catalog = append(catalog, sshCatalogIdentity{
			ItemID: identity.ItemID,
			Metadata: catalogSSHMetadata{
				Algorithm: identity.Algorithm, Fingerprint: identity.Fingerprint,
				PublicKey: identity.PublicKey, PublicKeyBlob: identity.PublicKeyBlob,
			},
			Version: identity.Version,
		})
	}
	return validateServedSSHIdentities(catalog)
}

func decodeStrictSSHIdentityCache(encoded []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing SSH identity cache data")
	}
	return nil
}
