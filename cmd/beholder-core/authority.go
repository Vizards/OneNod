package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	beholderAuthoritySchemaVersion = 1
	beholderAuthorizationLifetime  = 30 * time.Second
	beholderAuthorizationProtocol  = "onenod-beholder-authorization-v1"
)

type beholderAuthorityFile struct {
	SchemaVersion int    `json:"schema_version"`
	Seed          string `json:"seed"`
}

type beholderAuthorityIdentity struct {
	SchemaVersion int    `json:"schema_version"`
	KeyID         string `json:"key_id"`
	PublicKey     string `json:"public_key"`
}

type beholderAuthority struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	now        func() time.Time
}

func loadBeholderAuthority(path string, production bool) (*beholderAuthority, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("Beholder authority key path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return nil, errors.New("Beholder authority key identity is invalid")
	}
	if production {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, errors.New("Beholder authority key is not root-controlled")
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 4096 {
		clear(contents)
		return nil, errors.New("read Beholder authority key failed")
	}
	defer clear(contents)
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var stored beholderAuthorityFile
	if decoder.Decode(&stored) != nil {
		return nil, errors.New("Beholder authority key is invalid")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) || stored.SchemaVersion != beholderAuthoritySchemaVersion {
		return nil, errors.New("Beholder authority key is invalid")
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(stored.Seed)
	stored.Seed = ""
	if err != nil || len(seed) != ed25519.SeedSize {
		clear(seed)
		return nil, errors.New("Beholder authority key is invalid")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(publicKey)
	return &beholderAuthority{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      base64.RawURLEncoding.EncodeToString(digest[:]),
		now:        time.Now,
	}, nil
}

func initializeBeholderAuthority(path string, production bool) (beholderAuthorityIdentity, error) {
	if authority, err := loadBeholderAuthority(path, production); err == nil {
		defer authority.close()
		return authority.identity(), nil
	} else if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		return beholderAuthorityIdentity{}, err
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return beholderAuthorityIdentity{}, errors.New("Beholder authority key parent is invalid")
	}
	if production {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return beholderAuthorityIdentity{}, errors.New("Beholder authority key parent is not root-controlled")
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return beholderAuthorityIdentity{}, errors.New("generate Beholder authority key failed")
	}
	stored := beholderAuthorityFile{
		SchemaVersion: beholderAuthoritySchemaVersion,
		Seed:          base64.RawURLEncoding.EncodeToString(seed),
	}
	clear(seed)
	encoded, err := json.Marshal(stored)
	stored.Seed = ""
	if err != nil {
		return beholderAuthorityIdentity{}, errors.New("encode Beholder authority key failed")
	}
	encoded = append(encoded, '\n')
	defer clear(encoded)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return beholderAuthorityIdentity{}, errors.New("create Beholder authority key failed")
	}
	created := true
	defer func() {
		if created {
			_ = os.Remove(path)
		}
	}()
	writeErr := error(nil)
	if _, err := file.Write(encoded); err != nil {
		writeErr = err
	} else if err := file.Sync(); err != nil {
		writeErr = err
	}
	if err := file.Close(); writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		return beholderAuthorityIdentity{}, errors.New("persist Beholder authority key failed")
	}
	authority, err := loadBeholderAuthority(path, production)
	if err != nil {
		return beholderAuthorityIdentity{}, err
	}
	parentDirectory, err := os.Open(parent)
	if err != nil {
		authority.close()
		return beholderAuthorityIdentity{}, errors.New("persist Beholder authority key failed")
	}
	syncErr := parentDirectory.Sync()
	closeErr := parentDirectory.Close()
	if syncErr != nil || closeErr != nil {
		authority.close()
		return beholderAuthorityIdentity{}, errors.New("persist Beholder authority key failed")
	}
	created = false
	defer authority.close()
	return authority.identity(), nil
}

func (authority *beholderAuthority) identity() beholderAuthorityIdentity {
	return beholderAuthorityIdentity{
		SchemaVersion: beholderAuthoritySchemaVersion,
		KeyID:         authority.keyID,
		PublicKey:     base64.RawURLEncoding.EncodeToString(authority.publicKey),
	}
}

func (authority *beholderAuthority) authorize(
	evidenceID string,
	requesterDeviceID string,
	operationTargetSHA256 string,
) (*beholderAuthorization, error) {
	if authority == nil || len(authority.privateKey) != ed25519.PrivateKeySize ||
		!safeDecisionField(evidenceID, 96, false) ||
		!safeDecisionField(requesterDeviceID, 128, false) ||
		!validCoreBinarySHA256(operationTargetSHA256) {
		return nil, errors.New("invalid Beholder authorization input")
	}
	issuedAt := authority.now().UTC().Unix()
	authorization := &beholderAuthorization{
		SchemaVersion:         beholderAuthoritySchemaVersion,
		Decision:              "allow",
		EvidenceID:            evidenceID,
		ExpiresAt:             issuedAt + int64(beholderAuthorizationLifetime/time.Second),
		IssuedAt:              issuedAt,
		KeyID:                 authority.keyID,
		OperationTargetSHA256: strings.ToLower(operationTargetSHA256),
		RequesterDeviceID:     requesterDeviceID,
	}
	authorization.Signature = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(authority.privateKey, []byte(beholderAuthorizationMaterial(*authorization))),
	)
	return authorization, nil
}

func beholderAuthorizationMaterial(value beholderAuthorization) string {
	return strings.Join([]string{
		beholderAuthorizationProtocol,
		value.KeyID,
		value.EvidenceID,
		value.RequesterDeviceID,
		value.OperationTargetSHA256,
		strconv.FormatInt(value.IssuedAt, 10),
		strconv.FormatInt(value.ExpiresAt, 10),
		value.Decision,
	}, "\n")
}

func (authority *beholderAuthority) close() {
	if authority == nil {
		return
	}
	clear(authority.privateKey)
	clear(authority.publicKey)
	authority.privateKey = nil
	authority.publicKey = nil
	authority.keyID = ""
}

func validAuthorizationForTarget(
	value *beholderAuthorization,
	authority *beholderAuthority,
	evidenceID string,
	requesterDeviceID string,
	targetDigest string,
) bool {
	if value == nil || authority == nil || value.SchemaVersion != 1 || value.Decision != "allow" ||
		value.EvidenceID != evidenceID || value.RequesterDeviceID != requesterDeviceID ||
		value.OperationTargetSHA256 != strings.ToLower(targetDigest) || value.KeyID != authority.keyID ||
		value.ExpiresAt <= value.IssuedAt || value.ExpiresAt-value.IssuedAt > 30 {
		return false
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		clear(signature)
		return false
	}
	defer clear(signature)
	return ed25519.Verify(authority.publicKey, []byte(beholderAuthorizationMaterial(*value)), signature)
}

func authorityFileSHA256(path string) string {
	contents, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	defer clear(contents)
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}
