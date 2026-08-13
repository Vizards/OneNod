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
	"fmt"
	"strings"
)

const (
	keychainAccount                   = "may"
	defaultKeychainService            = "com.github.vizards.onenod.requester.default"
	originScopedKeychainServicePrefix = "com.github.vizards.onenod.requester.target."
)

type requesterCredential struct {
	DeviceID     string `json:"device_id"`
	DisplayName  string `json:"display_name"`
	PrivateKey   string `json:"private_key,omitempty"`
	PublicKey    string `json:"public_key"`
	Version      int    `json:"version"`
	helperOrigin string
	helperSlot   string
}

func generateRequesterCredential(displayName string) (*requesterCredential, error) {
	if strings.TrimSpace(displayName) == "" {
		return nil, errors.New("requester display name is required")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate requester key: %w", err)
	}
	deviceID, err := newUUIDv4()
	if err != nil {
		return nil, err
	}
	return &requesterCredential{
		DeviceID:    deviceID,
		DisplayName: displayName,
		PrivateKey:  base64.RawURLEncoding.EncodeToString(privateKey),
		PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
		Version:     1,
	}, nil
}

func (credential *requesterCredential) privateKey() (ed25519.PrivateKey, error) {
	if credential == nil || credential.Version != 1 || credential.DeviceID == "" {
		return nil, errors.New("invalid requester credential")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(credential.PrivateKey)
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid requester private key")
	}
	privateKey := ed25519.PrivateKey(decoded)
	derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
	if base64.RawURLEncoding.EncodeToString(derivedPublicKey) != credential.PublicKey {
		return nil, errors.New("requester public key does not match private key")
	}
	return privateKey, nil
}

func publicKeyFingerprint(credential *requesterCredential) (string, error) {
	if err := credential.validatePublic(); err != nil {
		return "", err
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(credential.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("invalid requester public key")
	}
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func (credential *requesterCredential) validatePublic() error {
	if credential == nil || credential.Version != 1 || credential.DeviceID == "" ||
		strings.TrimSpace(credential.DisplayName) == "" {
		return errors.New("invalid requester credential")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(credential.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid requester public key")
	}
	if credential.PrivateKey == "" && credential.helperOrigin == "" {
		return errors.New("requester credential has no signing provider")
	}
	return nil
}

type keychainBackend interface {
	Load(account string, service string) ([]byte, bool, error)
	Save(account string, service string, data []byte) error
}

type unavailableKeychainBackend struct{}

func (unavailableKeychainBackend) Load(string, string) ([]byte, bool, error) {
	return nil, false, errors.New("requester Keychain access requires the installed OneNod Keychain helper")
}

func (unavailableKeychainBackend) Save(string, string, []byte) error {
	return errors.New("requester Keychain access requires the installed OneNod Keychain helper")
}

type keychainStore struct {
	backend keychainBackend
	origin  string
	service string
	slot    string
}

func requesterKeychainService(origin string) (string, error) {
	parsed, err := parseGatewayOrigin(origin)
	if err != nil {
		return "", err
	}
	normalized := parsed.String()
	digest := sha256.Sum256([]byte(normalized))
	return originScopedKeychainServicePrefix + hex.EncodeToString(digest[:8]), nil
}

func (store keychainStore) selectedService() string {
	service := store.service
	if service == "" {
		service = defaultKeychainService
	}
	if store.slot != "" && store.slot != "active" {
		return service + ".slot." + store.slot
	}
	return service
}

func (store keychainStore) selectedBackend() keychainBackend {
	if store.backend != nil {
		return store.backend
	}
	return unavailableKeychainBackend{}
}

func (store keychainStore) Save(credential *requesterCredential) error {
	if _, err := credential.privateKey(); err != nil {
		return err
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		return fmt.Errorf("encode requester credential: %w", err)
	}
	if err := store.selectedBackend().Save(
		keychainAccount,
		store.selectedService(),
		encoded,
	); err != nil {
		return errors.New("store requester credential in Keychain failed")
	}
	return nil
}

func (store keychainStore) Load() (*requesterCredential, error) {
	credential, found, err := store.LoadIfPresent()
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("requester credential was not found in Keychain; run enroll first")
	}
	return credential, nil
}

func (store keychainStore) LoadIfPresent() (*requesterCredential, bool, error) {
	if store.backend == nil && store.origin != "" {
		identity, found, err := loadRequesterFromHelper(store.origin, store.slot)
		if err != nil {
			return nil, false, err
		}
		if !found {
			return nil, false, nil
		}
		identity.helperOrigin = store.origin
		identity.helperSlot = store.slot
		if err := identity.validatePublic(); err != nil {
			return nil, false, errors.New("requester credential helper returned invalid public metadata")
		}
		return identity, true, nil
	}
	output, found, err := store.selectedBackend().Load(
		keychainAccount,
		store.selectedService(),
	)
	if err != nil {
		return nil, false, errors.New("read requester credential from Keychain failed")
	}
	if !found {
		return nil, false, nil
	}
	var credential requesterCredential
	if err := json.Unmarshal(bytes.TrimSpace(output), &credential); err != nil {
		return nil, false, errors.New("requester credential in Keychain is invalid")
	}
	if _, err := credential.privateKey(); err != nil {
		return nil, false, errors.New("requester credential in Keychain is invalid")
	}
	return &credential, true, nil
}

func (store keychainStore) Ensure(displayName string) (*requesterCredential, bool, error) {
	if store.backend != nil || store.origin == "" {
		credential, found, err := store.LoadIfPresent()
		if err != nil {
			return nil, false, err
		}
		if found {
			if credential.DisplayName != displayName {
				return nil, false, fmt.Errorf(
					"Keychain already contains requester %q; refusing to overwrite it",
					credential.DisplayName,
				)
			}
			return credential, false, nil
		}
		credential, err = generateRequesterCredential(displayName)
		if err != nil {
			return nil, false, err
		}
		if err := store.Save(credential); err != nil {
			return nil, false, err
		}
		return credential, true, nil
	}
	credential, created, err := ensureRequesterWithHelper(store.origin, store.slot, displayName)
	if err != nil {
		return nil, false, err
	}
	credential.helperOrigin = store.origin
	credential.helperSlot = store.slot
	return credential, created, credential.validatePublic()
}

func (credential *requesterCredential) signCanonical(message []byte) ([]byte, error) {
	signature, _, err := credential.signCanonicalWithApplication(message, nil, nil)
	return signature, err
}

func (credential *requesterCredential) signCanonicalWithApplication(
	message,
	canonicalBody []byte,
	evidence *applicationEvidence,
) ([]byte, []byte, error) {
	if credential == nil {
		return nil, nil, errors.New("requester credential is required")
	}
	if credential.PrivateKey != "" {
		privateKey, err := credential.privateKey()
		if err != nil {
			return nil, nil, err
		}
		return ed25519.Sign(privateKey, message), nil, nil
	}
	if credential.helperOrigin == "" {
		return nil, nil, errors.New("requester signing provider is unavailable")
	}
	return signRequesterWithHelper(
		credential.helperOrigin,
		credential.helperSlot,
		message,
		canonicalBody,
		evidence,
	)
}
