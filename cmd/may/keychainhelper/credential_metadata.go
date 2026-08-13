package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const credentialMetadataVersion = 1

const credentialMetadataSignatureDomain = "onenod-keychain-transport-metadata-v1\n"

// credentialMetadata is deliberately non-secret. Security.framework exposes
// generic-password attributes without decrypting kSecValueData, while the
// item's update ACL protects their integrity. This lets a replacement helper
// authenticate its exact staged build, direct parent, transaction, and raw
// capability before any Keychain dialog can release the requester private key.
// DataSHA256 binds this envelope to the secret JSON changed in the same legacy
// SecKeychainItemModifyAttributesAndData call.
type credentialMetadata struct {
	Version    int                  `json:"version"`
	DataSHA256 string               `json:"data_sha256"`
	Identity   publicIdentity       `json:"identity"`
	Transport  storedTransportTrust `json:"transport"`
	Signature  string               `json:"signature"`
}

type credentialMetadataSignedFields struct {
	Version    int                  `json:"version"`
	DataSHA256 string               `json:"data_sha256"`
	Identity   publicIdentity       `json:"identity"`
	Transport  storedTransportTrust `json:"transport"`
}

func encodeCredentialRecord(identity storedIdentity) ([]byte, []byte, error) {
	if identity.Transport == nil {
		return nil, nil, errors.New("requester identity has no transport trust metadata")
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return nil, nil, errors.New("requester identity encoding failed")
	}
	metadata, err := credentialMetadataForData(identity, data)
	if err != nil {
		zero(data)
		return nil, nil, err
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		zero(data)
		return nil, nil, errors.New("requester transport metadata encoding failed")
	}
	return data, encodedMetadata, nil
}

func credentialMetadataForData(
	identity storedIdentity,
	data []byte,
) (credentialMetadata, error) {
	if identity.Transport == nil || len(data) == 0 {
		return credentialMetadata{}, errors.New("requester identity metadata is incomplete")
	}
	if err := validatePublicIdentity(identity.publicIdentity); err != nil {
		return credentialMetadata{}, err
	}
	if err := validateStoredTransportTrust(identity.Transport); err != nil {
		return credentialMetadata{}, err
	}
	digest := sha256.Sum256(data)
	metadata := credentialMetadata{
		Version:    credentialMetadataVersion,
		DataSHA256: fmt.Sprintf("sha256:%x", digest[:]),
		Identity:   identity.publicIdentity,
		Transport:  *identity.Transport,
	}
	privateKey, err := decodePrivateKey(identity)
	if err != nil {
		return credentialMetadata{}, err
	}
	defer zero(privateKey)
	material, err := credentialMetadataSignatureMaterial(metadata)
	if err != nil {
		return credentialMetadata{}, err
	}
	defer zero(material)
	signature := ed25519.Sign(privateKey, material)
	defer zero(signature)
	metadata.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return metadata, nil
}

func validateCredentialMetadata(metadata credentialMetadata) error {
	if metadata.Version != credentialMetadataVersion ||
		!transportSHA256.MatchString(metadata.DataSHA256) {
		return errors.New("requester transport metadata is invalid")
	}
	if err := validatePublicIdentity(metadata.Identity); err != nil {
		return err
	}
	if err := validateStoredTransportTrust(&metadata.Transport); err != nil {
		return err
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(metadata.Identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		zero(publicKey)
		return errors.New("requester transport metadata signer is invalid")
	}
	defer zero(publicKey)
	signature, err := base64.RawURLEncoding.Strict().DecodeString(metadata.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		zero(signature)
		return errors.New("requester transport metadata signature is invalid")
	}
	defer zero(signature)
	material, err := credentialMetadataSignatureMaterial(metadata)
	if err != nil {
		return err
	}
	defer zero(material)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), material, signature) {
		return errors.New("requester transport metadata signature is invalid")
	}
	return nil
}

func credentialMetadataSignatureMaterial(metadata credentialMetadata) ([]byte, error) {
	fields := credentialMetadataSignedFields{
		Version:    metadata.Version,
		DataSHA256: metadata.DataSHA256,
		Identity:   metadata.Identity,
		Transport:  metadata.Transport,
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, errors.New("requester transport metadata signature material is invalid")
	}
	material := make([]byte, 0, len(credentialMetadataSignatureDomain)+len(encoded))
	material = append(material, credentialMetadataSignatureDomain...)
	material = append(material, encoded...)
	zero(encoded)
	return material, nil
}

func validatePublicIdentity(identity publicIdentity) error {
	if identity.Version != 1 || !transportTransactionID.MatchString(identity.DeviceID) ||
		strings.TrimSpace(identity.DisplayName) == "" || len(identity.DisplayName) > 128 ||
		strings.ContainsAny(identity.DisplayName, "\x00\r\n") {
		return errors.New("requester public identity metadata is invalid")
	}
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		zero(publicKey)
		return errors.New("requester public identity metadata is invalid")
	}
	zero(publicKey)
	return nil
}

func inspectCredentialMetadata(
	store credentialStore,
	service string,
) (credentialMetadata, []byte, bool, error) {
	encoded, found, err := store.Inspect(keychainAccount, service)
	if err != nil {
		return credentialMetadata{}, nil, false,
			errors.New("requester transport metadata Keychain read failed")
	}
	if !found {
		zero(encoded)
		return credentialMetadata{}, nil, false, nil
	}
	if len(encoded) == 0 {
		return credentialMetadata{}, encoded, true,
			errors.New("legacy requester identity has no pre-decryption transport metadata")
	}
	var metadata credentialMetadata
	if err := json.Unmarshal(encoded, &metadata); err != nil ||
		validateCredentialMetadata(metadata) != nil {
		zero(encoded)
		return credentialMetadata{}, nil, true,
			errors.New("requester transport metadata in Keychain is invalid")
	}
	return metadata, encoded, true, nil
}

func loadIdentityForMetadata(
	store credentialStore,
	service string,
	metadata credentialMetadata,
) (storedIdentity, []byte, error) {
	if validateCredentialMetadata(metadata) != nil {
		return storedIdentity{}, nil, errors.New("requester transport metadata is invalid")
	}
	data, found, err := store.Load(keychainAccount, service)
	if err != nil {
		return storedIdentity{}, nil, errors.New("requester identity Keychain read failed")
	}
	if !found {
		zero(data)
		return storedIdentity{}, nil, errors.New("requester identity disappeared after metadata authentication")
	}
	digest := sha256.Sum256(data)
	actualHash := fmt.Sprintf("sha256:%x", digest[:])
	if actualHash != metadata.DataSHA256 {
		zero(data)
		return storedIdentity{}, nil, errors.New("requester identity does not match authenticated metadata")
	}
	var identity storedIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		zero(data)
		return storedIdentity{}, nil, errors.New("requester identity in Keychain is invalid")
	}
	privateKey, err := decodePrivateKey(identity)
	zero(privateKey)
	if err != nil || identity.Transport == nil {
		zero(data)
		return storedIdentity{}, nil, errors.New("requester identity in Keychain is invalid")
	}
	if identity.publicIdentity != metadata.Identity ||
		!sameStoredTransportTrust(identity.Transport, &metadata.Transport) {
		zero(data)
		return storedIdentity{}, nil, errors.New("requester identity transport metadata is inconsistent")
	}
	return identity, data, nil
}

func sameStoredTransportTrust(first, second *storedTransportTrust) bool {
	if first == nil || second == nil || first.Version != second.Version ||
		first.BootstrapPending != second.BootstrapPending ||
		first.ACLConvergencePending != second.ACLConvergencePending ||
		first.LastFinalizedTransactionID != second.LastFinalizedTransactionID ||
		first.LastFinalizedTransactionState != second.LastFinalizedTransactionState ||
		!sameTransportCodeIdentity(first.CurrentHelper, second.CurrentHelper) ||
		!sameTransportSet(first.Current, second.Current) ||
		(first.Staged == nil) != (second.Staged == nil) {
		return false
	}
	if first.Staged == nil {
		return true
	}
	return first.Staged.TransactionID == second.Staged.TransactionID &&
		first.Staged.CommitCapabilitySHA == second.Staged.CommitCapabilitySHA &&
		sameTransportCodeIdentity(first.Staged.Helper, second.Staged.Helper) &&
		sameTransportSet(first.Staged.Transports, second.Staged.Transports)
}
