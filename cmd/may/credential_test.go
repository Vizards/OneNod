package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestKeychainSavePassesCredentialOnlyToBackend(t *testing.T) {
	credential, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	backend := &recordingKeychainBackend{}
	store := keychainStore{backend: backend}
	if err := store.Save(credential); err != nil {
		t.Fatal(err)
	}
	if backend.account != keychainAccount || backend.service != defaultKeychainService {
		t.Fatal("unexpected Keychain item identity")
	}
	if !bytes.Contains(backend.saved, []byte(credential.PrivateKey)) {
		t.Fatal("private key was not supplied to the Keychain backend")
	}
}

func TestRequesterKeychainServiceSeparatesOrigins(t *testing.T) {
	first, err := requesterKeychainService("https://onenod.example-one.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	second, err := requesterKeychainService("https://onenod.example-two.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := requesterKeychainService("https://onenod.example-one.workers.dev")
	if err != nil {
		t.Fatal(err)
	}
	if first != repeated ||
		first == second ||
		!strings.HasPrefix(first, originScopedKeychainServicePrefix) ||
		!strings.HasPrefix(second, originScopedKeychainServicePrefix) {
		t.Fatalf("Origins did not receive stable isolated services: %q %q", first, second)
	}
}

func TestRequesterPublicKeyFingerprint(t *testing.T) {
	credential, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := publicKeyFingerprint(credential)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"
	if fingerprint != expected {
		t.Fatalf("fingerprint mismatch: %s", fingerprint)
	}
}

func TestKeychainLoadRejectsMalformedCredential(t *testing.T) {
	backend := &recordingKeychainBackend{
		found:  true,
		output: []byte(`{"version":1}`),
	}
	_, err := (keychainStore{backend: backend}).Load()
	if err == nil {
		t.Fatal("malformed credential was accepted")
	}
}

func TestKeychainLoadIfPresentRecognizesMissingItem(t *testing.T) {
	backend := &recordingKeychainBackend{found: false}
	credential, found, err := (keychainStore{backend: backend}).LoadIfPresent()
	if err != nil {
		t.Fatal(err)
	}
	if found || credential != nil {
		t.Fatal("missing Keychain item was reported as present")
	}
}

func TestUnselectedRequesterDoesNotProbeLegacyHelperSlot(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	credential, found, err := (keychainStore{
		origin: "https://onenod.example-account.workers.dev",
		slot:   "active",
	}).LoadIfPresent()
	if err != nil || found || credential != nil {
		t.Fatalf("unselected requester helper probe = %+v, %v, %v", credential, found, err)
	}
}

func TestKeychainBackendErrorDoesNotExposeOutput(t *testing.T) {
	backend := &recordingKeychainBackend{
		found:   true,
		loadErr: errors.New("failure"),
		output:  []byte("dummy-secret"),
	}
	store := keychainStore{backend: backend}
	_, err := store.Load()
	if err == nil || strings.Contains(err.Error(), "dummy-secret") {
		t.Fatal("secret-shaped command output was exposed")
	}
}
