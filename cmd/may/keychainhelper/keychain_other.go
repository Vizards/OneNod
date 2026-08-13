//go:build !darwin || !cgo

package main

import "errors"

type systemCredentialStore struct{}

func (systemCredentialStore) Create(string, string, []byte, []byte, keychainAccessPolicy) error {
	return errors.New("macOS Keychain is unavailable")
}

func (systemCredentialStore) Inspect(string, string) ([]byte, bool, error) {
	return nil, false, errors.New("macOS Keychain is unavailable")
}

func (systemCredentialStore) Load(string, string) ([]byte, bool, error) {
	return nil, false, errors.New("macOS Keychain is unavailable")
}

func (systemCredentialStore) Replace(
	string,
	string,
	[]byte,
	[]byte,
	[]byte,
	keychainAccessPolicy,
) error {
	return errors.New("macOS Keychain is unavailable")
}

func (systemCredentialStore) Constrain(
	string,
	string,
	[]byte,
	keychainAccessPolicy,
) error {
	return errors.New("macOS Keychain is unavailable")
}
