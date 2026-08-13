package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"strings"
)

func credentialFromSeed(name string) (*requesterCredential, error) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &requesterCredential{
		DeviceID:    "11223344-5566-4788-99aa-bbccddeeff00",
		DisplayName: name,
		PrivateKey:  base64.RawURLEncoding.EncodeToString(privateKey),
		PublicKey:   base64.RawURLEncoding.EncodeToString(publicKey),
		Version:     1,
	}, nil
}

type recordingKeychainBackend struct {
	account string
	service string
	saved   []byte
	output  []byte
	found   bool
	saveErr error
	loadErr error
}

type serviceKeychainBackend struct {
	items map[string][]byte
}

func (backend *serviceKeychainBackend) Save(_ string, service string, data []byte) error {
	backend.items[service] = append([]byte(nil), data...)
	return nil
}

func (backend *serviceKeychainBackend) Load(_ string, service string) ([]byte, bool, error) {
	value, found := backend.items[service]
	return append([]byte(nil), value...), found, nil
}

func (backend *recordingKeychainBackend) Save(account string, service string, data []byte) error {
	backend.account = account
	backend.service = service
	backend.saved = append([]byte(nil), data...)
	return backend.saveErr
}

func (backend *recordingKeychainBackend) Load(account string, service string) ([]byte, bool, error) {
	backend.account = account
	backend.service = service
	return append([]byte(nil), backend.output...), backend.found, backend.loadErr
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type stringReadCloser struct {
	*strings.Reader
}

func (stringReadCloser) Close() error { return nil }

func ioNopCloser(value string) *stringReadCloser {
	return &stringReadCloser{Reader: strings.NewReader(value)}
}

func jsonHTTPResponse(status int, value string) *http.Response {
	return &http.Response{
		Body:       ioNopCloser(value),
		Header:     http.Header{"content-type": []string{"application/json"}},
		StatusCode: status,
	}
}

func gatewayErrorHTTPResponse(status int, code string) *http.Response {
	response := jsonHTTPResponse(status, `{"code":"`+code+`","error":"`+code+`","ok":false}`)
	response.Header.Set(headerGatewayErrorCode, code)
	return response
}
