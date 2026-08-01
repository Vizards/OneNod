package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

type memoryStore struct{ value []byte }

func (store *memoryStore) Load(_, _ string) ([]byte, bool, error) {
	if store.value == nil {
		return nil, false, nil
	}
	return append([]byte(nil), store.value...), true, nil
}

func (store *memoryStore) Create(_, _ string, value []byte) error {
	if store.value != nil {
		return errIdentityExists
	}
	store.value = append([]byte(nil), value...)
	return nil
}

func TestHelperEnsuresPublicIdentityAndSignsOnlyCanonicalOriginRequest(t *testing.T) {
	store := &memoryStore{}
	origin := "https://onenod.example.workers.dev"
	ensured, err := handleRequest(helperRequest{
		Operation: "ensure", Origin: origin, DisplayName: "MacBook",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if ensured.Identity == nil || ensured.Identity.PublicKey == "" ||
		strings.Contains(mustJSON(t, ensured), "private_key") {
		t.Fatalf("unsafe ensure response: %+v", ensured)
	}
	message := []byte("onenod-request-v1\nonenod.example.workers.dev\nGET\n/v1/catalog\nbodyhash\n" +
		ensured.Identity.DeviceID + "\n1700000000\nnonce")
	signed, err := handleRequest(helperRequest{
		Operation: "sign", Origin: origin,
		Message: base64.RawURLEncoding.EncodeToString(message),
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(ensured.Identity.PublicKey)
	signature, _ := base64.RawURLEncoding.DecodeString(signed.Signature)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("helper signature did not verify")
	}
	if _, err := handleRequest(helperRequest{
		Operation: "sign", Origin: origin,
		Message: base64.RawURLEncoding.EncodeToString([]byte("arbitrary")),
	}, store); err == nil {
		t.Fatal("helper signed arbitrary bytes")
	}
}

func TestHelperProtocolRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"operation":"hello","secret":"no"}`,
		`{"operation":"hello"}{"operation":"hello"}`,
	} {
		var output strings.Builder
		if err := serveOne(strings.NewReader(input), &output, &memoryStore{}); err == nil {
			t.Fatalf("invalid request was accepted: %s", input)
		}
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
