package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type memoryStore struct {
	value       []byte
	metadata    []byte
	access      keychainAccessPolicy
	accesses    []keychainAccessPolicy
	loadCount   int
	replaceHook func(expected, replacement []byte, access keychainAccessPolicy) error
}

func (store *memoryStore) Load(_, _ string) ([]byte, bool, error) {
	store.loadCount++
	if store.value == nil {
		return nil, false, nil
	}
	return append([]byte(nil), store.value...), true, nil
}

func (store *memoryStore) Inspect(_, _ string) ([]byte, bool, error) {
	if store.value == nil {
		return nil, false, nil
	}
	return append([]byte(nil), store.metadata...), true, nil
}

func (store *memoryStore) Create(
	_, _ string,
	value,
	metadata []byte,
	access keychainAccessPolicy,
) error {
	if store.value != nil {
		return errIdentityExists
	}
	store.value = append([]byte(nil), value...)
	store.metadata = append([]byte(nil), metadata...)
	store.access = access
	store.accesses = append(store.accesses, access)
	return nil
}

func (store *memoryStore) Replace(
	_, _ string,
	expectedMetadata,
	replacement []byte,
	metadata []byte,
	access keychainAccessPolicy,
) error {
	if !bytes.Equal(store.metadata, expectedMetadata) {
		return errIdentityChanged
	}
	if access == keychainAccessPreserve && store.replaceHook != nil {
		if err := store.replaceHook(store.value, replacement, access); err != nil {
			return err
		}
	}
	previous := append([]byte(nil), store.value...)
	store.value = append(store.value[:0], replacement...)
	store.metadata = append(store.metadata[:0], metadata...)
	if access != keychainAccessPreserve && store.replaceHook != nil {
		if err := store.replaceHook(previous, replacement, access); err != nil {
			return err
		}
	}
	if access != keychainAccessPreserve {
		store.access = access
		store.accesses = append(store.accesses, access)
	}
	return nil
}

func (store *memoryStore) Constrain(
	_, _ string,
	expectedMetadata []byte,
	access keychainAccessPolicy,
) error {
	if !bytes.Equal(store.metadata, expectedMetadata) {
		return errIdentityChanged
	}
	if store.replaceHook != nil {
		if err := store.replaceHook(store.value, store.value, access); err != nil {
			return err
		}
	}
	store.access = access
	store.accesses = append(store.accesses, access)
	return nil
}

type testTransportRuntime struct {
	helper  transportCodeIdentity
	parent  transportCodeIdentity
	may     transportCodeIdentity
	adapter transportCodeIdentity
}

func useTestTransportRuntime(t *testing.T, runtime testTransportRuntime) {
	t.Helper()
	previousHelper := currentHelperIdentityResolver
	previousParent := directParentIdentityResolver
	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return runtime.helper, nil
	}
	directParentIdentityResolver = func(kind transportCodeKind) (transportCodeIdentity, error) {
		if kind != transportCodeKindMay {
			return transportCodeIdentity{}, errors.New("unexpected transport kind")
		}
		return runtime.parent, nil
	}
	t.Cleanup(func() {
		currentHelperIdentityResolver = previousHelper
		directParentIdentityResolver = previousParent
	})
}

func newTestTransportRuntime(marker byte) testTransportRuntime {
	return testTransportRuntime{
		helper:  testTransportIdentity(transportCodeKindHelper, marker),
		parent:  testTransportIdentity(transportCodeKindMay, marker+1),
		may:     testTransportIdentity(transportCodeKindMay, marker+1),
		adapter: testTransportIdentity(transportCodeKindSSHSign, marker+2),
	}
}

func testTransportIdentity(kind transportCodeKind, marker byte) transportCodeIdentity {
	identifier, ok := signingIdentifierForTransportKind(kind)
	if !ok {
		panic("unknown test transport kind")
	}
	return transportCodeIdentity{
		Kind:                  kind,
		PolicyVersion:         transportRuntimePolicyVersion,
		SignatureClass:        applicationSignatureAdHoc,
		SigningIdentifier:     identifier,
		CodeDirectoryHash:     bytes.Repeat([]byte{marker}, sha256.Size),
		DesignatedRequirement: []byte{0xfa, 0xde, marker},
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
	}
}

func authenticatedMemoryStore(
	t *testing.T,
	displayName string,
	runtime testTransportRuntime,
) (*memoryStore, storedIdentity) {
	t.Helper()
	identity, err := newIdentity(displayName)
	if err != nil {
		t.Fatal(err)
	}
	identity.Transport = &storedTransportTrust{
		Version:       transportStateVersion,
		CurrentHelper: runtime.helper,
		Current: []transportCodeIdentity{
			runtime.may,
			runtime.adapter,
		},
	}
	encoded, metadata, err := encodeCredentialRecord(identity)
	if err != nil {
		t.Fatal(err)
	}
	return &memoryStore{
		value: encoded, metadata: metadata, access: keychainAccessSelfOnly,
	}, identity
}

func TestHelperEnsuresPublicIdentityAndSignsOnlyCanonicalOriginRequest(t *testing.T) {
	runtime := newTestTransportRuntime(1)
	useTestTransportRuntime(t, runtime)
	store, _ := authenticatedMemoryStore(t, "MacBook", runtime)
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

func TestHelperAttestsOnlyBodyBoundVerifiedApplication(t *testing.T) {
	runtime := newTestTransportRuntime(8)
	useTestTransportRuntime(t, runtime)
	store, _ := authenticatedMemoryStore(t, "MacBook", runtime)
	origin := "https://onenod.example.workers.dev"
	ensured, err := handleRequest(helperRequest{
		Operation: "ensure", Origin: origin, DisplayName: "MacBook",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	resolved := applicationIdentity{
		Application: "Signed Editor", Source: applicationIdentitySource,
		Assurance: applicationIdentityAssurance, Platform: applicationIdentityPlatform,
		PrincipalScheme:   applicationPrincipalScheme,
		PrincipalID:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		SigningIdentifier: "com.example.editor", TeamIdentifier: "EXAMPLETEAM",
	}
	previousResolver := authorizedApplicationResolver
	authorizedApplicationResolver = func(
		evidence string,
		authorized authorizedTransportSet,
	) (applicationIdentity, error) {
		if evidence != applicationEvidenceParent {
			t.Fatalf("application evidence = %q", evidence)
		}
		if !authorized.authorizes(runtime.may) {
			t.Fatal("current transport set was not supplied to application resolver")
		}
		return resolved, nil
	}
	t.Cleanup(func() { authorizedApplicationResolver = previousResolver })

	body := []byte(`{"action":"secret.read","authorization_scope":{"scope_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","scope_kind":"application"},"client":{"application":"Signed Editor","identity":{"assurance":"verified-code-signature","platform":"macos","principal_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","principal_scheme":"macos-designated-requirement-v1","signing_identifier":"com.example.editor","team_identifier":"EXAMPLETEAM"},"source":"process-ancestry"},"expected_version":1,"field_id":"password","idempotency_key":"request-1","item_id":"item-1"}`)
	digest := sha256.Sum256(body)
	message := []byte("onenod-request-v1\nonenod.example.workers.dev\nPOST\n/v1/requests\n" +
		base64.RawURLEncoding.EncodeToString(digest[:]) + "\n" +
		ensured.Identity.DeviceID + "\n1700000000\nnonce")
	signed, err := handleRequest(helperRequest{
		ApplicationEvidence: applicationEvidenceParent,
		CanonicalBody:       base64.RawURLEncoding.EncodeToString(body),
		Operation:           "sign",
		Origin:              origin,
		Message:             base64.RawURLEncoding.EncodeToString(message),
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(ensured.Identity.PublicKey)
	attestation, err := base64.RawURLEncoding.Strict().DecodeString(
		signed.ApplicationAttestation,
	)
	if err != nil || !ed25519.Verify(
		publicKey,
		applicationAttestationMaterial(
			message,
			resolved.PrincipalScheme,
			resolved.PrincipalID,
		),
		attestation,
	) {
		t.Fatal("application attestation did not verify")
	}

	tampered := bytes.Replace(
		body,
		[]byte(resolved.PrincipalID),
		[]byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
		1,
	)
	tamperedDigest := sha256.Sum256(tampered)
	tamperedMessage := []byte("onenod-request-v1\nonenod.example.workers.dev\nPOST\n/v1/requests\n" +
		base64.RawURLEncoding.EncodeToString(tamperedDigest[:]) + "\n" +
		ensured.Identity.DeviceID + "\n1700000000\nnonce-2")
	if _, err := handleRequest(helperRequest{
		ApplicationEvidence: applicationEvidenceParent,
		CanonicalBody:       base64.RawURLEncoding.EncodeToString(tampered),
		Operation:           "sign",
		Origin:              origin,
		Message:             base64.RawURLEncoding.EncodeToString(tamperedMessage),
	}, store); err == nil {
		t.Fatal("helper attested a body with a different application principal")
	}
}

func TestApplicationObservationUsesAuthenticatedMetadataWithoutDecryptingPrivateKey(t *testing.T) {
	runtime := newTestTransportRuntime(9)
	useTestTransportRuntime(t, runtime)
	store, _ := authenticatedMemoryStore(t, "MacBook", runtime)

	response, err := handleRequest(helperRequest{
		ApplicationEvidence: applicationEvidenceParent,
		Operation:           "application",
		Origin:              "https://onenod.example.workers.dev",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	if response.Application == nil {
		t.Fatal("application observation was omitted")
	}
	if store.loadCount != 0 {
		t.Fatalf("application observation decrypted the requester private key %d times", store.loadCount)
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
