package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCanonicalJSONVector(t *testing.T) {
	body := createRequest{
		Action: "secret.read",
		Client: clientObservation{
			Application: "Codex",
			Identity: applicationIdentity{
				Assurance: applicationAssuranceUnverified,
				Platform:  "macos",
			},
			Source: "process-ancestry",
		},
		ExpectedVersion: 7,
		FieldID:         "password",
		IdempotencyKey:  "018f1f83-7b2a-7abc-8def-0123456789ab", // gitleaks:allow -- Fixed synthetic UUID test vector.
		ItemID:          "item-123",
	}
	actual, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"action":"secret.read","client":{"application":"Codex","identity":{"assurance":"unverified","platform":"macos"},"source":"process-ancestry"},"expected_version":7,"field_id":"password","idempotency_key":"018f1f83-7b2a-7abc-8def-0123456789ab","item_id":"item-123"}`
	if string(actual) != expected {
		t.Fatalf("canonical JSON mismatch\nactual:   %s\nexpected: %s", actual, expected)
	}
}

func TestCanonicalSecretRequestIncludesApplicationAuthorizationScope(t *testing.T) {
	body := createRequest{
		Action: "secret.read",
		AuthorizationScope: &applicationAuthorizationScope{
			ScopeID:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ScopeKind: "application",
		},
		Client: clientObservation{
			Application: "Codex",
			Identity: applicationIdentity{
				Assurance:         applicationAssuranceVerified,
				Platform:          "macos",
				PrincipalScheme:   macOSPrincipalScheme,
				PrincipalID:       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				SigningIdentifier: "com.example.codex",
				TeamIdentifier:    "EXAMPLETEAM",
			},
			Source: "process-ancestry",
		},
		ExpectedVersion: 7,
		FieldID:         "password",
		IdempotencyKey:  "018f1f83-7b2a-7abc-8def-0123456789ab", // gitleaks:allow -- Fixed synthetic UUID test vector.
		ItemID:          "item-123",
	}
	actual, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"action":"secret.read","authorization_scope":{"scope_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","scope_kind":"application"},"client":{"application":"Codex","identity":{"assurance":"verified-code-signature","platform":"macos","principal_id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","principal_scheme":"macos-designated-requirement-v1","signing_identifier":"com.example.codex","team_identifier":"EXAMPLETEAM"},"source":"process-ancestry"},"expected_version":7,"field_id":"password","idempotency_key":"018f1f83-7b2a-7abc-8def-0123456789ab","item_id":"item-123"}`
	if string(actual) != expected {
		t.Fatalf("canonical JSON mismatch\nactual:   %s\nexpected: %s", actual, expected)
	}
}

func TestCanonicalSignatureAndEd25519Vector(t *testing.T) {
	body, err := canonicalJSON(map[string]any{
		"z":                []any{3, map[string]any{"é": "雪", "a": true}},
		"action":           "secret.read",
		"expected_version": 42,
		"field_id":         "password",
		"idempotency_key":  "0190f2d8-b0a4-7000-8000-000000000002",
		"client": map[string]any{
			"application": "Codex",
			"source":      "process-ancestry",
		},
		"item_id": "item_dummy_01",
	})
	if err != nil {
		t.Fatal(err)
	}
	const expectedBody = `{"action":"secret.read","client":{"application":"Codex","source":"process-ancestry"},"expected_version":42,"field_id":"password","idempotency_key":"0190f2d8-b0a4-7000-8000-000000000002","item_id":"item_dummy_01","z":[3,{"a":true,"é":"雪"}]}`
	if string(body) != expectedBody {
		t.Fatalf("shared canonical body mismatch\nactual:   %s\nexpected: %s", body, expectedBody)
	}
	input := signatureInput{
		Audience:  "onenod.example-account.workers.dev",
		Body:      body,
		DeviceID:  "0190f2d8-b0a4-7000-8000-000000000001",
		Method:    "POST",
		Nonce:     "nonce_dummy_01",
		Path:      "/v1/requests",
		Timestamp: 1_784_246_400,
	}
	canonical, err := canonicalSignatureString(input)
	if err != nil {
		t.Fatal(err)
	}
	bodyHash := sha256.Sum256(body)
	if actual := base64.RawURLEncoding.EncodeToString(bodyHash[:]); actual !=
		"NCYFqdZZPzjK6ZuGG-DL2-bHErzPGAp4gfzxnxOIy94" {
		t.Fatalf("shared body hash mismatch: %s", actual)
	}
	expectedCanonical := strings.Join([]string{
		"onenod-request-v1",
		"onenod.example-account.workers.dev",
		"POST",
		"/v1/requests",
		base64.RawURLEncoding.EncodeToString(bodyHash[:]),
		"0190f2d8-b0a4-7000-8000-000000000001",
		"1784246400",
		"nonce_dummy_01",
	}, "\n")
	if canonical != expectedCanonical {
		t.Fatalf("canonical signature string mismatch\nactual:   %q\nexpected: %q", canonical, expectedCanonical)
	}

	seed, err := base64.RawURLEncoding.DecodeString(
		"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if actual := base64.RawURLEncoding.EncodeToString(publicKey); actual !=
		"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" {
		t.Fatalf("shared public key mismatch: %s", actual)
	}
	publicKeyDigest := sha256.Sum256(publicKey)
	if actual := base64.RawURLEncoding.EncodeToString(publicKeyDigest[:]); actual !=
		"If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk" {
		t.Fatalf("shared public key fingerprint mismatch: %s", actual)
	}
	signature := ed25519.Sign(privateKey, []byte(canonical))
	const expectedSignature = "TJVavsyX0UkHGD0hqvGW7J0XJFIUJLK0zZ7hbSP7rNi78jhUJBADp3hKTroW2sDBYFGZ_NOjNl_k_njesA29Cw"
	actualSignature := base64.RawURLEncoding.EncodeToString(signature)
	if actualSignature != expectedSignature {
		t.Fatalf("signature mismatch\nactual:   %s\nexpected: %s", actualSignature, expectedSignature)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), []byte(canonical), signature) {
		t.Fatal("signature did not verify")
	}
}

func TestAPIClientSignsCanonicalBody(t *testing.T) {
	credential, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := new(bytes.Buffer)
		if _, err := body.ReadFrom(request.Body); err != nil {
			t.Fatal(err)
		}
		expectedBody := `{"query":"dummy"}`
		if body.String() != expectedBody {
			t.Fatalf("body mismatch: %s", body.String())
		}
		timestamp := request.Header.Get(headerRequestTimestamp)
		nonce := request.Header.Get(headerRequestNonce)
		if request.Header.Get(headerDeviceID) != credential.DeviceID {
			t.Fatal("device ID header mismatch")
		}
		canonical, err := canonicalSignatureString(signatureInput{
			Audience:  request.URL.Host,
			Body:      []byte(expectedBody),
			DeviceID:  credential.DeviceID,
			Method:    request.Method,
			Nonce:     nonce,
			Path:      request.URL.Path,
			Timestamp: 1_725_000_000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if timestamp != "1725000000" {
			t.Fatalf("unexpected timestamp %q", timestamp)
		}
		signature, err := base64.RawURLEncoding.DecodeString(
			request.Header.Get(headerRequestSignature),
		)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := base64.RawURLEncoding.DecodeString(credential.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if !ed25519.Verify(publicKey, []byte(canonical), signature) {
			t.Fatal("request signature did not verify")
		}
		return &http.Response{
			Body:       ioNopCloser(`{"ok":true}`),
			Header:     make(http.Header),
			StatusCode: http.StatusOK,
		}, nil
	})
	client, err := newAPIClient(
		"https://onenod.example-account.workers.dev",
		credential,
		&http.Client{Transport: transport},
	)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(1_725_000_000, 0) }
	client.random = bytes.NewReader([]byte{
		0, 1, 2, 3, 4, 5, 6, 7,
		8, 9, 10, 11, 12, 13, 14, 15,
	})
	var response map[string]bool
	if err := client.doJSON(
		context.Background(),
		http.MethodPost,
		"/v1/catalog/search",
		catalogSearchRequest{Query: "dummy"},
		&response,
	); err != nil {
		t.Fatal(err)
	}
	if !response["ok"] {
		t.Fatal("response was not decoded")
	}
}

func TestCanonicalJSONRejectsFractions(t *testing.T) {
	_, err := canonicalJSON(map[string]any{"value": 1.5})
	if err == nil {
		t.Fatal("fractional number was accepted")
	}
}

func TestCanonicalJSONUsesTheCrossRuntimeSafeIntegerDomain(t *testing.T) {
	for _, value := range []int64{maximumCanonicalInteger, -maximumCanonicalInteger} {
		if _, err := canonicalJSON(map[string]any{"value": value}); err != nil {
			t.Fatalf("safe integer %d was rejected: %v", value, err)
		}
	}
	for _, value := range []int64{maximumCanonicalInteger + 1, -maximumCanonicalInteger - 1} {
		if _, err := canonicalJSON(map[string]any{"value": value}); err == nil {
			t.Fatalf("unsafe integer %d was accepted", value)
		}
	}
}

func TestCanonicalJSONEscapesHTMLWithoutHTMLSubstitution(t *testing.T) {
	actual, err := canonicalJSON(map[string]string{"value": "<dummy>&\u2028"})
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "{\"value\":\"<dummy>&\u2028\"}" {
		t.Fatalf("unexpected encoding %s", actual)
	}
}
