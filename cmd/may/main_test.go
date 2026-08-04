package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultRequesterDisplayNameIsUsable(t *testing.T) {
	t.Parallel()
	name := defaultRequesterDisplayName()
	if strings.TrimSpace(name) == "" {
		t.Fatal("default requester display name is empty")
	}
	if len([]rune(name)) > 80 {
		t.Fatalf("default requester display name has %d runes, want at most 80", len([]rune(name)))
	}
}

func TestCommandHelpRunsBeforeConfigurationCredentialsAndNetwork(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, userAgentEnvFileName), []byte("BROKEN=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, args := range [][]string{
		{"--help"},
		{"help", "version"},
		{"version", "--help"},
		{"install", "--help"},
		{"preflight", "--help"},
		{"enroll", "-h"},
		{"catalog", "search", "--help"},
		{"read", "--help"},
		{"secret", "read", "--help"},
		{"item", "create", "--help"},
		{"item", "patch", "--help"},
		{"item", "archive", "--help"},
		{"ssh", "public-key", "export", "--help"},
		{"agent", "status", "--help"},
		{"configure", "ssh", "--help"},
		{"configure", "git-signing", "apply", "--help"},
		{"update", "check", "--help"},
		{"dev", "verify-release", "--help"},
		{"operator", "init", "--help"},
		{"operator", "revoke-cloudflare", "--help"},
		{"--origin", "https://ignored.example.workers.dev", "catalog", "search", "--help"},
	} {
		name := strings.NewReplacer("-", "_", " ", "_").Replace(strings.Join(args, "_"))
		t.Run(name, func(t *testing.T) {
			var stderr bytes.Buffer
			backend := &recordingKeychainBackend{
				loadErr: errors.New("credentials must not be loaded for help"),
			}
			err := runCLI(args, dependencies{
				keychain: keychainStore{backend: backend},
				stderr:   &stderr,
				stdin:    strings.NewReader(""),
				stdout:   io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			if strings.TrimSpace(stderr.String()) == "" {
				t.Fatal("help output was empty")
			}
			if backend.account != "" {
				t.Fatal("help loaded requester credentials")
			}
		})
	}
}

func TestCatalogQueryNamedHelpIsNotAHelpFlag(t *testing.T) {
	if _, ok := requestedHelp([]string{"catalog", "search", "help"}); ok {
		t.Fatal("a literal catalog query named help was treated as CLI help")
	}
}

func TestCanonicalJSONVector(t *testing.T) {
	body := createRequest{
		Action:          "secret.read",
		Client:          clientObservation{Application: "Codex", Source: "process-ancestry"},
		ExpectedVersion: 7,
		FieldID:         "password",
		IdempotencyKey:  "018f1f83-7b2a-7abc-8def-0123456789ab", // gitleaks:allow -- Fixed synthetic UUID test vector.
		ItemID:          "item-123",
	}
	actual, err := canonicalJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"action":"secret.read","client":{"application":"Codex","source":"process-ancestry"},"expected_version":7,"field_id":"password","idempotency_key":"018f1f83-7b2a-7abc-8def-0123456789ab","item_id":"item-123"}`
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

func TestProductionInitializerExposesOnlyTheOneShotInitCommand(t *testing.T) {
	err := runOperator([]string{"vapid"}, dependencies{})
	if err == nil || !strings.Contains(err.Error(), "operator init") {
		t.Fatalf("unsupported operator command returned %v", err)
	}
	err = runOperator([]string{"init", "status"}, dependencies{})
	if err == nil || !strings.Contains(err.Error(), "operator init") {
		t.Fatalf("retired initializer subcommand returned %v", err)
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

func TestSecretValueIsSuppressedWithoutRaw(t *testing.T) {
	response := secretConsumeResponse{}
	value := "dummy-secret"
	response.Value = &value
	actual, ok := response.secretValue()
	if !ok || actual != value {
		t.Fatal("consume value was not decoded")
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := emitConsumedSecret(&stdout, &stderr, actual, false); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatal("secret was written to stdout without --raw")
	}
	if strings.Contains(stderr.String(), value) {
		t.Fatal("secret was written to diagnostics")
	}
}

func TestReferenceReadResolvesExactItemAndFieldThenPrintsOnlyTheValue(t *testing.T) {
	credential, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	encodedCredential, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "dummy-reference-value"
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		switch request.URL.Path {
		case "/v1/catalog/search":
			return jsonHTTPResponse(http.StatusOK, `{"items":[{
				"category":"ApiCredentials",
				"fields":[{"field_id":"token","field_type":"Concealed","label":"API token"}],
				"item_id":"item-123",
				"title":"Dummy API",
				"updated_at":"2026-07-27T00:00:00Z",
				"version":4
			}]}`), nil
		case "/v1/requests":
			var body createRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.ItemID != "item-123" || body.FieldID != "token" ||
				body.ExpectedVersion != 4 || body.Client.Application == "" ||
				(body.Client.Source != "process-ancestry" && body.Client.Source != "unavailable") {
				t.Fatalf("unexpected reference request: %+v", body)
			}
			return jsonHTTPResponse(http.StatusCreated, `{
				"expires_at":"2099-01-01T00:00:00Z",
				"poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"request_id":"request-reference-1",
				"status":"approved"
			}`), nil
		case "/v1/requests/request-reference-1/consume":
			return jsonHTTPResponse(http.StatusOK, `{
				"ok":true,
				"request_id":"request-reference-1",
				"status":"consumed",
				"value":"dummy-reference-value"
			}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = runCLI(
		[]string{
			"--origin", "https://onenod.example-account.workers.dev",
			"read", "--no-newline", "op://Agent/Dummy%20API/API%20token",
		},
		dependencies{
			httpClient: &http.Client{Transport: transport},
			keychain: keychainStore{backend: &recordingKeychainBackend{
				found: true, output: encodedCredential,
			}},
			stderr: &stderr,
			stdout: &stdout,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 3 || stdout.String() != secret ||
		strings.Contains(stderr.String(), secret) {
		t.Fatalf("unexpected reference read result: count=%d stdout=%q stderr=%q", requestCount, stdout.String(), stderr.String())
	}
}

func TestItemCreateUsesClosedStdinSpecAndNeverLogsFieldValues(t *testing.T) {
	credential, err := credentialFromSeed("test-requester")
	if err != nil {
		t.Fatal(err)
	}
	encodedCredential, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	backend := &recordingKeychainBackend{found: true, output: encodedCredential}
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		switch request.URL.Path {
		case "/v1/requests":
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			var value itemCreateRequest
			if err := json.Unmarshal(body, &value); err != nil {
				t.Fatal(err)
			}
			if value.Action != "item.create" || value.Category != "ApiCredentials" {
				t.Fatalf("unexpected item request: %#v", value)
			}
			if len(value.Fields) != 2 || value.Fields[0].FieldID != "alpha" ||
				value.Fields[1].FieldID != "zulu" {
				t.Fatalf("fields were not deterministically sorted: %#v", value.Fields)
			}
			return jsonHTTPResponse(http.StatusCreated, `{"expires_at":"2099-01-01T00:00:00Z","poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","request_id":"request-1","status":"pending"}`), nil
		case "/v1/requests/request-1/status":
			if request.Method != http.MethodGet || request.Header.Get("authorization") != "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
				t.Fatal("status polling did not use the read-only capability contract")
			}
			return jsonHTTPResponse(http.StatusOK, `{"expires_at":"2099-01-01T00:00:00Z","request_id":"request-1","status":"approved"}`), nil
		case "/v1/requests/request-1/consume":
			return jsonHTTPResponse(http.StatusOK, `{"item_id":"item-created","ok":true,"request_id":"request-1","status":"consumed","version":1}`), nil
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
			return nil, nil
		}
	})
	const secret = "dummy-secret-value"
	spec := `{"category":"ApiCredentials","fields":[{"field_id":"zulu","field_type":"Concealed","label":"Zulu","value":"` + secret + `"},{"field_id":"alpha","field_type":"Text","label":"Alpha","value":"dummy-public"}],"title":"Created by test"}`
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err = runCLI(
		[]string{
			"--origin", "https://onenod.example-account.workers.dev",
			"item", "create", "--spec", "-",
		},
		dependencies{
			httpClient: &http.Client{Transport: transport},
			keychain:   keychainStore{backend: backend},
			stderr:     &stderr,
			stdin:      strings.NewReader(spec),
			stdout:     &stdout,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 3 {
		t.Fatalf("unexpected request count %d", requestCount)
	}
	if strings.Contains(stderr.String(), secret) || strings.Contains(stdout.String(), secret) {
		t.Fatal("item field value was exposed in CLI output")
	}
	if !strings.Contains(stdout.String(), `"item_id":"item-created"`) {
		t.Fatalf("safe result was not written to stdout: %s", stdout.String())
	}
}

func TestItemPatchRejectsOperationFieldsThatDoNotMatchTheOperation(t *testing.T) {
	value := "dummy"
	fieldType := "Text"
	spec := itemPatchSpec{Operations: []itemPatchOperation{
		{FieldID: "field-1", FieldType: &fieldType, Op: "replace", Value: &value},
	}}
	if err := validatePatchSpec(&spec); err == nil {
		t.Fatal("replace operation accepted an add-only field_type")
	}
}

func TestSSHKeyCreateSpecHasOneExactPrivateKeyField(t *testing.T) {
	privateKey := "-----BEGIN " + "PRIVATE KEY-----\nZHVtbXk=\n-----END " + "PRIVATE KEY-----\n"
	valid := itemCreateSpec{
		Category: "SshKey",
		Fields: []itemCreateFieldSpec{{
			FieldID: "private_key", FieldType: "SshKey", Label: "private key", Value: &privateKey,
		}},
		Title: "Disposable SSH fixture",
	}
	if _, err := validateCreateSpec(valid); err != nil {
		t.Fatalf("valid SSH Key spec failed: %v", err)
	}

	invalidField := valid
	invalidField.Fields = append([]itemCreateFieldSpec(nil), valid.Fields...)
	invalidField.Fields[0].FieldID = "key"
	if _, err := validateCreateSpec(invalidField); err == nil {
		t.Fatal("SSH Key spec accepted a non-built-in field ID")
	}

	wrongCategory := valid
	wrongCategory.Category = "SecureNote"
	if _, err := validateCreateSpec(wrongCategory); err == nil {
		t.Fatal("non-SSH category accepted an SSH key field")
	}
}

func TestItemSpecRejectsUnknownJSONFields(t *testing.T) {
	var spec itemCreateSpec
	err := readStrictSpec(
		"-",
		strings.NewReader(`{"category":"SecureNote","fields":[],"title":"dummy","unexpected":true}`),
		&spec,
	)
	if err == nil {
		t.Fatal("item spec accepted an unknown JSON field")
	}
}

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

func TestCanonicalJSONEscapesHTMLWithoutHTMLSubstitution(t *testing.T) {
	actual, err := canonicalJSON(map[string]string{"value": "<dummy>&\u2028"})
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "{\"value\":\"<dummy>&\u2028\"}" {
		t.Fatalf("unexpected encoding %s", actual)
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
