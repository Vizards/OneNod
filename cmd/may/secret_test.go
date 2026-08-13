package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

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
	t.Setenv("HOME", t.TempDir())
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
			if request.Header.Get("authorization") !=
				"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
				t.Fatal("secret consume did not require its polling capability")
			}
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
