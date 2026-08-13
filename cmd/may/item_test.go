package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
			if request.Header.Get("authorization") !=
				"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" {
				t.Fatal("item consume did not require its polling capability")
			}
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
