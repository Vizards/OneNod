package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestItemMutationsCarryBeholderDecisionToGateway(t *testing.T) {
	const evidenceID = "item-decision-0123456789abcdef"
	const secret = "dummy-item-mutation-secret"
	cases := []struct {
		name string
		args []string
		spec string
	}{
		{"create", []string{"create", "--spec", "-"}, `{"category":"ApiCredentials","fields":[{"field_id":"credential","field_type":"Concealed","label":"Credential","value":"` + secret + `"}],"title":"Disposable fixture"}`},
		{"patch", []string{"patch", "--item", "item-1", "--expected-version", "3", "--spec", "-"}, `{"operations":[{"field_id":"credential","op":"replace","value":"` + secret + `"}]}`},
		{"archive", []string{"archive", "--item", "item-1", "--expected-version", "3"}, ""},
	}
	for _, test := range cases {
		for _, decision := range []string{"allow", "escalate"} {
			t.Run(test.name+"/"+decision, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				t.Setenv("CODEX_THREAD_ID", "item-mutation-fixture-task")
				credential, err := credentialFromSeed("test-requester")
				if err != nil {
					t.Fatal(err)
				}
				encodedCredential, err := json.Marshal(credential)
				if err != nil {
					t.Fatal(err)
				}
				observedDigest := ""
				observedTrace := ""
				created := false
				consumed := false
				deps := dependencies{
					keychain: keychainStore{backend: &recordingKeychainBackend{found: true, output: encodedCredential}},
					stdin:    strings.NewReader(test.spec), stdout: io.Discard, stderr: io.Discard,
					beholder: func(request beholderWireRequest) (beholderWireResponse, error) {
						response := beholderWireResponse{SchemaVersion: 1, Accepted: true, EvidenceID: evidenceID}
						if request.Kind == "human-outcome" {
							return response, nil
						}
						if request.Kind != "direct-operation" || request.Operation == nil ||
							request.Operation.Operation != "item."+test.name {
							t.Fatalf("unexpected Core observation: %+v", request)
						}
						encoded, err := json.Marshal(request)
						if err != nil || bytes.Contains(encoded, []byte(secret)) {
							t.Fatal("item field value crossed the Core observation boundary")
						}
						observedDigest = request.Operation.PayloadDigest
						observedTrace = request.TraceID
						called := true
						response.ModelCalled = &called
						response.Disposition = decision
						if decision == "allow" {
							now := time.Now().Unix()
							response.Authorization = &beholderAuthorization{
								SchemaVersion: 1, Decision: "allow", EvidenceID: evidenceID,
								IssuedAt: now, ExpiresAt: now + 30,
								KeyID: strings.Repeat("k", 43), Signature: strings.Repeat("s", 86),
								OperationTargetSHA256: observedDigest, RequesterDeviceID: credential.DeviceID,
							}
						}
						return response, nil
					},
				}
				deps.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Path {
					case "/v1/requests":
						created = true
						var body map[string]any
						if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
							t.Fatal(err)
						}
						if observedDigest == "" || body["action"] != "item."+test.name {
							t.Fatal("item request was not observed before submission")
						}
						if decision == "allow" {
							authorization, ok := body["beholder_authorization"].(map[string]any)
							if !ok || authorization["evidence_id"] != evidenceID ||
								authorization["operation_target_sha256"] != observedDigest {
								t.Fatal("item request lost its exact Core authorization")
							}
							delete(body, "beholder_authorization")
						} else {
							if body["beholder_authorization"] != nil {
								t.Fatal("escalation attached an allow authorization")
							}
							client, ok := body["client"].(map[string]any)
							if !ok {
								t.Fatal("item request lost its client context")
							}
							diagnostic, ok := client["beholder_diagnostic"].(map[string]any)
							if !ok || diagnostic["trace_id"] != observedTrace ||
								diagnostic["evidence_id"] != evidenceID || diagnostic["code"] != "model-escalated" {
								t.Fatal("item request lost its human-fallback diagnostic")
							}
							delete(client, "beholder_diagnostic")
						}
						canonical, err := canonicalJSON(body)
						if err != nil {
							t.Fatal(err)
						}
						digest := sha256.Sum256(canonical)
						if hex.EncodeToString(digest[:]) != observedDigest {
							t.Fatal("submitted item content differs from the observed request")
						}
						return jsonHTTPResponse(http.StatusCreated, `{"expires_at":"2099-01-01T00:00:00Z","poll_token":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","request_id":"request-item-1","status":"approved"}`), nil
					case "/v1/requests/request-item-1/consume":
						consumed = true
						return jsonHTTPResponse(http.StatusOK, `{"item_id":"item-1","ok":true,"request_id":"request-item-1","status":"consumed","version":4}`), nil
					default:
						t.Fatalf("unexpected Gateway path %q", request.URL.Path)
						return nil, nil
					}
				})}
				args := append([]string{"--origin", "https://onenod.example-account.workers.dev", "item"}, test.args...)
				if err := runCLI(args, deps); err != nil {
					t.Fatal(err)
				}
				if !created || !consumed {
					t.Fatal("item mutation did not complete its request lifecycle")
				}
			})
		}
	}
}

func TestItemCreateUsesClosedStdinSpecAndNeverLogsFieldValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
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
