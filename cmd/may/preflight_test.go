package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequesterPreflightChecksCoreWithoutRequiringEnrollment(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := healthyPreflightServer(t)
	defer server.Close()
	var output strings.Builder
	err := runCLI(
		[]string{"--origin", server.URL, "preflight"},
		dependencies{
			httpClient: server.Client(),
			keychain: keychainStore{
				backend: &recordingKeychainBackend{found: false},
			},
			stderr: io.Discard,
			stdout: &output,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	var report requesterPreflightReport
	if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Origin != server.URL || report.Gateway.Environment != "prod" ||
		report.Channel != "stable" ||
		report.GatewayCrypto != "not_checked_anonymously" ||
		report.HumanIdentity != "not_checked_anonymously" ||
		report.Executor.Declared != true || report.Executor.Version != "0.2.0" ||
		report.LocalFallback.Configured || report.LocalFallback.AgentConfig != "not detected" ||
		report.LocalFallback.SSHAgent != "not detected" ||
		report.Requester.LocalCredential != "absent" {
		t.Fatalf("unexpected preflight report %+v", report)
	}
}

func TestRequesterPreflightReportsOnlyPublicRequesterIdentity(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := healthyPreflightServer(t)
	defer server.Close()
	credential, err := credentialFromSeed("test-agent-device")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	err = runCLI(
		[]string{"--origin", server.URL, "preflight"},
		dependencies{
			httpClient: server.Client(),
			keychain: keychainStore{
				backend: &recordingKeychainBackend{found: true, output: encoded},
			},
			stderr: io.Discard,
			stdout: &output,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, credential.PrivateKey) {
		t.Fatal("preflight output exposed requester private key")
	}
	for _, expected := range []string{
		credential.DeviceID,
		credential.DisplayName,
		`"local_credential": "present"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("preflight output omitted %q", expected)
		}
	}
}

func TestRequesterPreflightFailsClosedOnUndeclaredExecutor(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/api/health":
			_, _ = io.WriteString(response, `{"environment":"prod","ok":true,"service":"onenod-gateway","version":"0.2.0"}`)
		case "/api/version":
			_, _ = io.WriteString(response, staticVersionResponse(false))
		default:
			t.Fatalf("unexpected request after failed Executor gate: %s", request.URL.Path)
		}
	}))
	defer server.Close()
	err := runCLI(
		[]string{"--origin", server.URL, "preflight"},
		dependencies{
			httpClient: server.Client(),
			keychain: keychainStore{
				backend: &recordingKeychainBackend{found: false},
			},
			stderr: io.Discard,
			stdout: io.Discard,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "incompatible release declaration") {
		t.Fatalf("undeclared Executor preflight returned %v", err)
	}
}

func TestRequesterPreflightFailsClosedOnReleaseChannelMismatch(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("content-type", "application/json")
		switch request.URL.Path {
		case "/api/health":
			_, _ = io.WriteString(response, `{"environment":"prod","ok":true,"service":"onenod-gateway","version":"0.2.0"}`)
		case "/api/version":
			var value map[string]any
			if err := json.Unmarshal([]byte(staticVersionResponse(true)), &value); err != nil {
				t.Fatal(err)
			}
			value["release_channel"] = "beta"
			_ = json.NewEncoder(response).Encode(value)
		default:
			t.Fatalf("unexpected preflight path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	err := runCLI(
		[]string{"--origin", server.URL, "preflight"},
		dependencies{
			httpClient: server.Client(),
			keychain: keychainStore{
				backend: &recordingKeychainBackend{found: false},
			},
			stderr: io.Discard,
			stdout: io.Discard,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "incompatible release declaration") {
		t.Fatalf("mismatched release channel preflight returned %v", err)
	}
}

func healthyPreflightServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("content-type", "application/json; charset=utf-8")
		switch request.URL.Path {
		case "/api/health":
			_, _ = io.WriteString(response, `{"environment":"prod","ok":true,"service":"onenod-gateway","version":"0.2.0"}`)
		case "/api/version":
			_, _ = io.WriteString(response, staticVersionResponse(true))
		default:
			t.Fatalf("unexpected preflight path %s", request.URL.Path)
		}
	}))
}

func staticVersionResponse(executorDeclared bool) string {
	encoded, _ := json.Marshal(map[string]any{
		"ok":              true,
		"service":         "onenod-gateway",
		"release_channel": "stable",
		"release_version": "0.2.0",
		"source_commit":   "0123456789abcdef0123456789abcdef01234567",
		"components": map[string]any{
			"gateway": map[string]any{
				"channel":                  "stable",
				"version":                  "0.2.0",
				"accepted_client_protocol": map[string]int{"min": 1, "max": 1},
			},
			"executor": map[string]any{
				"declared": executorDeclared,
				"channel":  "stable",
				"version":  "0.2.0",
			},
			"pwa": map[string]any{"channel": "stable", "version": "0.2.0"},
		},
	})
	return string(encoded)
}
