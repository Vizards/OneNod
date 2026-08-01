package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPollingCapabilityUsesUnsignedBodylessGet(t *testing.T) {
	t.Parallel()
	credential, err := credentialFromSeed("poll-test")
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("A", 43)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet {
			t.Fatalf("poll method = %q, want GET", request.Method)
		}
		if request.URL.Path != "/v1/requests/request-1/status" {
			t.Fatalf("poll path = %q", request.URL.Path)
		}
		if request.Header.Get("authorization") != "Bearer "+token {
			t.Fatal("polling capability was not sent as an exact bearer")
		}
		for _, header := range []string{
			headerDeviceID,
			headerRequestNonce,
			headerRequestSignature,
			headerRequestTimestamp,
		} {
			if request.Header.Get(header) != "" {
				t.Fatalf("poll unexpectedly carried signed-request header %q", header)
			}
		}
		if request.Body != nil {
			body, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if len(body) != 0 {
				t.Fatal("poll unexpectedly carried a request body")
			}
		}
		return jsonHTTPResponse(http.StatusOK, `{"request_id":"request-1","status":"pending"}`), nil
	})
	client, err := newAPIClient(
		"https://onenod.example-account.workers.dev",
		credential,
		&http.Client{Transport: transport},
	)
	if err != nil {
		t.Fatal(err)
	}
	var response requestStatusResponse
	if err := client.doPollingJSON(
		context.Background(),
		"/v1/requests/request-1/status",
		token,
		&response,
	); err != nil {
		t.Fatal(err)
	}
	if response.RequestID != "request-1" || response.Status != "pending" {
		t.Fatalf("unexpected poll response: %+v", response)
	}
}

func TestPollingCapabilityRejectsMalformedTokensBeforeNetwork(t *testing.T) {
	t.Parallel()
	credential, err := credentialFromSeed("poll-test")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	client, err := newAPIClient(
		"https://onenod.example-account.workers.dev",
		credential,
		&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return nil, nil
		})},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.doPollingJSON(
		context.Background(),
		"/v1/requests/request-1/status",
		"not-a-capability",
		&map[string]any{},
	); err == nil {
		t.Fatal("malformed polling capability was accepted")
	}
	if called {
		t.Fatal("malformed polling capability reached the network")
	}
}
