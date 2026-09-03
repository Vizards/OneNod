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

func TestGatewayErrorHeaderExposesOnlyOneStableSafeCode(t *testing.T) {
	t.Parallel()
	credential, err := credentialFromSeed("error-code-test")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		header string
		status int
		want   string
	}{
		{header: "executor_internal_error", status: http.StatusServiceUnavailable, want: "gateway returned executor_internal_error (HTTP 503)"},
		{header: "executor_internal_error", status: http.StatusBadRequest, want: "gateway returned HTTP 400"},
		{header: "onepassword_rate_limited", status: http.StatusTooManyRequests, want: "gateway returned onepassword_rate_limited (HTTP 429)"},
		{header: "onepassword_rate_limited", status: http.StatusBadGateway, want: "gateway returned HTTP 502"},
		{header: "private_item_identifier", status: http.StatusTooManyRequests, want: "gateway returned HTTP 429"},
		{header: "secret value", status: http.StatusTooManyRequests, want: "gateway returned HTTP 429"},
	}
	for _, test := range tests {
		client, createErr := newAPIClient(
			"https://onenod.example-account.workers.dev",
			credential,
			&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				response := jsonHTTPResponse(test.status, `{"ok":false}`)
				response.Header.Set(headerGatewayErrorCode, test.header)
				return response, nil
			})},
		)
		if createErr != nil {
			t.Fatal(createErr)
		}
		err = client.doPollingJSON(
			context.Background(),
			"/v1/requests/request-1/status",
			strings.Repeat("A", 43),
			&map[string]any{},
		)
		if err == nil || err.Error() != test.want {
			t.Fatalf("error = %v, want %q", err, test.want)
		}
	}
}
