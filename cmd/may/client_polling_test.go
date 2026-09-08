package main

import (
	"context"
	"errors"
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

func TestGatewayErrorHeaderExposesOnlyStableCodesWithMatchingStatus(t *testing.T) {
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
		{header: "executor_unavailable", status: http.StatusBadGateway, want: "gateway returned executor_unavailable (HTTP 502)"},
		{header: "executor_unavailable", status: http.StatusGatewayTimeout, want: "gateway returned HTTP 504"},
		{header: "executor_timeout", status: http.StatusGatewayTimeout, want: "gateway returned executor_timeout (HTTP 504)"},
		{header: "executor_timeout", status: http.StatusBadGateway, want: "gateway returned HTTP 502"},
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

func TestGatewayErrorIncludesOnlyValidatedRayIDAndNeverResponseBody(t *testing.T) {
	t.Parallel()
	credential, err := credentialFromSeed("ray-id-test")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		code    string
		rays    []string
		wantRay string
	}{
		{name: "worker failure", code: "executor_unavailable", rays: []string{"0123456789abcdef-HKG"}, wantRay: "0123456789abcdef-HKG"},
		{name: "edge failure", rays: []string{"0123456789abcdef-HKG"}, wantRay: "0123456789abcdef-HKG"},
		{name: "bare id", rays: []string{"0123456789abcdef"}, wantRay: "0123456789abcdef"},
		{name: "uppercase hex", rays: []string{"0123456789ABCDEF-SJC"}, wantRay: "0123456789ABCDEF-SJC"},
		{name: "missing"},
		{name: "empty", rays: []string{""}},
		{name: "unknown code", code: "private-error-canary", rays: []string{"0123456789abcdef"}, wantRay: "0123456789abcdef"},
		{name: "wrong status for quota", code: "onepassword_rate_limited", rays: []string{"0123456789abcdef"}, wantRay: "0123456789abcdef"},
		{name: "oversized", rays: []string{strings.Repeat("a", 1000)}},
		{name: "short", rays: []string{"0123-HKG"}},
		{name: "not hex", rays: []string{"0123456789abcdeg-HKG"}},
		{name: "private suffix", rays: []string{"0123456789abcdef-private-item"}},
		{name: "newline", rays: []string{"0123456789abcdef\nprivate-item"}},
		{name: "whitespace", rays: []string{" 0123456789abcdef"}},
		{name: "unicode", rays: []string{"0123456789abcdef-香港"}},
		{name: "joined", rays: []string{"0123456789abcdef,0123456789abcdef"}},
		{name: "duplicate", rays: []string{"0123456789abcdef", "0123456789abcdef"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, createErr := newAPIClient(
				"https://onenod.example-account.workers.dev", credential,
				&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					response := jsonHTTPResponse(http.StatusBadGateway, `{"error":"private-body-canary"}`)
					response.Header.Set(headerGatewayErrorCode, test.code)
					for _, ray := range test.rays {
						response.Header.Add("cf-ray", ray)
					}
					return response, nil
				})},
			)
			if createErr != nil {
				t.Fatal(createErr)
			}
			err := client.doPollingJSON(context.Background(), "/v1/requests/request-1/status", strings.Repeat("A", 43), &map[string]any{})
			var gatewayError *gatewayHTTPError
			if !errors.As(err, &gatewayError) || gatewayError.RayID != test.wantRay {
				t.Fatalf("error = %v, want validated Ray ID %q", err, test.wantRay)
			}
			want := "gateway returned HTTP 502"
			if test.code == "executor_unavailable" {
				want = "gateway returned executor_unavailable (HTTP 502)"
			}
			if test.wantRay != "" {
				want += " (CF Ray ID: " + test.wantRay + ")"
			}
			if err.Error() != want {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
			if isGatewayErrorCode(err, "onepassword_rate_limited") {
				t.Fatal("diagnostics must not enable quota fallback on HTTP 502")
			}
		})
	}
}

func TestGatewayRayIDPreservesQuotaErrorClassification(t *testing.T) {
	t.Parallel()
	err := &gatewayHTTPError{
		Code: "onepassword_rate_limited", Status: http.StatusTooManyRequests, RayID: "0123456789abcdef-HKG",
	}
	if !isGatewayErrorCode(err, "onepassword_rate_limited") {
		t.Fatal("correlation diagnostics changed the authenticated quota fallback trigger")
	}
}
