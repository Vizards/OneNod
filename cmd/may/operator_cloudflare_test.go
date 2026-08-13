package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCloudflareSubdomainPrecheckUsesAuthenticatedAccount(t *testing.T) {
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Hostname() != "api.cloudflare.com" ||
			request.URL.Path != "/client/v4/accounts/"+testCloudflareAccountID+"/workers/subdomain" ||
			request.Header.Get("Authorization") != "Bearer oauth-test-token" {
			t.Fatal("unexpected Cloudflare request")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"subdomain":"human-vault"}}`)), Header: make(http.Header)}, nil
	})
	subdomain, err := fetchCloudflareAccountSubdomain(transport, testCloudflareAccountID, []byte("oauth-test-token"))
	if err != nil || subdomain != "human-vault" {
		t.Fatalf("%q %v", subdomain, err)
	}
}

func TestCloudflareSubdomainPrecheckRejectsRedirectBeforeCredentialCanMoveHosts(t *testing.T) {
	calls := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Hostname() != "api.cloudflare.com" {
			t.Fatal("credential reached another host")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://attacker.example/steal"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})
	_, err := fetchCloudflareAccountSubdomain(transport, testCloudflareAccountID, []byte("oauth-test-token"))
	if err == nil {
		t.Fatal("redirect was accepted")
	}
	if calls != 1 {
		t.Fatalf("transport called %d times", calls)
	}
}

func TestSecureCloudflareClientRejectsUnexpectedHostBeforeTransport(t *testing.T) {
	calls := 0
	client := secureCloudflareAPIClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected transport call")
	}))
	request, err := http.NewRequest(http.MethodGet, "https://attacker.example/steal", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); err == nil {
		t.Fatal("unexpected Cloudflare API host was accepted")
	}
	if calls != 0 {
		t.Fatalf("unsafe request reached the base transport %d times", calls)
	}
}

func TestSecureCloudflareClientDisablesEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://attacker.example")
	client := secureCloudflareAPIClient(nil)
	pinned, ok := client.Transport.(exactHostTransport)
	if !ok {
		t.Fatal("Cloudflare client is not wrapped by the exact-host transport")
	}
	base, ok := pinned.base.(*http.Transport)
	if !ok || base.Proxy != nil {
		t.Fatal("Cloudflare client inherited an environment proxy")
	}
}

func TestRemoteBootstrapStateAcceptsOnlyInitializedJSON(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"initialized":true}`)), Header: make(http.Header)}, nil
	})}
	initialized, err := readRemoteInitializationState(client, "https://onenod.human-vault.workers.dev")
	if err != nil || !initialized {
		t.Fatalf("%v %v", initialized, err)
	}
}

func TestGatewayReadinessWaitsThroughPublicRoutePropagation(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		if request.URL.Path != "/api/health" {
			t.Fatalf("unexpected readiness path %s", request.URL.Path)
		}
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("There is nothing here yet")),
				Header:     http.Header{"content-type": []string{"text/plain"}},
			}, nil
		}
		version := "0.0.2-alpha.12"
		if attempts >= 3 {
			version = "0.0.2-alpha.13"
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"environment":"prod","ok":true,"service":"onenod-gateway","version":"` + version + `"}`)),
			Header:     http.Header{"content-type": []string{"application/json"}},
		}, nil
	})}
	if err := waitForGatewayReadiness(
		context.Background(), client, "https://onenod.human-vault.workers.dev",
		"0.0.2-alpha.13", 100*time.Millisecond, time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("readiness used %d probes, want 3", attempts)
	}
}

func TestRemoteRuntimeVersionWaitsThroughDeploymentPropagation(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		if request.URL.Path != "/api/version" {
			t.Fatalf("unexpected runtime version path %s", request.URL.Path)
		}
		if attempts == 1 {
			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(strings.NewReader("There is nothing here yet")),
				Header:     http.Header{"content-type": []string{"text/plain"}},
			}, nil
		}
		version := "0.0.2-alpha.13"
		if attempts >= 3 {
			version = "0.0.2-alpha.14"
		}
		body := fmt.Sprintf(`{
			"release_channel":"alpha",
			"release_version":%q,
			"components":{
				"executor":{"channel":"alpha","version":%q},
				"gateway":{"accepted_client_protocol":{"min":1,"max":2},"channel":"alpha","protocol":1,"version":%q},
				"pwa":{"channel":"alpha","version":%q}
			}
		}`, version, version, version, version)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{"content-type": []string{"application/json"}},
		}, nil
	})}
	if err := waitForRemoteRuntimeVersion(
		context.Background(), client, "https://onenod.human-vault.workers.dev",
		"0.0.2-alpha.14", 100*time.Millisecond, time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("runtime convergence used %d probes, want 3", attempts)
	}
}

func TestBootstrapCompletionPollsWithoutTerminalConfirmation(t *testing.T) {
	attempts := 0
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts++
		initialized := attempts >= 2
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"initialized":%t}`, initialized))),
			Header:     make(http.Header),
		}, nil
	})}
	if err := waitForRemoteInitialization(
		context.Background(), client, "https://onenod.human-vault.workers.dev",
		100*time.Millisecond, time.Millisecond,
	); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("bootstrap wait used %d probes, want 2", attempts)
	}
}
