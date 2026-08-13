package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCloudflareAccountID = "0123456789abcdef0123456789abcdef"
const testOnePasswordAccount = "my.1password.com"

const (
	testTargetWorkerVersion = "11111111-1111-4111-8111-111111111111"
	testPriorWorkerVersion  = "22222222-2222-4222-8222-222222222222"
)

func testProductionIdentity() productionTargetIdentity {
	return productionTargetIdentity{
		AccountID: testCloudflareAccountID, AccountSubdomain: "human-vault",
		ExecutorName: defaultExecutorWorkerBaseName, GatewayName: defaultGatewayWorkerBaseName,
		Origin: "https://onenod.human-vault.workers.dev", RPID: "onenod.human-vault.workers.dev",
	}
}

func testServiceAccountToken() string { return "ops_" + strings.Repeat("a", 32) }

func testOnePasswordProvisioning() onePasswordProvisioning {
	return onePasswordProvisioning{
		Account:            testOnePasswordAccount,
		AgentVault:         humanRecoveryVault{ID: "abcdefghijklmnopqrstuvwxya", Name: defaultAgentVaultName},
		RecoveryVault:      humanRecoveryVault{ID: "abcdefghijklmnopqrstuvwxyb", Name: defaultRecoveryVaultName},
		ServiceAccountName: defaultServiceAccountName, ServiceAccountToken: testServiceAccountToken(),
		ServiceAccountTokenItem: "service-account-token-item",
	}
}

func dedicatedAccountTransport(t *testing.T, expectedToken string) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer "+expectedToken ||
			request.URL.Path != "/client/v4/accounts" {
			t.Fatal("unexpected Cloudflare account request")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"success":true,"result":[{"id":"0123456789abcdef0123456789abcdef","name":"Dedicated"}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})
}

func indexOfString(values []string, expected string) int {
	for index, value := range values {
		if value == expected {
			return index
		}
	}
	return -1
}

func writeWranglerFixture(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wrangler")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
