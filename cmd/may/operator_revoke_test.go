package main

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorRevokeCloudflareDeletesOnlyReceiptAccountProfiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearCloudflareCredentialEnvironment(t)
	deleted := filepath.Join(home, "deleted-release")
	wrangler := writeWranglerFixture(t, wranglerRevocationFixture(deleted))
	t.Setenv("PATH", filepath.Dir(wrangler)+":/usr/bin:/bin")
	writeOperatorRevokeReceipt(t, false)

	var output strings.Builder
	err := runOperatorRevokeCloudflare(nil, dependencies{
		cloudflareTransport: revocationAccountTransport(t),
		stdin:               strings.NewReader("y\n"),
		stderr:              io.Discard,
		stdout:              &output,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(deleted); err != nil {
		t.Fatalf("receipt-bound Wrangler profile was not deleted: %v", err)
	}
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil || !receipt.CloudflareProfileRevoked {
		t.Fatalf("revocation was not persisted in the operator receipt: %+v, %v", receipt, err)
	}
	for _, expected := range []string{
		"OneNod current-Mac Cloudflare revocation plan",
		"release-profile (used for this operation)",
		"Remote Workers, Durable Objects, traffic, and 1Password data are unchanged",
		"verified that this Mac has no Wrangler profile",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("revocation output omitted %q:\n%s", expected, output.String())
		}
	}
}

func TestOperatorRevokeCloudflareRequiresExplicitConfirmation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearCloudflareCredentialEnvironment(t)
	deleted := filepath.Join(home, "deleted-release")
	wrangler := writeWranglerFixture(t, wranglerRevocationFixture(deleted))
	t.Setenv("PATH", filepath.Dir(wrangler)+":/usr/bin:/bin")
	writeOperatorRevokeReceipt(t, true)

	err := runOperatorRevokeCloudflare(nil, dependencies{
		cloudflareTransport: revocationAccountTransport(t),
		stdin:               strings.NewReader("\n"),
		stderr:              io.Discard,
		stdout:              io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "revocation was not confirmed") {
		t.Fatalf("default-no confirmation did not retain authority: %v", err)
	}
	if _, statErr := os.Stat(deleted); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("Wrangler profile was deleted without an explicit yes")
	}
	receipt, readErr := readOperatorDeploymentReceipt()
	if readErr != nil || receipt.CloudflareProfileRevoked {
		t.Fatalf("retained authority was not reflected in the receipt: %+v, %v", receipt, readErr)
	}
}

func writeOperatorRevokeReceipt(t *testing.T, revoked bool) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, userAgentDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	err = writeOperatorDeploymentReceipt(operatorDeploymentReceipt{
		AccountID:                "0123456789abcdef0123456789abcdef",
		AccountSubdomain:         "dedicated",
		Channel:                  "alpha",
		CloudflareProfile:        "release-profile",
		CloudflareProfileRevoked: revoked,
		DeploymentArtifact:       "onenod-deployment-0.0.2-alpha.10.tar.gz",
		DeploymentArtifactSHA:    "sha256:" + strings.Repeat("a", 64),
		ExecutorVersionID:        "11111111-1111-4111-8111-111111111111",
		ExecutorWorker:           "onenod-executor-test",
		GatewayVersionID:         "22222222-2222-4222-8222-222222222222",
		GatewayWorker:            "onenod-test",
		OnePasswordAccount:       "my.1password.com",
		OnePasswordVaultID:       strings.Repeat("a", 26),
		Origin:                   "https://onenod-test.dedicated.workers.dev",
		RPID:                     "onenod-test.dedicated.workers.dev",
		ReleaseVersion:           "0.0.2-alpha.10",
		SourceCommit:             strings.Repeat("b", 40),
		VAPIDPublicKey:           "public",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func wranglerRevocationFixture(deleted string) string {
	return `
if [ "$1 $3" = "auth --help" ]; then
  exit 0
fi
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ release-profile │ /tmp/onenod │'
  printf '%s\n' '│ unrelated-profile │ - │'
  exit 0
fi
if [ "$1 $2 $3 $4" = "auth token --profile release-profile" ]; then
  if [ -f "` + deleted + `" ]; then exit 1; fi
  printf '%s\n' '{"type":"oauth","token":"receipt-token"}'
  exit 0
fi
if [ "$1 $2 $3 $4" = "auth token --profile unrelated-profile" ]; then
  printf '%s\n' '{"type":"oauth","token":"unrelated-token"}'
  exit 0
fi
if [ "$1 $2 $3" = "auth delete release-profile" ]; then
  : > "` + deleted + `"
  exit 0
fi
exit 2
`
}

func revocationAccountTransport(t *testing.T) http.RoundTripper {
	t.Helper()
	return roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var body string
		switch request.Header.Get("Authorization") {
		case "Bearer receipt-token":
			body = `{"success":true,"result":[{"id":"0123456789abcdef0123456789abcdef","name":"Dedicated"}]}`
		case "Bearer unrelated-token":
			body = `{"success":true,"result":[{"id":"ffffffffffffffffffffffffffffffff","name":"Unrelated"}]}`
		default:
			t.Fatalf("unexpected Cloudflare authorization %q", request.Header.Get("Authorization"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     make(http.Header),
		}, nil
	})
}

func clearCloudflareCredentialEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
		"CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL",
	} {
		t.Setenv(name, "")
	}
}
