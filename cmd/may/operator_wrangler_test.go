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

func TestWranglerProfileInspectionUsesNamedOAuthTokenInsteadOfWhoami(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "calls")
	wrangler := writeWranglerFixture(t, `
printf '%s\n' "$*" >> "`+logPath+`"
if [ "$1 $2" = "auth token" ] && [ "$3 $4" = "--profile onenod-operator-test" ]; then
  printf '%s\n' '{"type":"oauth","token":"profile-oauth-token"}'
  exit 0
fi
exit 9
`)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Scheme != "https" || request.URL.Hostname() != "api.cloudflare.com" ||
			request.URL.Path != "/client/v4/accounts" ||
			request.URL.Query().Get("page") != "1" ||
			request.URL.Query().Get("per_page") != "50" ||
			request.Header.Get("Authorization") != "Bearer profile-oauth-token" {
			t.Fatal("unexpected Cloudflare accounts request")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"success":true,"result":[{"id":"` + testCloudflareAccountID + `","name":"Dedicated"}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	identity, err := inspectWranglerIdentity(wrangler, "onenod-operator-test", transport)
	if err != nil || identity.AuthType != "OAuth Token" || len(identity.Accounts) != 1 ||
		identity.Accounts[0].ID != testCloudflareAccountID {
		t.Fatalf("named Wrangler profile inspection failed: %+v, %v", identity, err)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "whoami") ||
		!strings.Contains(string(calls), "auth token --profile onenod-operator-test --json") {
		t.Fatalf("unexpected Wrangler identity commands: %s", calls)
	}
}

func TestBestEffortWranglerProfileCleanupDeletesAndVerifies(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "wrangler")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$(dirname "$0")/calls"
if [ "$1" = "auth" ] && [ "$2" = "token" ]; then
  exit 1
fi
exit 0
`
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if !bestEffortDeleteWranglerProfile(executable, "onenod-operator-test") {
		t.Fatal("temporary Wrangler profile cleanup was not verified")
	}
	calls, err := os.ReadFile(filepath.Join(directory, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(calls)
	if !strings.Contains(text, "auth delete onenod-operator-test") ||
		!strings.Contains(text, "auth token --profile onenod-operator-test --json") {
		t.Fatalf("unexpected cleanup commands: %s", text)
	}
}

func TestExplicitWranglerProfileRetentionSkipsDeletion(t *testing.T) {
	deleteLog := filepath.Join(t.TempDir(), "deleted")
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ password-gateway-release │ /tmp/project │'
  exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3 $4" = "--profile password-gateway-release" ]; then
  printf '%s\n' '{"type":"oauth","token":"release-token"}'
  exit 0
fi
if [ "$1 $2" = "auth delete" ]; then
  printf '%s\n' "$3" >> "`+deleteLog+`"
  exit 0
fi
exit 2
`)
	input := strings.NewReader("n\n")
	console := operatorConsole{
		stdin: input, stdout: io.Discard, stderr: io.Discard,
	}
	revoked, err := promptAndRevokeWranglerProfile(
		wrangler,
		"password-gateway-release",
		"0123456789abcdef0123456789abcdef",
		dedicatedAccountTransport(t, "release-token"),
		&console,
		true,
	)
	if err != nil || revoked {
		t.Fatalf("explicit retention should succeed without deletion: revoked=%v err=%v", revoked, err)
	}
	if _, statErr := os.Stat(deleteLog); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("retained Wrangler profile was deleted")
	}
}

func TestParseWranglerProfilesAcceptsExperimentalOutputAndANSIWarnings(t *testing.T) {
	output := []byte("\x1b[33mWARNING experimental\x1b[0m\n" +
		"┌──────────────────────────┬────────────────────┐\n" +
		"│ Profile                  │ Bound Directories  │\n" +
		"├──────────────────────────┼────────────────────┤\n" +
		"│ default                  │ -                  │\n" +
		"├──────────────────────────┼────────────────────┤\n" +
		"│ onenod-operator-deadbeef │ /tmp/project       │\n" +
		"└──────────────────────────┴────────────────────┘\n")
	profiles, err := parseWranglerProfiles(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(profiles, ",") != "default,onenod-operator-deadbeef" {
		t.Fatalf("unexpected profiles: %v", profiles)
	}
}

func TestParseWranglerProfilesFailsClosedOnUnknownShapeAndDuplicates(t *testing.T) {
	for _, output := range []string{
		"default\n",
		"│ Profile │ Bound Directories │\n│ default │ - │\n│ default │ /tmp │\n",
		"│ Profile │ Bound Directories │\n│ unsafe profile │ - │\n",
	} {
		if profiles, err := parseWranglerProfiles([]byte(output)); err == nil {
			t.Fatalf("unsafe profile output was accepted: %v", profiles)
		}
	}
}

func TestExistingWranglerProfileIsReusedWithoutOAuthOrRevocation(t *testing.T) {
	callLog := filepath.Join(t.TempDir(), "calls")
	wrangler := writeWranglerFixture(t, `
printf '%s\n' "$*" >> "`+callLog+`"
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ password-gateway-release │ /tmp/project │'
	exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3 $4" = "--profile password-gateway-release" ]; then
	printf '%s\n' '{"type":"oauth","token":"release-token"}'
	exit 0
fi
exit 2
`)
	var output strings.Builder
	selection, err := selectOrCreateWranglerProfile(
		wrangler, "", dedicatedAccountTransport(t, "release-token"),
		&operatorConsole{stdin: strings.NewReader(""), stdout: &output, stderr: io.Discard},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Profile != "password-gateway-release" || selection.CreatedByMay ||
		selection.Account.ID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("existing profile was not reused: %#v", selection)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "auth create") || strings.Contains(string(calls), "auth delete") {
		t.Fatalf("existing profile caused redundant authentication mutation: %s", calls)
	}
}

func TestMissingAuthenticatedWranglerProfileFallsBackToFreshOAuth(t *testing.T) {
	createdProfilePath := filepath.Join(t.TempDir(), "created-profile")
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ default │ - │'
  exit 0
fi
if [ "$1 $2" = "auth create" ]; then
  printf '%s' "$3" > "`+createdProfilePath+`"
  exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3" = "--profile" ]; then
  created=$(cat "`+createdProfilePath+`" 2>/dev/null) || exit 2
  if [ "$4" = "$created" ]; then
    printf '%s\n' '{"type":"oauth","token":"fresh-token"}'
    exit 0
  fi
fi
exit 2
`)
	selection, err := selectOrCreateWranglerProfile(
		wrangler, "", dedicatedAccountTransport(t, "fresh-token"),
		&operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !selection.CreatedByMay || !strings.HasPrefix(selection.Profile, "onenod-operator-") {
		t.Fatalf("fresh OAuth profile was not selected: %#v", selection)
	}
	created, err := os.ReadFile(createdProfilePath)
	if err != nil || string(created) != selection.Profile {
		t.Fatalf("Wrangler auth create did not receive the selected profile: %q err=%v", created, err)
	}
}

func TestMultipleExistingWranglerAccountsRequireHumanSelection(t *testing.T) {
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ default │ - │'
  printf '%s\n' '│ password-gateway-release │ /tmp/project │'
	exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3" = "--profile" ]; then
  case "$4" in
    default) printf '%s\n' '{"type":"oauth","token":"daily-token"}'; exit 0 ;;
    password-gateway-release) printf '%s\n' '{"type":"oauth","token":"release-token"}'; exit 0 ;;
  esac
fi
exit 2
`)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		name := ""
		id := ""
		switch request.Header.Get("Authorization") {
		case "Bearer daily-token":
			name, id = "Daily", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		case "Bearer release-token":
			name, id = "Dedicated", "0123456789abcdef0123456789abcdef"
		default:
			t.Fatal("unexpected Cloudflare token")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"success":true,"result":[{"id":"` + id + `","name":"` + name + `"}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	var output strings.Builder
	selection, err := selectOrCreateWranglerProfile(
		wrangler, "",
		transport,
		&operatorConsole{stdin: strings.NewReader("2\n"), stdout: &output, stderr: io.Discard},
	)
	if err != nil {
		t.Fatal(err)
	}
	if selection.Profile != "password-gateway-release" || selection.CreatedByMay ||
		selection.Account.Name != "Dedicated" {
		t.Fatalf("human-selected profile was not reused: %#v", selection)
	}
	if !strings.Contains(output.String(), "Sign in to another Cloudflare account") {
		t.Fatal("multiple-account selector omitted the fresh OAuth choice")
	}
}

func TestFinalRevocationDeletesEveryProfileForTheDedicatedAccount(t *testing.T) {
	directory := t.TempDir()
	deletedA := filepath.Join(directory, "deleted-a")
	deletedB := filepath.Join(directory, "deleted-b")
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ default │ - │'
  if [ ! -f "`+deletedA+`" ]; then printf '%s\n' '│ release-a │ /tmp/a │'; fi
  if [ ! -f "`+deletedB+`" ]; then printf '%s\n' '│ release-b │ /tmp/b │'; fi
  exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3" = "--profile" ]; then
  case "$4" in
    release-a) if [ -f "`+deletedA+`" ]; then exit 2; fi; printf '%s\n' '{"type":"oauth","token":"token-a"}'; exit 0 ;;
    release-b) if [ -f "`+deletedB+`" ]; then exit 2; fi; printf '%s\n' '{"type":"oauth","token":"token-b"}'; exit 0 ;;
    default) exit 2 ;;
  esac
fi
if [ "$1 $2" = "auth delete" ]; then
  case "$3" in
    release-a) : > "`+deletedA+`"; exit 0 ;;
    release-b) : > "`+deletedB+`"; exit 0 ;;
  esac
fi
exit 2
`)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer token-a" &&
			request.Header.Get("Authorization") != "Bearer token-b" {
			t.Fatal("unexpected Cloudflare token")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: io.NopCloser(strings.NewReader(
				`{"success":true,"result":[{"id":"0123456789abcdef0123456789abcdef","name":"Dedicated"}]}`,
			)),
			Header: make(http.Header),
		}, nil
	})
	var output strings.Builder
	revoked, err := promptAndRevokeWranglerProfile(
		wrangler,
		"release-b",
		"0123456789abcdef0123456789abcdef",
		transport,
		&operatorConsole{stdin: strings.NewReader("y\n"), stdout: &output, stderr: io.Discard},
		true,
	)
	if err != nil || !revoked {
		t.Fatalf("dedicated-account profiles were not revoked: revoked=%v err=%v", revoked, err)
	}
	for _, path := range []string{deletedA, deletedB} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected revocation marker %s: %v", path, err)
		}
	}
	if !strings.Contains(output.String(), "release-b (used for this operation)") {
		t.Fatal("used Wrangler profile was not identified in the final plan")
	}
}
