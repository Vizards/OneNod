package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testTargetWorkerVersion = "11111111-1111-4111-8111-111111111111"
	testPriorWorkerVersion  = "22222222-2222-4222-8222-222222222222"
)

func TestDeployWorkerVersionAcceptsVerifiedSuccessAfterWranglerError(t *testing.T) {
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "versions deploy" ]; then
  exit 1
fi
if [ "$1 $2" = "deployments status" ]; then
  printf '%s\n' '{"versions":[{"version_id":"`+testTargetWorkerVersion+`","percentage":100}]}'
  exit 0
fi
exit 2
`)
	var stderr strings.Builder
	console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr}
	if err := deployWorkerVersion(wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
		testTargetWorkerVersion, "test", console); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "Continuing without retry") {
		t.Fatal("verified post-error success was not explained")
	}
}

func TestDeployWorkerVersionDistinguishesUnchangedAndUnknownState(t *testing.T) {
	for _, fixture := range []struct {
		name       string
		statusJSON string
		unknown    bool
	}{
		{
			name:       "known prior version",
			statusJSON: `{"versions":[{"version_id":"` + testPriorWorkerVersion + `","percentage":100}]}`,
		},
		{
			name: "mixed traffic",
			statusJSON: `{"versions":[{"version_id":"` + testPriorWorkerVersion + `","percentage":50},` +
				`{"version_id":"` + testTargetWorkerVersion + `","percentage":50}]}`,
			unknown: true,
		},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "versions deploy" ]; then
  exit 1
fi
if [ "$1 $2" = "deployments status" ]; then
  printf '%s\n' '`+fixture.statusJSON+`'
  exit 0
fi
exit 2
`)
			console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
			err := deployWorkerVersion(wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
				testTargetWorkerVersion, "test", console)
			if err == nil {
				t.Fatal("failed deployment was accepted")
			}
			var unknown *remoteOutcomeUnknownError
			var observed *observedDeploymentError
			if fixture.unknown {
				if !errors.As(err, &unknown) {
					t.Fatalf("mixed state was not outcome_unknown: %v", err)
				}
			} else if !errors.As(err, &observed) || observed.ObservedVersion != testPriorWorkerVersion {
				t.Fatalf("known unchanged state was not preserved: %v", err)
			}
		})
	}
}

func TestUploadAndTriggerFailuresRemainUnknownWithoutRetry(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "calls")
	wrangler := writeWranglerFixture(t, `
printf '%s\n' "$1 $2" >> "`+logPath+`"
if [ "$1 $2" = "versions upload" ]; then
  printf '%s\n' 'Worker Version ID: `+testTargetWorkerVersion+`'
fi
exit 1
`)
	console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
	_, uploadErr := uploadWorkerVersion(wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway", "test", console)
	triggerErr := deployWorkerTriggers(wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway", console)
	for _, err := range []error{uploadErr, triggerErr} {
		var unknown *remoteOutcomeUnknownError
		if !errors.As(err, &unknown) {
			t.Fatalf("failure was not outcome_unknown: %v", err)
		}
	}
	var uploadUnknown *remoteOutcomeUnknownError
	if !errors.As(uploadErr, &uploadUnknown) || uploadUnknown.ObservedVersion != testTargetWorkerVersion {
		t.Fatalf("possible orphan version was not inventoried: %v", uploadErr)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(calls), "versions upload") != 1 || strings.Count(string(calls), "triggers deploy") != 1 {
		t.Fatalf("Wrangler mutation was retried: %s", calls)
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

func TestOtherWranglerProfileForDedicatedAccountFailsClosed(t *testing.T) {
	wrangler := writeWranglerFixture(t, `
if [ "$1 $2" = "auth list" ]; then
  printf '%s\n' '│ Profile │ Bound Directories │'
  printf '%s\n' '│ default │ - │'
	printf '%s\n' '│ onenod-operator-test │ /tmp/project │'
	exit 0
fi
if [ "$1 $2" = "auth token" ] && [ "$3 $4" = "--profile default" ]; then
	printf '%s\n' '{"type":"oauth","token":"default-token"}'
	exit 0
fi
exit 2
`)
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bearer default-token" ||
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
	err := assertNoOtherWranglerProfileAccess(
		wrangler, "onenod-operator-test", "0123456789abcdef0123456789abcdef", true,
		transport,
	)
	if err == nil || !strings.Contains(err.Error(), "default") {
		t.Fatalf("same-account profile did not block the ceremony: %v", err)
	}
}

func TestFirstDeploymentAppliesTriggersOnlyAfterFinalSecretBearingVersions(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "calls")
	counterPath := filepath.Join(directory, "counter")
	wrangler := writeWranglerFixture(t, `
worker=''
previous=''
for argument in "$@"; do
  if [ "$previous" = "--name" ]; then worker="$argument"; fi
  previous="$argument"
done
if [ "$1 $2" = "versions upload" ]; then
  count=0
  if [ -f "`+counterPath+`" ]; then count=$(cat "`+counterPath+`"); fi
  count=$((count + 1))
  printf '%s' "$count" > "`+counterPath+`"
  case "$count" in
    1) version='11111111-1111-4111-8111-111111111111' ;;
    2) version='22222222-2222-4222-8222-222222222222' ;;
    3) version='33333333-3333-4333-8333-333333333333' ;;
    4) version='44444444-4444-4444-8444-444444444444' ;;
    *) exit 9 ;;
  esac
  printf 'upload %s %s\n' "$worker" "$version" >> "`+logPath+`"
  printf 'Worker Version ID: %s\n' "$version"
  exit 0
fi
if [ "$1 $2" = "versions deploy" ]; then
  version=${3%@100}
  printf '%s' "$version" > "`+directory+`/state-$worker"
  printf 'deploy %s %s\n' "$worker" "$version" >> "`+logPath+`"
  exit 0
fi
if [ "$1 $2" = "deployments status" ]; then
  version=$(cat "`+directory+`/state-$worker")
  printf '{"versions":[{"version_id":"%s","percentage":100}]}\n' "$version"
  exit 0
fi
if [ "$1 $2" = "versions view" ]; then
  printf '{"id":"%s","resources":{"bindings":[' "$3"
  printf '%s' '{"name":"EXECUTOR_AUTH_TOKEN","type":"secret_text"},'
  printf '%s' '{"name":"OP_SERVICE_ACCOUNT_TOKEN","type":"secret_text"},'
  printf '%s' '{"name":"GATEWAY_MASTER_KEY","type":"secret_text"},'
  printf '%s' '{"name":"VAPID_PRIVATE_KEY","type":"secret_text"},'
  printf '%s' '{"name":"BOOTSTRAP_TOKEN","type":"secret_text"}'
  printf '%s\n' ']}}'
  exit 0
fi
if [ "$1 $2" = "secret put" ]; then
  printf 'secret %s %s\n' "$worker" "$3" >> "`+logPath+`"
  exit 0
fi
if [ "$1 $2" = "triggers deploy" ]; then
  version=$(cat "`+directory+`/state-$worker")
  printf 'trigger %s %s\n' "$worker" "$version" >> "`+logPath+`"
  exit 0
fi
exit 8
`)
	bundle := &stagedDeploymentBundle{Root: directory}
	bundle.Descriptor.Executor.Config = "executor.jsonc"
	bundle.Descriptor.Gateway.Config = "gateway.jsonc"
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.1", nil)}
	material := &productionInitializationMaterial{
		ExecutorName: "onenod-executor", GatewayName: "onenod",
		ExecutorAuthToken: "executor-secret", OnePasswordServiceAccountToken: "service-account-secret",
		GatewayMasterKey: "gateway-secret", BootstrapToken: "bootstrap-secret",
		VAPID: vapidCredential{PrivateKey: "vapid-secret"},
	}
	console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard}
	executorVersion, gatewayVersion, err := deployFirstReleaseBundle(
		context.Background(), wrangler, "temporary", bundle, release, material, console,
	)
	if err != nil {
		t.Fatal(err)
	}
	if executorVersion != "22222222-2222-4222-8222-222222222222" ||
		gatewayVersion != "44444444-4444-4444-8444-444444444444" {
		t.Fatalf("unexpected final versions %s %s", executorVersion, gatewayVersion)
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(calls)), "\n")
	for _, expected := range []string{
		"secret onenod-executor EXECUTOR_AUTH_TOKEN",
		"secret onenod-executor OP_SERVICE_ACCOUNT_TOKEN",
		"deploy onenod-executor 22222222-2222-4222-8222-222222222222",
		"trigger onenod-executor 22222222-2222-4222-8222-222222222222",
		"secret onenod BOOTSTRAP_TOKEN",
		"deploy onenod 44444444-4444-4444-8444-444444444444",
		"trigger onenod 44444444-4444-4444-8444-444444444444",
	} {
		if indexOfString(lines, expected) < 0 {
			t.Fatalf("missing %q in operation log:\n%s", expected, calls)
		}
	}
	if indexOfString(lines, "trigger onenod-executor 22222222-2222-4222-8222-222222222222") <
		indexOfString(lines, "deploy onenod-executor 22222222-2222-4222-8222-222222222222") ||
		indexOfString(lines, "trigger onenod 44444444-4444-4444-8444-444444444444") <
			indexOfString(lines, "deploy onenod 44444444-4444-4444-8444-444444444444") {
		t.Fatalf("trigger was applied before its final version:\n%s", calls)
	}
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
