package main

import (
	"context"
	"errors"
	"fmt"
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
	var stderr strings.Builder
	console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr}
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
	if !strings.Contains(stderr.String(), "Wrangler diagnostic (the operation will not be retried)") {
		t.Fatal("failed upload omitted the bounded Wrangler diagnostic")
	}
}

func TestRecoverOperatorUpdateReusesExactGatewayUploadTransaction(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	receipt := &operatorDeploymentReceipt{
		AccountID:      "0123456789abcdef0123456789abcdef",
		ReleaseVersion: "0.0.2-alpha.10",
	}
	release := &verifiedRelease{Manifest: releaseManifest{ReleaseVersion: "0.0.2-alpha.11"}}
	artifact := releaseArtifact{Name: "onenod-deployment.tar.gz", SHA256: strings.Repeat("a", 64)}

	transaction, path, err := newOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	transaction.ExecutorAfter = "33333333-3333-4333-8333-333333333333"
	transaction.Outcome = "remote_needs_attention"
	transaction.Phase = "gateway_upload_unknown"
	if err := writeAtomicPrivateJSON(path, transaction); err != nil {
		t.Fatal(err)
	}

	recovered, recoveredPath, resuming, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, testPriorWorkerVersion, testTargetWorkerVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !resuming || recoveredPath != path || recovered.ID != transaction.ID ||
		recovered.ExecutorAfter != transaction.ExecutorAfter {
		t.Fatalf("unexpected recovered transaction: resuming=%t path=%q transaction=%+v", resuming, recoveredPath, recovered)
	}

	if _, _, _, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, artifact, "44444444-4444-4444-8444-444444444444", testTargetWorkerVersion,
	); err == nil || !strings.Contains(err.Error(), "Cloudflare traffic changed") {
		t.Fatalf("changed production baseline was accepted: %v", err)
	}
}

func TestUploadOrReuseWorkerVersionNeverUploadsKnownVersion(t *testing.T) {
	callLog := filepath.Join(t.TempDir(), "calls")
	wrangler := writeWranglerFixture(t, `
printf '%s\n' "$*" >> "`+callLog+`"
if [ "$1 $2" = "versions view" ]; then
  printf '%s\n' '{"id":"`+testTargetWorkerVersion+`","resources":{"bindings":[{"name":"EXECUTOR_AUTH_TOKEN","type":"secret_text"}]}}'
  exit 0
fi
exit 2
`)
	var output strings.Builder
	version, err := uploadOrReuseWorkerVersion(
		wrangler, "temporary", t.TempDir(), "worker.jsonc", "gateway",
		testTargetWorkerVersion, "test", &operatorConsole{stdout: &output, stderr: io.Discard},
		[]string{"EXECUTOR_AUTH_TOKEN"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if version != testTargetWorkerVersion || !strings.Contains(output.String(), "Reusing previously uploaded") {
		t.Fatalf("known version was not reused: version=%q output=%q", version, output.String())
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "versions upload") || strings.Count(string(calls), "versions view") != 1 {
		t.Fatalf("known version caused a mutation or duplicate inspection: %s", calls)
	}
}

func TestDeployPrivateWorkerScaffoldReportsConfirmedAbsence(t *testing.T) {
	directory := t.TempDir()
	config := filepath.Join(directory, "worker.jsonc")
	if err := os.WriteFile(config, []byte(`{"workers_dev":true,"preview_urls":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	wrangler := writeWranglerFixture(t, `
if [ "$1" = "deploy" ]; then
  printf '%s\n' 'You cannot create this Worker in the selected account.' >&2
  exit 1
fi
if [ "$1 $2" = "deployments status" ]; then
  printf '%s\n' 'This Worker does not exist [code: 10007]' >&2
  exit 1
fi
exit 2
`)
	var stderr strings.Builder
	console := &operatorConsole{stdin: strings.NewReader(""), stdout: io.Discard, stderr: &stderr}
	_, err := deployPrivateWorkerScaffold(
		wrangler, "temporary", config, "gateway", "test", console,
	)
	if err == nil || !strings.Contains(err.Error(), "Cloudflare confirms that the Worker is absent") {
		t.Fatalf("confirmed absence was not reported as a known failure: %v", err)
	}
	var unknown *remoteOutcomeUnknownError
	if errors.As(err, &unknown) {
		t.Fatalf("confirmed absence was mislabeled outcome_unknown: %v", err)
	}
	if !strings.Contains(stderr.String(), "You cannot create this Worker") {
		t.Fatal("actionable Wrangler diagnostic was hidden")
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

func TestFirstDeploymentAppliesTriggersOnlyAfterFinalSecretBearingVersions(t *testing.T) {
	directory := t.TempDir()
	logPath := filepath.Join(directory, "calls")
	wrangler := writeWranglerFixture(t, `
worker=''
config=''
previous=''
for argument in "$@"; do
  if [ "$previous" = "--name" ]; then worker="$argument"; fi
  if [ "$previous" = "--config" ]; then config="$argument"; fi
  previous="$argument"
done
if [ "$1" = "deploy" ]; then
  if grep -q '"workers_dev":[[:space:]]*true' "$config" ||
     grep -q '"preview_urls":[[:space:]]*true' "$config" ||
     grep -q '"routes"' "$config" || grep -q '"triggers"' "$config"; then
    exit 7
  fi
  case "$worker" in
    onenod-executor) version='11111111-1111-4111-8111-111111111111' ;;
    onenod) version='33333333-3333-4333-8333-333333333333' ;;
    *) exit 9 ;;
  esac
  printf '%s' "$version" > "`+directory+`/state-$worker"
  printf 'scaffold %s %s\n' "$worker" "$version" >> "`+logPath+`"
  printf 'Worker Version ID: %s\n' "$version"
  exit 0
fi
if [ "$1 $2" = "versions upload" ]; then
  case "$worker" in
    onenod-executor) version='22222222-2222-4222-8222-222222222222' ;;
    onenod) version='44444444-4444-4444-8444-444444444444' ;;
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
	for name, workersDev := range map[string]bool{
		"executor.jsonc": false,
		"gateway.jsonc":  true,
	} {
		encoded := []byte(`{"workers_dev":` + fmt.Sprint(workersDev) + `,"preview_urls":true,"routes":[{"pattern":"unsafe.example"}],"triggers":{"crons":["0 0 * * *"]}}`)
		if err := os.WriteFile(filepath.Join(directory, name), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
		"scaffold onenod-executor 11111111-1111-4111-8111-111111111111",
		"secret onenod-executor EXECUTOR_AUTH_TOKEN",
		"secret onenod-executor OP_SERVICE_ACCOUNT_TOKEN",
		"deploy onenod-executor 22222222-2222-4222-8222-222222222222",
		"trigger onenod-executor 22222222-2222-4222-8222-222222222222",
		"scaffold onenod 33333333-3333-4333-8333-333333333333",
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
