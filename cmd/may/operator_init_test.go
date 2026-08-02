package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCloudflareAccountID = "0123456789abcdef0123456789abcdef"
const testOnePasswordAccount = "my.1password.com"

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

func TestProductionInitializationGeneratesClosedDistinctMaterial(t *testing.T) {
	material, err := newProductionInitializationMaterial(testOnePasswordProvisioning(), testProductionIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if material.ExecutorAuthToken == material.GatewayMasterKey || material.ExecutorAuthToken == material.BootstrapToken || material.GatewayMasterKey == material.BootstrapToken {
		t.Fatal("independent initialization secrets collided")
	}
}

func TestRecoveryTemplateExcludesBootstrapAndServiceAccountTokens(t *testing.T) {
	material, err := newProductionInitializationMaterial(testOnePasswordProvisioning(), testProductionIdentity())
	if err != nil {
		t.Fatal(err)
	}
	template, err := productionRecoveryItemTemplate(material)
	if err != nil || !json.Valid(template) {
		t.Fatalf("invalid template: %v", err)
	}
	text := string(template)
	for _, required := range []string{material.ExecutorAuthToken, material.GatewayMasterKey, material.VAPID.PrivateKey, material.Origin, material.AgentVaultID} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing recovery value")
		}
	}
	for _, forbidden := range []string{material.BootstrapToken, material.OnePasswordServiceAccountToken} {
		if strings.Contains(text, forbidden) {
			t.Fatal("ephemeral/upstream token leaked into deployment recovery item")
		}
	}
}

func TestServiceAccountCreationIsAgentOnlyRawAndExplicitAccount(t *testing.T) {
	arguments := agentServiceAccountCreateArguments("example.1password.com", defaultServiceAccountName, "abcdefghijklmnopqrstuvwxya")
	joined := strings.Join(arguments, " ")
	for _, required := range []string{"service-account create", "abcdefghijklmnopqrstuvwxya:read_items,write_items", "--raw", "--account example.1password.com"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("missing %q in %s", required, joined)
		}
	}
	for _, forbidden := range []string{"share_items", "--can-create-vaults"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("granted %q", forbidden)
		}
	}
}

func TestBinaryTargetDerivesWorkersDevOriginWithoutSubdomainPrompt(t *testing.T) {
	input := strings.NewReader("\n\n")
	var prompts strings.Builder
	console := operatorConsole{stdin: input, stdout: io.Discard, stderr: &prompts}
	identity, err := readBinaryProductionTargetIdentity(testCloudflareAccountID, "human-vault", &console)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPrefix := defaultGatewayWorkerBaseName + "-"
	executorPrefix := defaultExecutorWorkerBaseName + "-"
	if !strings.HasPrefix(identity.GatewayName, gatewayPrefix) ||
		!strings.HasPrefix(identity.ExecutorName, executorPrefix) {
		t.Fatalf("random defaults were not applied: %+v", identity)
	}
	gatewayID := strings.TrimPrefix(identity.GatewayName, gatewayPrefix)
	executorID := strings.TrimPrefix(identity.ExecutorName, executorPrefix)
	if gatewayID != executorID || len(gatewayID) != 8 ||
		strings.Trim(gatewayID, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		t.Fatalf("defaults do not share a valid deployment ID: %+v", identity)
	}
	expectedOrigin := "https://" + identity.GatewayName + ".human-vault.workers.dev"
	if identity.Origin != expectedOrigin || identity.RPID != strings.TrimPrefix(expectedOrigin, "https://") {
		t.Fatalf("%+v", identity)
	}
	if !strings.Contains(prompts.String(), "["+identity.GatewayName+"]") ||
		!strings.Contains(prompts.String(), "["+identity.ExecutorName+"]") {
		t.Fatalf("random defaults were not displayed: %s", prompts.String())
	}
}

func TestBinaryTargetUsesExplicitWorkerNamesWithoutSuffix(t *testing.T) {
	input := strings.NewReader("my-gateway\nprivate-executor\n")
	console := operatorConsole{stdin: input, stdout: io.Discard, stderr: io.Discard}
	identity, err := readBinaryProductionTargetIdentity(testCloudflareAccountID, "human-vault", &console)
	if err != nil {
		t.Fatal(err)
	}
	if identity.GatewayName != "my-gateway" || identity.ExecutorName != "private-executor" ||
		identity.Origin != "https://my-gateway.human-vault.workers.dev" {
		t.Fatalf("explicit Worker names were rewritten: %+v", identity)
	}
}

func TestBinaryTargetAllowsOneExplicitNameAndOneRandomDefault(t *testing.T) {
	input := strings.NewReader("my-gateway\n\n")
	console := operatorConsole{stdin: input, stdout: io.Discard, stderr: io.Discard}
	identity, err := readBinaryProductionTargetIdentity(testCloudflareAccountID, "human-vault", &console)
	if err != nil {
		t.Fatal(err)
	}
	if identity.GatewayName != "my-gateway" ||
		!strings.HasPrefix(identity.ExecutorName, defaultExecutorWorkerBaseName+"-") ||
		identity.Origin != "https://my-gateway.human-vault.workers.dev" {
		t.Fatalf("mixed explicit/default Worker names were not preserved: %+v", identity)
	}
}

func TestDeploymentIDUsesExactLowercaseBase32Encoding(t *testing.T) {
	id, err := deploymentIDFromReader(bytes.NewReader([]byte{0, 1, 2, 3, 4}))
	if err != nil {
		t.Fatal(err)
	}
	if id != "aaaqeaye" {
		t.Fatalf("unexpected deployment ID %q", id)
	}
	if _, err := deploymentIDFromReader(strings.NewReader("short"[:4])); err == nil {
		t.Fatal("short random input was accepted")
	}
}

func TestProductionTargetIdentityRejectsUnsafeInputs(t *testing.T) {
	base := testProductionIdentity()
	wrong := base
	wrong.Origin = "https://attacker.example"
	wrong.RPID = "attacker.example"
	invalid := base
	invalid.AccountID = "invalid"
	collision := base
	collision.ExecutorName = collision.GatewayName
	for _, fixture := range []productionTargetIdentity{wrong, invalid, collision} {
		if _, err := validateProductionTargetIdentity(fixture); err == nil {
			t.Fatalf("accepted %+v", fixture)
		}
	}
}

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

func TestOperatorPromptsDoNotPrefetchAcrossPromptKinds(t *testing.T) {
	input := strings.NewReader("Agent\ny\nOneNod Recovery\n")
	console := operatorConsole{stdin: input, stdout: io.Discard, stderr: io.Discard}
	first, err := console.readRequiredValue("Agent vault")
	if err != nil || first != "Agent" {
		t.Fatalf("first prompt returned %q: %v", first, err)
	}
	confirmed, err := promptYesNo(console.stdin, console.stdout, "Continue?", false)
	if err != nil || !confirmed {
		t.Fatalf("security prompt returned %v: %v", confirmed, err)
	}
	second, err := console.readRequiredValue("Recovery vault")
	if err != nil || second != "OneNod Recovery" {
		t.Fatalf("prompt after security confirmation returned %q: %v", second, err)
	}
}

func TestSecurityPromptRejectsNonTerminalFileWithoutConsumingIt(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		reader.Close()
		writer.Close()
	})
	if _, err := writer.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := promptYesNo(reader, io.Discard, "Continue?", false); err == nil ||
		!strings.Contains(err.Error(), "interactive terminal") {
		t.Fatalf("non-terminal confirmation returned %v", err)
	}
	remaining := make([]byte, 2)
	if _, err := io.ReadFull(reader, remaining); err != nil || string(remaining) != "y\n" {
		t.Fatalf("non-terminal input was consumed: %q %v", remaining, err)
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

func TestSupportedOnePasswordAccountsAreValidatedDeduplicatedAndSorted(t *testing.T) {
	accounts, err := supportedOnePasswordAccounts([]byte(`[
		{"url":"https://team.1password.eu/"},
		{"url":"HTTPS://TEAM-ENGINEERING.1PASSWORD.CA/"},
		{"url":"my.1password.com"},
		{"url":"https://my.1password.com"}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(accounts, ",") != "my.1password.com,team-engineering.1password.ca,team.1password.eu" {
		t.Fatalf("unexpected accounts: %v", accounts)
	}
	for _, invalid := range [][]byte{
		[]byte(`[]`),
		[]byte(`[{"url":"https://attacker.example"}]`),
		[]byte(`[{"url":"https://nested.team.1password.com"}]`),
		[]byte(`[{"url":"https://-team.1password.com"}]`),
		[]byte(`[{"url":"https://team-.1password.com"}]`),
		[]byte(`[{"url":"https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1password.com"}]`),
		[]byte(`not-json`),
	} {
		if _, err := supportedOnePasswordAccounts(invalid); err == nil {
			t.Fatalf("accepted invalid account list %s", invalid)
		}
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
	)
	if err != nil || revoked {
		t.Fatalf("explicit retention should succeed without deletion: revoked=%v err=%v", revoked, err)
	}
	if _, statErr := os.Stat(deleteLog); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("retained Wrangler profile was deleted")
	}
}

func TestInitializerReexecEnvironmentDoesNotInheritProductionCredentialsOrProfiles(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "secret")
	t.Setenv("CLOUDFLARE_API_TOKEN", "secret")
	t.Setenv("WRANGLER_PROFILE", "daily")
	t.Setenv("UNRELATED_SECRET_TOKEN", "secret")
	t.Setenv("PATH", "/usr/bin:/bin")
	environment := initializerReexecEnvironment("0.0.2@" + strings.Repeat("a", 40))
	joined := strings.Join(environment, "\n")
	for _, forbidden := range []string{
		"OP_SERVICE_ACCOUNT_TOKEN=", "CLOUDFLARE_API_TOKEN=", "WRANGLER_PROFILE=", "UNRELATED_SECRET_TOKEN=",
	} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("re-exec inherited %s", forbidden)
		}
	}
	for _, required := range []string{
		"PATH=/usr/bin:/bin", initializerReexecIdentity + "=0.0.2@" + strings.Repeat("a", 40),
		"WRANGLER_WRITE_LOGS=false",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("re-exec environment omitted %s", required)
		}
	}
}

func TestOperatorEnvironmentCannotInheritCloudflareOrOnePasswordAuthority(t *testing.T) {
	for name, value := range map[string]string{
		"CLOUDFLARE_API_TOKEN":        "cloudflare-secret",
		"CF_API_KEY":                  "cloudflare-key",
		"DYLD_INSERT_LIBRARIES":       "/tmp/untrusted.dylib",
		"GIT_CONFIG_GLOBAL":           "/tmp/untrusted-gitconfig",
		"GIT_CONFIG_KEY_0":            "credential.helper",
		"GIT_CONFIG_VALUE_0":          "untrusted",
		"NODE_EXTRA_CA_CERTS":         "/tmp/untrusted-ca.pem",
		"NODE_OPTIONS":                "--require=/tmp/untrusted.cjs",
		"OP_ACCOUNT":                  "unselected.1password.com",
		"OP_SERVICE_ACCOUNT_TOKEN":    "service-secret",
		"OP_SESSION_my_1password_com": "session-secret",
		"SSLKEYLOGFILE":               "/tmp/untrusted-tls-keys",
		"WRANGLER_PROFILE":            "everyday",
	} {
		t.Setenv(name, value)
	}
	environment := strings.Join(operatorEnvironment(map[string]string{
		"OP_BIOMETRIC_UNLOCK_ENABLED": "true",
	}), "\n")
	for _, forbidden := range []string{
		"CLOUDFLARE_API_TOKEN=", "CF_API_KEY=", "OP_ACCOUNT=",
		"OP_SERVICE_ACCOUNT_TOKEN=", "OP_SESSION_", "WRANGLER_PROFILE=",
		"DYLD_INSERT_LIBRARIES=", "GIT_CONFIG_GLOBAL=", "GIT_CONFIG_KEY_0=",
		"GIT_CONFIG_VALUE_0=", "NODE_EXTRA_CA_CERTS=", "NODE_OPTIONS=",
		"SSLKEYLOGFILE=",
	} {
		if strings.Contains(environment, forbidden) {
			t.Fatalf("operator child inherited %s", forbidden)
		}
	}
	if !strings.Contains(environment, "OP_BIOMETRIC_UNLOCK_ENABLED=true") ||
		!strings.Contains(environment, "WRANGLER_LOG_SANITIZE=true") ||
		!strings.Contains(environment, "WRANGLER_WRITE_LOGS=false") {
		t.Fatal("operator child omitted required explicit safety overrides")
	}
}
