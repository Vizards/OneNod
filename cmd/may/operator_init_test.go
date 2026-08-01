package main

import (
	"bufio"
	"encoding/json"
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
		ExecutorName: defaultExecutorWorkerName, GatewayName: defaultGatewayWorkerName,
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
	if err := validateProductionInitializationMaterial(material); err != nil {
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
	console := operatorConsole{input: newBufferedReader(input), stdin: input, stdout: io.Discard, stderr: io.Discard}
	identity, err := readBinaryProductionTargetIdentity(testCloudflareAccountID, "human-vault", &console)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Origin != "https://onenod.human-vault.workers.dev" || identity.RPID != "onenod.human-vault.workers.dev" {
		t.Fatalf("%+v", identity)
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
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/client/v4/accounts/"+testCloudflareAccountID+"/workers/subdomain" || request.Header.Get("Authorization") != "Bearer oauth-test-token" {
			t.Fatal("unexpected Cloudflare request")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"success":true,"result":{"subdomain":"human-vault"}}`)), Header: make(http.Header)}, nil
	})}
	subdomain, err := fetchCloudflareAccountSubdomain(client, testCloudflareAccountID, []byte("oauth-test-token"))
	if err != nil || subdomain != "human-vault" {
		t.Fatalf("%q %v", subdomain, err)
	}
}

func TestSecureCloudflareClientRejectsRedirectBeforeCredentialCanMoveHosts(t *testing.T) {
	calls := 0
	client := secureCloudflareAPIClient(roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.Hostname() != "api.cloudflare.com" {
			t.Fatal("credential reached another host")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://attacker.example/steal"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	}))
	request, _ := http.NewRequest(http.MethodGet, "https://api.cloudflare.com/client/v4/test", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := client.Do(request)
	if err == nil {
		t.Fatal("redirect was accepted")
	}
	if response != nil {
		response.Body.Close()
	}
	if calls != 1 {
		t.Fatalf("transport called %d times", calls)
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
	input := strings.NewReader("n\n")
	console := operatorConsole{
		input: bufio.NewReader(input), stdin: input, stdout: io.Discard, stderr: io.Discard,
	}
	revoked, err := promptAndRevokeWranglerProfile(
		"/does/not/exist",
		"onenod-operator-test",
		strings.Repeat("a", 32),
		&console,
	)
	if err != nil || revoked {
		t.Fatalf("explicit retention should succeed without deletion: revoked=%v err=%v", revoked, err)
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

func newBufferedReader(reader io.Reader) *bufio.Reader { return bufio.NewReader(reader) }
