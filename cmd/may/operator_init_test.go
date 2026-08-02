package main

import (
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
	console := operatorConsole{stdin: input, stdout: io.Discard, stderr: io.Discard}
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
	input := strings.NewReader("n\n")
	console := operatorConsole{
		stdin: input, stdout: io.Discard, stderr: io.Discard,
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
