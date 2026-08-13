package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

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
