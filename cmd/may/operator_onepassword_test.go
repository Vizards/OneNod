package main

import (
	"encoding/json"
	"strings"
	"testing"
)

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
