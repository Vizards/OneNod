package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProductionConfigurationRequiresCompiledConfirmation(t *testing.T) {
	raw, err := json.Marshal(validTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "confirmation.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if _, _, err := loadConfirmedConfig(path, digest); err != nil {
		t.Fatalf("valid dummy metadata failed: %v", err)
	}
	if _, _, err := loadProductionConfig(path, digest); err == nil {
		t.Fatal("self-selected configuration could reach production credential acquisition")
	}
	if _, _, err := loadProductionConfig(path, confirmedConfigSHA256); err == nil {
		t.Fatal("substituted configuration accepted under the production digest")
	}
}

func TestDeploymentMetadataRejectsCredentialOrURLAmbiguity(t *testing.T) {
	for _, mutate := range []func(*confirmedConfig){
		func(c *confirmedConfig) { c.Provider.BaseURL += "?redirect=other" },
		func(c *confirmedConfig) { c.Provider.CallerOrigin = "https://user:secret@example.com" },
		func(c *confirmedConfig) { c.Authentication.OneNodReference = "op://OtherVault/item/field" },
		func(c *confirmedConfig) { c.Observability.EvidenceRoot = "relative/path" },
	} {
		config := validTestConfig()
		mutate(&config)
		if validateConfirmedConfig(config) == nil {
			t.Fatal("invalid deployment metadata accepted")
		}
	}
}

func TestRetrievalDeploymentLeavesProviderIdentityToCompiledDigest(t *testing.T) {
	config := validRetrievalTestConfig()
	config.Provider.Name = "Alternative Provider"
	config.Provider.Route = "Direct alternative route"
	config.Provider.CallerOrigin = "https://alternative.example.invalid"
	config.Provider.BaseURL = "https://alternative.example.invalid/v1"
	config.Provider.UpstreamOrigin = "https://alternative.example.invalid"
	if err := validateConfirmedConfig(config); err != nil {
		t.Fatalf("provider identity should be bound by the compiled config digest: %v", err)
	}
}

func TestRetrievalDeploymentLeavesCredentialIdentityToCompiledDigest(t *testing.T) {
	config := validRetrievalTestConfig()
	config.Authentication.OneNodReference = "op://Agent/another-machine-local-item/api-key"
	if err := validateConfirmedConfig(config); err != nil {
		t.Fatalf("machine-local credential reference should be bound by the compiled config digest: %v", err)
	}
}
