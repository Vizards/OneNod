package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/schema/fieldname"
)

func TestSupportedShellPluginsUseOfficialNeedsAuthAndProvisioners(t *testing.T) {
	definitions, err := supportedShellPluginDefinitions()
	if err != nil {
		t.Fatalf("load supported shell plugins: %v", err)
	}
	if len(definitions) != 2 {
		t.Fatalf("supported plugin count = %d, want 2", len(definitions))
	}
	byCommand := make(map[string]shellPluginDefinition)
	for _, definition := range definitions {
		byCommand[definition.Command] = definition
	}
	cases := []struct {
		command    string
		noAuthArgs []string
		authArgs   []string
		fields     map[sdk.FieldName]string
		wantEnv    map[string]string
	}{
		{
			command:    "gh",
			noAuthArgs: []string{"--version"},
			authArgs:   []string{"api", "user"},
			fields:     map[sdk.FieldName]string{fieldname.Token: "github-test-token"},
			wantEnv: map[string]string{
				"GH_TOKEN":     "github-test-token",
				"GITHUB_TOKEN": "github-test-token",
			},
		},
		{
			command:    "wrangler",
			noAuthArgs: []string{"--help"},
			authArgs:   []string{"whoami"},
			fields: map[sdk.FieldName]string{
				fieldname.Token:     "cloudflare-test-token",
				fieldname.AccountID: "cloudflare-test-account",
			},
			wantEnv: map[string]string{
				"CLOUDFLARE_API_TOKEN":  "cloudflare-test-token",
				"CLOUDFLARE_ACCOUNT_ID": "cloudflare-test-account",
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.command, func(t *testing.T) {
			definition, exists := byCommand[testCase.command]
			if !exists {
				t.Fatalf("definition %s is missing", testCase.command)
			}
			if definition.needsAuthentication(testCase.noAuthArgs) {
				t.Fatalf("%s no-auth command unexpectedly requires a credential", testCase.command)
			}
			if !definition.needsAuthentication(testCase.authArgs) {
				t.Fatalf("%s authenticated command unexpectedly bypasses credential provisioning", testCase.command)
			}
			output := newShellPluginProvisionOutput()
			definition.provisioner().Provision(context.Background(), sdk.ProvisionInput{
				ItemFields: testCase.fields,
			}, &output)
			if err := validateEnvironmentOnlyProvisionOutput(output, definition.EnvironmentNameSet); err != nil {
				t.Fatalf("validate official provisioner output: %v", err)
			}
			for name, expected := range testCase.wantEnv {
				if output.Environment[name] != expected {
					t.Fatalf("%s environment %s = %q, want %q", testCase.command, name, output.Environment[name], expected)
				}
			}
		})
	}
}

func TestShellPluginBindingsPreferNearestDirectoryAndStripAmbientCredentials(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	nested := filepath.Join(project, "packages", "worker")
	outside := filepath.Join(home, "outside")
	for _, directory := range []string{nested, outside} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	canonicalProject, err := canonicalExistingDirectory(project)
	if err != nil {
		t.Fatal(err)
	}
	field := map[string]shellPluginFieldBinding{
		"Token": {FieldID: "credential", Label: "credential"},
	}
	config := shellPluginConfig{
		SchemaVersion: shellPluginConfigSchema,
		Bindings: []shellPluginBinding{
			{
				Command: "wrangler", Plugin: "wrangler", Scope: shellPluginScope{Kind: "global"},
				Target: "/bin/sh", ItemID: "global-item", CredentialFields: field,
				UpstreamRevision: shellPluginUpstreamRevision,
			},
			{
				Command: "wrangler", Plugin: "wrangler", Scope: shellPluginScope{Kind: "directory", Root: canonicalProject},
				Target: "/bin/sh", ItemID: "directory-item", CredentialFields: field,
				UpstreamRevision: shellPluginUpstreamRevision,
			},
		},
	}
	if err := writeShellPluginConfig(home, config); err != nil {
		t.Fatalf("write shell plugin config: %v", err)
	}
	loaded, err := readShellPluginConfig(home)
	if err != nil {
		t.Fatalf("read shell plugin config: %v", err)
	}
	selected, found, err := selectShellPluginBinding(loaded, "wrangler", nested)
	if err != nil || !found || selected.ItemID != "directory-item" {
		t.Fatalf("nearest directory binding = %#v, found=%v, err=%v", selected, found, err)
	}
	selected, found, err = selectShellPluginBinding(loaded, "wrangler", outside)
	if err != nil || !found || selected.ItemID != "global-item" {
		t.Fatalf("global fallback binding = %#v, found=%v, err=%v", selected, found, err)
	}

	environment := shellPluginEnvironment(
		[]string{"PATH=/usr/bin", "GH_TOKEN=ambient", "GITHUB_TOKEN=ambient"},
		[]string{"GH_TOKEN", "GITHUB_TOKEN"},
		map[string]string{"GH_TOKEN": "approved"},
	)
	if !slices.Contains(environment, "PATH=/usr/bin") || !slices.Contains(environment, "GH_TOKEN=approved") {
		t.Fatalf("environment omitted preserved or approved values: %v", environment)
	}
	for _, entry := range environment {
		if strings.HasSuffix(entry, "=ambient") || strings.HasPrefix(entry, "GITHUB_TOKEN=") {
			t.Fatalf("ambient credential survived environment isolation: %s", entry)
		}
	}
}
