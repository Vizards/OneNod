package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	githubplugin "github.com/1Password/shell-plugins/plugins/github"
	wranglerplugin "github.com/1Password/shell-plugins/plugins/wrangler"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/schema"
)

const shellPluginUpstreamRevision = "fec9cd00b7eea740995e93e457105eea4ff149d7"

type shellPluginDefinition struct {
	Plugin             schema.Plugin
	Credential         schema.CredentialType
	Executable         schema.Executable
	Usage              schema.CredentialUsage
	Command            string
	EnvironmentNames   []string
	EnvironmentNameSet map[string]bool
}

func supportedShellPluginDefinitions() ([]shellPluginDefinition, error) {
	plugins := []schema.Plugin{
		githubplugin.New(),
		wranglerplugin.New(),
	}
	definitions := make([]shellPluginDefinition, 0, len(plugins))
	commands := make(map[string]bool)
	for _, plugin := range plugins {
		if len(plugin.Credentials) != 1 {
			return nil, fmt.Errorf("shell plugin %s does not have exactly one credential type", plugin.Name)
		}
		for _, report := range plugin.DeepValidate() {
			if report.HasErrors() {
				return nil, fmt.Errorf("shell plugin %s failed upstream schema validation", plugin.Name)
			}
		}
		credential := plugin.Credentials[0]
		for _, executable := range plugin.Executables {
			if len(executable.Runs) != 1 || strings.TrimSpace(executable.Runs[0]) == "" ||
				strings.Contains(executable.Runs[0], "/") {
				return nil, fmt.Errorf("shell plugin %s uses an unsupported executable shape", plugin.Name)
			}
			if len(executable.Uses) != 1 {
				return nil, fmt.Errorf("shell plugin %s executable %s does not have exactly one credential usage", plugin.Name, executable.Name)
			}
			usage := executable.Uses[0]
			if usage.SelectFrom != nil || usage.Name != credential.Name ||
				(usage.Plugin != "" && usage.Plugin != plugin.Name) {
				return nil, fmt.Errorf("shell plugin %s executable %s uses an unsupported credential selection", plugin.Name, executable.Name)
			}
			command := executable.Runs[0]
			if commands[command] {
				return nil, fmt.Errorf("duplicate shell plugin executable %s", command)
			}
			definition := shellPluginDefinition{
				Plugin:     plugin,
				Credential: credential,
				Executable: executable,
				Usage:      usage,
				Command:    command,
			}
			environment, err := auditShellPluginCapability(definition)
			if err != nil {
				return nil, err
			}
			definition.EnvironmentNames = environment
			definition.EnvironmentNameSet = make(map[string]bool, len(environment))
			for _, name := range environment {
				definition.EnvironmentNameSet[name] = true
			}
			commands[command] = true
			definitions = append(definitions, definition)
		}
	}
	sort.Slice(definitions, func(left, right int) bool {
		return definitions[left].Command < definitions[right].Command
	})
	return definitions, nil
}

func shellPluginDefinitionByName(name string) (shellPluginDefinition, bool, error) {
	definitions, err := supportedShellPluginDefinitions()
	if err != nil {
		return shellPluginDefinition{}, false, err
	}
	name = strings.ToLower(strings.TrimSpace(name))
	var match *shellPluginDefinition
	for index := range definitions {
		definition := definitions[index]
		if definition.Command != name && definition.Plugin.Name != name {
			continue
		}
		if match != nil && match.Command != definition.Command {
			return shellPluginDefinition{}, false, fmt.Errorf("shell plugin name %q is ambiguous", name)
		}
		copy := definition
		match = &copy
	}
	if match == nil {
		return shellPluginDefinition{}, false, nil
	}
	return *match, true, nil
}

func (definition shellPluginDefinition) provisioner() sdk.Provisioner {
	if definition.Usage.Provisioner != nil {
		return definition.Usage.Provisioner
	}
	return definition.Credential.DefaultProvisioner
}

func (definition shellPluginDefinition) needsAuthentication(arguments []string) bool {
	input := sdk.NeedsAuthenticationInput{
		CredentialType: definition.Credential.Name.String(),
		CommandArgs:    append([]string(nil), arguments...),
	}
	if definition.Executable.NeedsAuth != nil && !definition.Executable.NeedsAuth(input) {
		return false
	}
	return definition.Usage.NeedsAuth == nil || definition.Usage.NeedsAuth(input)
}

func auditShellPluginCapability(definition shellPluginDefinition) ([]string, error) {
	provisioner := definition.provisioner()
	if provisioner == nil {
		return nil, fmt.Errorf("shell plugin %s has no provisioner", definition.Plugin.Name)
	}
	required := make(map[sdk.FieldName]string)
	all := make(map[sdk.FieldName]string)
	for _, field := range definition.Credential.Fields {
		all[field.Name] = "onenod-placeholder"
		if !field.Optional {
			required[field.Name] = "onenod-placeholder"
		}
	}
	environmentNames := make(map[string]bool)
	for _, fields := range []map[sdk.FieldName]string{required, all} {
		output := newShellPluginProvisionOutput()
		provisioner.Provision(context.Background(), sdk.ProvisionInput{
			DryRun:     true,
			ItemFields: fields,
		}, &output)
		if err := validateEnvironmentOnlyProvisionOutput(output, nil); err != nil {
			return nil, fmt.Errorf("shell plugin %s capability audit failed: %w", definition.Plugin.Name, err)
		}
		for name := range output.Environment {
			environmentNames[name] = true
		}
	}
	if len(environmentNames) == 0 {
		return nil, fmt.Errorf("shell plugin %s did not declare an environment-variable capability", definition.Plugin.Name)
	}
	deprovisioned := sdk.DeprovisionOutput{}
	provisioner.Deprovision(context.Background(), sdk.DeprovisionInput{DryRun: true}, &deprovisioned)
	if len(deprovisioned.Diagnostics.Errors) != 0 {
		return nil, fmt.Errorf("shell plugin %s deprovision capability audit failed", definition.Plugin.Name)
	}
	names := make([]string, 0, len(environmentNames))
	for name := range environmentNames {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func newShellPluginProvisionOutput() sdk.ProvisionOutput {
	return sdk.ProvisionOutput{
		Environment: make(map[string]string),
		Files:       make(map[string]sdk.OutputFile),
		Cache: sdk.CacheOperations{
			Puts: make(map[string]sdk.CacheEntry),
		},
	}
}

func validateEnvironmentOnlyProvisionOutput(
	output sdk.ProvisionOutput,
	allowed map[string]bool,
) error {
	if len(output.Diagnostics.Errors) != 0 {
		return errors.New("provisioner reported an error")
	}
	if len(output.CommandLine) != 0 || len(output.Files) != 0 ||
		len(output.Cache.Puts) != 0 || len(output.Cache.Removes) != 0 {
		return errors.New("provisioner requested an unsupported non-environment capability")
	}
	for name, value := range output.Environment {
		if !validEnvironmentName(name) || strings.ContainsRune(value, 0) {
			return errors.New("provisioner produced an invalid environment entry")
		}
		if allowed != nil && !allowed[name] {
			return fmt.Errorf("provisioner produced unaudited environment variable %s", name)
		}
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || character == '_' ||
			(index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}
