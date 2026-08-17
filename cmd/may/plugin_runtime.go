package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/1Password/shell-plugins/sdk"
)

type shellPluginProcessExitError struct {
	code int
}

func (failure shellPluginProcessExitError) Error() string {
	return fmt.Sprintf("shell plugin target exited with status %d", failure.code)
}

func runShellPluginEntrypoint(command string, arguments []string, deps dependencies) error {
	definition, found, err := shellPluginDefinitionByName(command)
	if err != nil {
		return err
	}
	if !found || definition.Command != command {
		return fmt.Errorf("unsupported OneNod shell plugin entry %q", command)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve user home for shell plugin failed")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return errors.New("resolve current directory for shell plugin failed")
	}
	config, err := readShellPluginConfig(home)
	if err != nil {
		return err
	}
	binding, configured, err := selectShellPluginBinding(config, command, cwd)
	if err != nil {
		return err
	}
	if !configured {
		return fmt.Errorf("no OneNod %s binding applies here; run may plugin status %s", command, command)
	}
	target, err := validateShellPluginTarget(command, binding.Target, home)
	if err != nil {
		return err
	}
	if !definition.needsAuthentication(arguments) {
		return runShellPluginTarget(target, arguments, os.Environ(), deps)
	}
	cli := cliConfig{
		origin:       os.Getenv(userAgentOriginKey),
		pollInterval: 2 * time.Second,
		timeout:      10 * time.Minute,
	}
	cli, deps, err = prepareRequesterInvocation(cli, deps)
	if err != nil {
		return err
	}
	if binding.ItemVersion <= 0 {
		binding, err = refreshShellPluginBindingMetadata(
			cli, deps, config, binding, home,
		)
		if err != nil {
			return err
		}
		config, err = readShellPluginConfig(home)
		if err != nil {
			return err
		}
	}
	fieldIDs, err := shellPluginCredentialFieldIDs(definition, binding)
	if err != nil {
		return err
	}
	values, err := useApprovedCredential(
		cli, deps, binding.ItemID, fieldIDs, binding.ItemVersion,
	)
	if isGatewayErrorCode(err, "item_stale") {
		binding, err = refreshShellPluginBindingMetadata(
			cli, deps, config, binding, home,
		)
		if err == nil {
			fieldIDs, err = shellPluginCredentialFieldIDs(definition, binding)
		}
		if err == nil {
			values, err = useApprovedCredential(
				cli, deps, binding.ItemID, fieldIDs, binding.ItemVersion,
			)
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		for fieldID := range values {
			values[fieldID] = ""
			delete(values, fieldID)
		}
	}()
	fields := make(map[sdk.FieldName]string)
	defer func() {
		for name := range fields {
			fields[name] = ""
			delete(fields, name)
		}
	}()
	for _, field := range definition.Credential.Fields {
		fieldBinding, exists := binding.CredentialFields[field.Name.String()]
		if !exists {
			if field.Optional {
				continue
			}
			return fmt.Errorf("OneNod %s binding omits required field %s", command, field.Name)
		}
		value, exists := values[fieldBinding.FieldID]
		if !exists {
			return fmt.Errorf("OneNod %s credential response omitted field %s", command, field.Name)
		}
		fields[field.Name] = value
	}
	homeDirectory, err := os.UserHomeDir()
	if err != nil {
		return errors.New("resolve home directory for shell plugin provisioner failed")
	}
	temporaryDirectory, err := os.MkdirTemp("", "onenod-shell-plugin-")
	if err != nil {
		return errors.New("create private shell plugin temporary directory failed")
	}
	defer os.RemoveAll(temporaryDirectory)
	output := newShellPluginProvisionOutput()
	definition.provisioner().Provision(context.Background(), sdk.ProvisionInput{
		HomeDir:    homeDirectory,
		TempDir:    temporaryDirectory,
		ItemFields: fields,
	}, &output)
	if err := validateEnvironmentOnlyProvisionOutput(output, definition.EnvironmentNameSet); err != nil {
		return fmt.Errorf("official %s provisioner was rejected: %w", definition.Plugin.Name, err)
	}
	environment := shellPluginEnvironment(os.Environ(), definition.EnvironmentNames, output.Environment)
	runErr := runShellPluginTarget(target, arguments, environment, deps)
	deprovisioned := sdk.DeprovisionOutput{}
	definition.provisioner().Deprovision(context.Background(), sdk.DeprovisionInput{
		HomeDir: homeDirectory,
		TempDir: temporaryDirectory,
	}, &deprovisioned)
	for name := range output.Environment {
		output.Environment[name] = ""
		delete(output.Environment, name)
	}
	if len(deprovisioned.Diagnostics.Errors) != 0 && runErr == nil {
		return errors.New("official shell plugin deprovisioner reported an error")
	}
	return runErr
}

func shellPluginCredentialFieldIDs(
	definition shellPluginDefinition,
	binding shellPluginBinding,
) ([]string, error) {
	fieldIDs := make([]string, 0, len(binding.CredentialFields))
	seen := make(map[string]bool, len(binding.CredentialFields))
	for _, field := range definition.Credential.Fields {
		fieldBinding, exists := binding.CredentialFields[field.Name.String()]
		if !exists {
			if field.Optional {
				continue
			}
			return nil, fmt.Errorf("OneNod %s binding omits required field %s", binding.Command, field.Name)
		}
		if seen[fieldBinding.FieldID] {
			return nil, errors.New("OneNod shell plugin binding contains duplicate field IDs")
		}
		seen[fieldBinding.FieldID] = true
		fieldIDs = append(fieldIDs, fieldBinding.FieldID)
	}
	sort.Strings(fieldIDs)
	return fieldIDs, nil
}

func refreshShellPluginBindingMetadata(
	config cliConfig,
	deps dependencies,
	pluginConfig shellPluginConfig,
	binding shellPluginBinding,
	home string,
) (shellPluginBinding, error) {
	credentialFields := make(
		map[string]shellPluginFieldBinding,
		len(binding.CredentialFields),
	)
	for name, field := range binding.CredentialFields {
		credentialFields[name] = field
	}
	binding.CredentialFields = credentialFields
	credential, err := deps.keychain.Load()
	if err != nil {
		return shellPluginBinding{}, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return shellPluginBinding{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	item, err := readCatalogItemWithLocalFallback(
		ctx,
		client,
		binding.ItemID,
		deps,
	)
	cancel()
	if err != nil {
		return shellPluginBinding{}, err
	}
	metadata := make(map[string]catalogFieldResult, len(item.Fields))
	for _, field := range item.Fields {
		if _, duplicate := metadata[field.FieldID]; duplicate {
			return shellPluginBinding{}, errors.New("targeted item metadata contains duplicate field IDs")
		}
		metadata[field.FieldID] = field
	}
	for name, fieldBinding := range binding.CredentialFields {
		field, exists := metadata[fieldBinding.FieldID]
		if !exists {
			return shellPluginBinding{}, fmt.Errorf("OneNod %s binding field %s is no longer present in the credential item", binding.Command, name)
		}
		fieldBinding.Label = field.Label
		binding.CredentialFields[name] = fieldBinding
	}
	binding.ItemTitle = item.Title
	binding.ItemVersion = item.Version
	if err := requireUnchangedShellPluginConfig(home, pluginConfig); err != nil {
		return shellPluginBinding{}, err
	}
	index := exactShellPluginBindingIndex(
		pluginConfig,
		binding.Command,
		binding.Scope,
	)
	if index < 0 || pluginConfig.Bindings[index].ItemID != binding.ItemID {
		return shellPluginBinding{}, errors.New("OneNod shell plugin binding changed during metadata refresh")
	}
	pluginConfig.Bindings[index] = binding
	if err := writeShellPluginConfig(home, pluginConfig); err != nil {
		return shellPluginBinding{}, err
	}
	fmt.Fprintf(
		writerOrDefault(deps.stderr, os.Stderr),
		"Refreshed OneNod %s credential metadata at item version %d.\n",
		binding.Command,
		binding.ItemVersion,
	)
	return binding, nil
}

func shellPluginEnvironment(base []string, removed []string, overrides map[string]string) []string {
	blocked := make(map[string]bool, len(removed)+len(overrides))
	for _, name := range removed {
		blocked[name] = true
	}
	for name := range overrides {
		blocked[name] = true
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if found && !blocked[name] {
			result = append(result, entry)
		}
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, name+"="+overrides[name])
	}
	return result
}

func runShellPluginTarget(target string, arguments []string, environment []string, deps dependencies) error {
	command := exec.Command(target, arguments...)
	command.Env = environment
	command.Stdin = readerOrDefault(deps.stdin, os.Stdin)
	command.Stdout = writerOrDefault(deps.stdout, os.Stdout)
	command.Stderr = writerOrDefault(deps.stderr, os.Stderr)
	err := command.Run()
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if exitError.ExitCode() >= 0 {
			return shellPluginProcessExitError{code: exitError.ExitCode()}
		}
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return shellPluginProcessExitError{code: 128 + int(status.Signal())}
		}
	}
	return errors.New("run shell plugin target failed")
}

func readerOrDefault(value io.Reader, fallback io.Reader) io.Reader {
	if value != nil {
		return value
	}
	return fallback
}

func writerOrDefault(value io.Writer, fallback io.Writer) io.Writer {
	if value != nil {
		return value
	}
	return fallback
}
