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
	item, err := resolveShellPluginCatalogItem(cli, deps, binding.ItemID)
	if err != nil {
		return err
	}
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
		if !catalogItemHasField(item, fieldBinding.FieldID) {
			return fmt.Errorf("OneNod %s binding field %s is no longer present in the catalog item", command, field.Name)
		}
		value, err := readApprovedSecret(cli, deps, item.ItemID, fieldBinding.FieldID, item.Version)
		if err != nil {
			return err
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

func resolveShellPluginCatalogItem(
	config cliConfig,
	deps dependencies,
	itemID string,
) (catalogItemResult, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return catalogItemResult{}, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return catalogItemResult{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	defer cancel()
	response, err := searchCatalogWithLocalFallback(ctx, client, itemID, deps)
	if err != nil {
		return catalogItemResult{}, err
	}
	var selected *catalogItemResult
	for index := range response.Items {
		if response.Items[index].ItemID != itemID {
			continue
		}
		if selected != nil {
			return catalogItemResult{}, errors.New("catalog returned duplicate shell plugin items")
		}
		copy := response.Items[index]
		selected = &copy
	}
	if selected == nil || selected.Version <= 0 {
		return catalogItemResult{}, errors.New("shell plugin catalog item was not found at a positive version")
	}
	return *selected, nil
}

func catalogItemHasField(item catalogItemResult, fieldID string) bool {
	for _, field := range item.Fields {
		if field.FieldID == fieldID {
			return true
		}
	}
	return false
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
