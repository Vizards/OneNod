package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	localFallbackConfigFileName = "local-fallback.json"
	localFallbackConfigSchema   = 1
	localFallbackOperationLimit = 2 * time.Minute
	localFallbackSDKSetting     = "Integrate with 1Password SDKs"
	localFallbackVaultTitle     = "Agent"
	maxLocalFallbackConfigBytes = 4096
)

type localFallbackConfig struct {
	Account       string `json:"account"`
	SchemaVersion int    `json:"schema_version"`
	VaultID       string `json:"vault_id"`
	VaultTitle    string `json:"vault_title"`
}

func runConfigureLocalFallback(args []string, deps dependencies) error {
	if len(args) == 0 {
		return errors.New("usage: may configure local-fallback <status|apply|restore> [--account name-or-uuid]")
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: may configure local-fallback status")
		}
		return writeLocalFallbackStatus(deps.stdout)
	case "apply":
		return applyLocalFallbackConfiguration(args[1:], deps)
	case "restore":
		if len(args) != 1 {
			return errors.New("usage: may configure local-fallback restore")
		}
		return restoreLocalFallbackConfiguration(deps.stdout)
	default:
		return errors.New("usage: may configure local-fallback <status|apply|restore> [--account name-or-uuid]")
	}
}

func applyLocalFallbackConfiguration(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("configure local-fallback apply", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	account := flags.String(
		"account",
		"",
		"1Password account name shown in the desktop app, or account UUID",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may configure local-fallback apply [--account name-or-uuid]")
	}
	if runtime.GOOS != "darwin" {
		return errors.New("local 1Password fallback is currently supported only on macOS")
	}
	selectedAccount := strings.TrimSpace(*account)
	if selectedAccount == "" {
		console := operatorConsole{stdin: deps.stdin, stderr: deps.stderr, stdout: deps.stdout}
		var err error
		selectedAccount, err = console.readRequiredValue(
			"1Password account name shown in the desktop app, or account UUID",
		)
		if err != nil {
			return err
		}
	}
	if err := validateLocalAccountReference(selectedAccount); err != nil {
		return err
	}

	fmt.Fprintln(deps.stdout, "Local 1Password quota-fallback plan:")
	fmt.Fprintf(deps.stdout, "  Account: %s\n", selectedAccount)
	fmt.Fprintf(deps.stdout, "  Vault: %s (fixed OneNod Vault; resolved to an ID before saving)\n", localFallbackVaultTitle)
	fmt.Fprintf(deps.stdout, "  1Password prerequisite: Settings > Developer > %s must be enabled\n", localFallbackSDKSetting)
	fmt.Fprintln(deps.stdout, "  Secret reads: official 1Password Desktop SDK, only after the Gateway reports onepassword_rate_limited")
	fmt.Fprintln(deps.stdout, "  SSH/Git signing: local 1Password SSH Agent, only after the same exact Gateway error")
	fmt.Fprintln(deps.stdout, "  Item create, patch, archive, denial, Lock mode, revocation, timeout, network failure, and generic 5xx responses never fall back.")
	fmt.Fprintln(deps.stdout, "  1Password authorizes the SDK process to the selected account for up to ten minutes of inactivity; OneNod restricts its code path to the resolved Agent Vault.")
	configPath, err := onePasswordSSHAgentConfigPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Before continuing, make the Agent Vault available to the 1Password SSH Agent.")
	fmt.Fprintf(deps.stdout, "Add this entry to %s without removing unrelated entries:\n\n", configPath)
	fmt.Fprintln(deps.stdout, "[[ssh-keys]]")
	fmt.Fprintf(deps.stdout, "vault = %s\n", strconv.Quote(localFallbackVaultTitle))
	fmt.Fprintf(deps.stdout, "account = %s\n\n", strconv.Quote(selectedAccount))
	fmt.Fprintf(deps.stdout, "In 1Password Settings > Developer, also enable both the SSH Agent and %s. Lock and unlock 1Password if it does not notice a newly created agent.toml file.\n", localFallbackSDKSetting)
	configured, err := promptYesNo(
		deps.stdin,
		deps.stdout,
		"I saved the agent.toml entry and enabled both 1Password integrations",
		false,
	)
	if err != nil {
		return err
	}
	if !configured {
		return errors.New("1Password local integrations were not confirmed; no OneNod fallback configuration was saved")
	}
	if _, exists, err := readOptionalRegularFile(configPath, 1<<20); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("1Password SSH Agent config does not exist at %s", configPath)
	}

	confirmed, err := promptYesNo(
		deps.stdin,
		deps.stdout,
		"Request local 1Password authorization and verify the Agent Vault now?",
		false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("local 1Password fallback was not configured")
	}

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	backend, err := localOnePasswordFactoryFor(deps)(clientCtx, selectedAccount)
	if err != nil {
		return fmt.Errorf(
			"open local 1Password Desktop SDK integration failed; verify Settings > Developer > %s is enabled: %w",
			localFallbackSDKSetting,
			err,
		)
	}
	validationCtx, validationCancel := context.WithTimeout(
		context.Background(),
		localFallbackOperationLimit,
	)
	defer validationCancel()
	vault, err := backend.ResolveAgentVault(validationCtx)
	if err != nil {
		if errors.Is(validationCtx.Err(), context.DeadlineExceeded) {
			return errors.New("resolve the local Agent Vault through 1Password timed out")
		}
		return err
	}
	if vault.Title != localFallbackVaultTitle || !onePasswordVaultIDPattern.MatchString(vault.ID) {
		return errors.New("local 1Password integration returned an invalid Agent Vault identity")
	}
	sshCatalog, err := backend.SearchCatalog(validationCtx, vault.ID, "")
	if err != nil {
		if errors.Is(validationCtx.Err(), context.DeadlineExceeded) {
			return errors.New("read Agent SSH inventory through the local 1Password SDK timed out")
		}
		return fmt.Errorf("read Agent SSH inventory through the local 1Password SDK failed: %w", err)
	}
	if err := verifyNativeSSHAgentInventory(validationCtx, deps, sshCatalog.Items); err != nil {
		return err
	}
	config := localFallbackConfig{
		Account: selectedAccount, SchemaVersion: localFallbackConfigSchema,
		VaultID: vault.ID, VaultTitle: vault.Title,
	}
	if err := writeLocalFallbackConfig(config); err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Configured local 1Password fallback for exact Service Account quota exhaustion.")
	fmt.Fprintln(deps.stdout, "Agents must continue to call may; this does not authorize direct op usage.")
	return nil
}

func writeLocalFallbackStatus(output io.Writer) error {
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return err
	}
	if !found {
		_, err = fmt.Fprintln(output, "Local 1Password fallback: not configured")
		return err
	}
	configPath, err := onePasswordSSHAgentConfigPath()
	if err != nil {
		return err
	}
	_, agentConfigPresent, configErr := readOptionalRegularFile(configPath, 1<<20)
	if configErr != nil {
		return configErr
	}
	socketPath, err := onePasswordSSHAgentSocketPath()
	if err != nil {
		return err
	}
	_, socketErr := os.Lstat(socketPath)
	fmt.Fprintln(output, "Local 1Password fallback: configured")
	fmt.Fprintf(output, "  account: %s\n", config.Account)
	fmt.Fprintf(output, "  vault: %s (%s)\n", config.VaultTitle, config.VaultID)
	fmt.Fprintf(output, "  Desktop SDK app: %s\n", localDesktopAppStatus())
	fmt.Fprintf(output, "  1Password SSH Agent socket: %s\n", presentStatus(socketErr == nil))
	fmt.Fprintf(output, "  agent.toml: %s (%s)\n", presentStatus(agentConfigPresent), configPath)
	return nil
}

func restoreLocalFallbackConfiguration(output io.Writer) error {
	path, err := localFallbackConfigPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove local 1Password fallback configuration failed")
	}
	fmt.Fprintln(output, "Disabled OneNod local 1Password fallback.")
	fmt.Fprintln(output, "The user-owned 1Password agent.toml file and 1Password app settings were not changed.")
	return nil
}

func onePasswordSSHAgentConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for the 1Password SSH Agent config failed")
	}
	return filepath.Join(home, ".config", "1Password", "ssh", "agent.toml"), nil
}

func localFallbackConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for local fallback configuration failed")
	}
	return filepath.Join(home, userAgentDirectoryName, localFallbackConfigFileName), nil
}

func readLocalFallbackConfig() (localFallbackConfig, bool, error) {
	path, err := localFallbackConfigPath()
	if err != nil {
		return localFallbackConfig{}, false, err
	}
	encoded, exists, err := readOptionalRegularFile(path, maxLocalFallbackConfigBytes)
	if err != nil || !exists {
		return localFallbackConfig{}, exists, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return localFallbackConfig{}, false, errors.New("local fallback configuration must be private to the current user")
	}
	var config localFallbackConfig
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || ensureDecoderEOF(decoder) != nil ||
		config.SchemaVersion != localFallbackConfigSchema ||
		config.VaultTitle != localFallbackVaultTitle ||
		!onePasswordVaultIDPattern.MatchString(config.VaultID) ||
		validateLocalAccountReference(config.Account) != nil {
		return localFallbackConfig{}, false, errors.New("local fallback configuration is invalid")
	}
	return config, true, nil
}

func writeLocalFallbackConfig(config localFallbackConfig) error {
	config.SchemaVersion = localFallbackConfigSchema
	if config.VaultTitle != localFallbackVaultTitle ||
		!onePasswordVaultIDPattern.MatchString(config.VaultID) ||
		validateLocalAccountReference(config.Account) != nil {
		return errors.New("refusing to write an invalid local fallback configuration")
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("encode local fallback configuration failed")
	}
	encoded = append(encoded, '\n')
	path, err := localFallbackConfigPath()
	if err != nil {
		return err
	}
	return writeAtomicUserConfig(path, encoded, 0o600)
}

func validateLocalAccountReference(value string) error {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) ||
		len([]rune(value)) > 160 {
		return errors.New("1Password account name or UUID is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("1Password account name or UUID is invalid")
		}
	}
	return nil
}

func localDesktopAppStatus() string {
	paths := []string{
		"/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(
			paths,
			filepath.Join(
				home,
				"Applications",
				"1Password.app",
				"Contents",
				"Frameworks",
				"libop_sdk_ipc_client.dylib",
			),
		)
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return "present"
		}
	}
	return "not detected"
}

func presentStatus(present bool) string {
	if present {
		return "present"
	}
	return "not detected"
}
