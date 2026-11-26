package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const manualLocalFallbackFileName = "local-fallback-manual.json"

// Kept separately from the existing binding so older releases can still read
// their configuration after a rollback. An older release ignores this mode.
type manualLocalFallbackMode struct {
	Account       string `json:"account"`
	DeviceID      string `json:"device_id"`
	Origin        string `json:"origin"`
	SchemaVersion int    `json:"schema_version"`
	VaultID       string `json:"vault_id"`
}

func manualLocalFallbackPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for manual local fallback failed")
	}
	return filepath.Join(home, userAgentDirectoryName, manualLocalFallbackFileName), nil
}

func manualLocalFallbackEnabled() (bool, error) {
	_, enabled, err := readManualLocalFallbackMode()
	return enabled, err
}

func readManualLocalFallbackMode() (manualLocalFallbackMode, bool, error) {
	path, err := manualLocalFallbackPath()
	if err != nil {
		return manualLocalFallbackMode{}, false, err
	}
	encoded, exists, err := readOptionalRegularFile(path, maxLocalFallbackConfigBytes)
	if err != nil || !exists {
		return manualLocalFallbackMode{}, false, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return manualLocalFallbackMode{}, false, errors.New("manual local fallback mode must be private to the current user")
	}
	var mode manualLocalFallbackMode
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&mode) != nil || ensureDecoderEOF(decoder) != nil || mode.SchemaVersion != 1 {
		return manualLocalFallbackMode{}, false, errors.New("manual local fallback mode is invalid; disable it and enable it again")
	}
	parsedOrigin, err := parseGatewayOrigin(mode.Origin)
	if err != nil || parsedOrigin.String() != mode.Origin || mode.DeviceID == "" {
		return manualLocalFallbackMode{}, false, errors.New("manual local fallback requester binding is invalid; disable it and enable it again")
	}
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return manualLocalFallbackMode{}, false, err
	}
	if !found || mode.Account != config.Account || mode.VaultID != config.VaultID {
		return manualLocalFallbackMode{}, false, errors.New("manual local fallback no longer matches its configured account and Vault; disable it and configure it again")
	}
	return mode, true, nil
}

func manualLocalFallbackForRequester(origin string, credential *requesterCredential) (bool, error) {
	mode, enabled, err := readManualLocalFallbackMode()
	if err != nil || !enabled {
		return false, err
	}
	parsedOrigin, err := parseGatewayOrigin(origin)
	if err != nil || credential == nil || mode.Origin != parsedOrigin.String() || mode.DeviceID != credential.DeviceID {
		return false, errors.New("manual local fallback is bound to another Origin or requester; disable it and enable it for this requester")
	}
	return true, nil
}

func enableManualLocalFallback(deps dependencies, cli cliConfig) error {
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return err
	}
	if !found {
		return errors.New("local fallback is not configured; run `may configure local-fallback apply` first")
	}
	cli, deps, err = prepareRequesterInvocation(cli, deps)
	if err != nil {
		return err
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return err
	}
	origin, err := parseGatewayOrigin(cli.origin)
	if err != nil {
		return err
	}
	enabled, err := manualLocalFallbackForRequester(origin.String(), credential)
	if err != nil {
		return err
	}
	if enabled {
		fmt.Fprintln(deps.stdout, "Manual local 1Password fallback is already enabled on this Mac.")
		return nil
	}
	fmt.Fprintf(deps.stdout, "Manual local fallback will use the %s account and its configured Agent Vault on this Mac.\n", config.Account)
	fmt.Fprintf(deps.stdout, "Requester: %s at %s\n", credential.DisplayName, origin.String())
	fmt.Fprintln(deps.stdout, "Supported reads and SSH/Git signatures will go directly to local 1Password until manually disabled.")
	fmt.Fprintln(deps.stdout, "These operations bypass Gateway approval, Lock mode, requester revocation, Beholder, and Gateway Activity; local 1Password authorization still applies.")
	fmt.Fprintln(deps.stdout, "1Password may remember an SDK or SSH authorization, so it may not prompt for every operation. Item changes are unavailable in this mode.")
	fmt.Fprintln(deps.stdout, "This applies to new operations only; reconcile any earlier operation with an unknown remote outcome before retrying it.")
	confirmed, err := promptYesNo(deps.stdin, deps.stdout, "Enable manual local 1Password fallback on this Mac?", false)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("manual local fallback was not enabled")
	}
	current, stillConfigured, err := readLocalFallbackConfig()
	if err != nil {
		return err
	}
	if !stillConfigured || current.Account != config.Account || current.VaultID != config.VaultID {
		return errors.New("local fallback configuration changed during confirmation; review it and try again")
	}
	currentCLI, currentDeps, err := prepareRequesterInvocation(cli, deps)
	if err != nil {
		return err
	}
	currentCredential, err := currentDeps.keychain.Load()
	if err != nil {
		return err
	}
	if currentCLI.origin != cli.origin || currentCredential.DeviceID != credential.DeviceID {
		return errors.New("requester changed during confirmation; review it and try again")
	}
	mode := manualLocalFallbackMode{
		Account: config.Account, DeviceID: credential.DeviceID, Origin: origin.String(),
		SchemaVersion: 1, VaultID: config.VaultID,
	}
	encoded, err := json.MarshalIndent(mode, "", "  ")
	if err != nil {
		return errors.New("encode manual local fallback mode failed")
	}
	path, err := manualLocalFallbackPath()
	if err != nil {
		return err
	}
	if err := writeAtomicUserConfig(path, append(encoded, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Manual local 1Password fallback is enabled. Run `may configure local-fallback disable` to return to the Gateway.")
	return nil
}

func disableManualLocalFallback() error {
	path, err := manualLocalFallbackPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("disable manual local 1Password fallback failed")
	}
	return nil
}
