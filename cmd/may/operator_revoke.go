package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func promptAndRevokeWranglerProfile(
	wrangler string,
	usedProfile string,
	accountID string,
	base http.RoundTripper,
	console *operatorConsole,
	defaultYes bool,
) (bool, error) {
	profiles, err := wranglerProfilesForAccount(wrangler, accountID, base)
	if err != nil {
		return false, err
	}
	if len(profiles) == 0 {
		fmt.Fprintln(console.stdout, "This Mac no longer has a Wrangler profile for the dedicated Cloudflare account.")
		return true, nil
	}
	fmt.Fprintln(console.stdout, "Wrangler profiles on this Mac that expose the dedicated Cloudflare account:")
	for _, profile := range profiles {
		marker := ""
		if profile == usedProfile {
			marker = " (used for this operation)"
		}
		fmt.Fprintf(console.stdout, "  - %s%s\n", profile, marker)
	}
	var revoke bool
	if defaultYes {
		revoke, err = console.confirmDefaultYes("Revoke this Mac's Cloudflare deployment authority now?")
	} else {
		revoke, err = console.confirmDefaultNo("Revoke this Mac's Cloudflare deployment authority now?")
	}
	if err != nil {
		return false, err
	}
	if !revoke {
		fmt.Fprintf(
			console.stderr,
			"Cloudflare deployment authority was retained by explicit choice in: %s.\n",
			strings.Join(profiles, ", "),
		)
		return false, nil
	}
	for _, profile := range profiles {
		if err := deleteWranglerProfileAndVerify(wrangler, profile, console); err != nil {
			return false, err
		}
	}
	remaining, err := wranglerProfilesForAccount(wrangler, accountID, base)
	if err != nil {
		return false, fmt.Errorf("Wrangler profiles were deleted, but current-Mac Cloudflare revocation could not be proven: %w", err)
	}
	if len(remaining) > 0 {
		return false, fmt.Errorf(
			"current-Mac Cloudflare revocation is incomplete; profiles still expose the dedicated account: %s",
			strings.Join(remaining, ", "),
		)
	}
	return true, nil
}

func runOperatorRevokeCloudflare(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("operator revoke-cloudflare", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may operator revoke-cloudflare")
	}
	if err := assertNoCloudflareCredentialEnvironment(); err != nil {
		return err
	}
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil {
		return err
	}
	wrangler, err := checkWranglerRevocationTool()
	if err != nil {
		return err
	}
	console := &operatorConsole{stdin: deps.stdin, stdout: deps.stdout, stderr: deps.stderr}
	fmt.Fprintln(console.stdout, "OneNod current-Mac Cloudflare revocation plan")
	fmt.Fprintf(console.stdout, "  Dedicated account: %s\n", receipt.AccountID)
	fmt.Fprintf(console.stdout, "  Deployment Origin: %s\n", receipt.Origin)
	fmt.Fprintln(console.stdout, "  Action: remove every local Wrangler profile that currently exposes this account")
	fmt.Fprintln(console.stdout, "  Remote Workers, Durable Objects, traffic, and 1Password data are unchanged")

	revoked, err := promptAndRevokeWranglerProfile(
		wrangler,
		receipt.CloudflareProfile,
		receipt.AccountID,
		deps.cloudflareTransport,
		console,
		false,
	)
	if err != nil {
		return err
	}
	receipt.CloudflareProfileRevoked = revoked
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
		return fmt.Errorf("Cloudflare authority handling finished, but the operator receipt could not be updated: %w", err)
	}
	if !revoked {
		return errors.New("Cloudflare revocation was not confirmed; current-Mac deployment authority remains")
	}
	fmt.Fprintln(console.stdout, "OneNod verified that this Mac has no Wrangler profile for the dedicated Cloudflare account.")
	return nil
}

func checkWranglerRevocationTool() (string, error) {
	path, err := exec.LookPath("wrangler")
	if err != nil {
		return "", errors.New("required external tool wrangler is not installed")
	}
	for _, arguments := range [][]string{
		{"auth", "delete", "--help"},
		{"auth", "list", "--help"},
		{"auth", "token", "--help"},
	} {
		command := exec.Command(path, arguments...)
		command.Env = operatorEnvironment(nil)
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Run(); err != nil {
			return "", fmt.Errorf("wrangler lacks required capability %s", strings.Join(arguments, " "))
		}
	}
	return path, nil
}

func wranglerProfilesForAccount(
	wrangler string,
	accountID string,
	base http.RoundTripper,
) ([]string, error) {
	profiles, err := listWranglerProfiles(wrangler)
	if err != nil {
		return nil, err
	}
	var matching []string
	for _, profile := range profiles {
		accounts, authenticated, inspectErr := tryInspectWranglerProfileAccounts(wrangler, profile, base)
		if inspectErr != nil {
			return nil, fmt.Errorf("cannot safely inspect authenticated Wrangler profile %q: %w", profile, inspectErr)
		}
		if !authenticated {
			continue
		}
		for _, account := range accounts {
			if account.ID == accountID {
				matching = append(matching, profile)
				break
			}
		}
	}
	sort.Strings(matching)
	return matching, nil
}

func deleteWranglerProfileAndVerify(
	wrangler string,
	profile string,
	console *operatorConsole,
) error {
	output, deleteErr := runOperatorCapture(
		wrangler, []string{"auth", "delete", profile}, "", nil, operatorCommandTimeout,
	)
	zeroBytes(output)
	output, tokenErr := runOperatorCapture(
		wrangler, []string{"auth", "token", "--profile", profile, "--json"}, "", nil, 30*time.Second,
	)
	zeroBytes(output)
	if tokenErr == nil {
		return fmt.Errorf("Wrangler profile %q still yields an OAuth token after deletion", profile)
	}
	if deleteErr != nil {
		fmt.Fprintf(
			console.stderr,
			"Wrangler reported an error while deleting %s, but token absence confirms this Mac no longer has that profile authority. Continuing without retry.\n",
			profile,
		)
	}
	fmt.Fprintf(console.stdout, "Revoked Wrangler profile %s from this Mac.\n", profile)
	return nil
}

func listWranglerProfiles(wrangler string) ([]string, error) {
	output, err := runOperatorCapture(wrangler, []string{"auth", "list"}, "", map[string]string{
		"FORCE_COLOR": "0", "NO_COLOR": "1",
	}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return nil, errors.New("Wrangler auth profiles cannot be enumerated safely")
	}
	return parseWranglerProfiles(output)
}

func parseWranglerProfiles(output []byte) ([]string, error) {
	plain := ansiEscapePattern.ReplaceAll(output, nil)
	defer zeroBytes(plain)
	seenHeader := false
	seen := map[string]struct{}{}
	var profiles []string
	scanner := bufio.NewScanner(bytes.NewReader(plain))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "│") && strings.HasSuffix(line, "│") {
			columns := strings.Split(line, "│")
			if len(columns) != 4 {
				return nil, errors.New("Wrangler auth list table has an unsupported shape")
			}
			profile := strings.TrimSpace(columns[1])
			boundDirectories := strings.TrimSpace(columns[2])
			if profile == "Profile" && boundDirectories == "Bound Directories" {
				seenHeader = true
				continue
			}
			if !seenHeader || !wranglerProfileNamePattern.MatchString(profile) || boundDirectories == "" {
				return nil, errors.New("Wrangler auth list contains an invalid profile row")
			}
			if _, duplicate := seen[profile]; duplicate {
				return nil, errors.New("Wrangler auth list contains duplicate profiles")
			}
			seen[profile] = struct{}{}
			profiles = append(profiles, profile)
		}
	}
	if scanner.Err() != nil || !seenHeader || len(profiles) == 0 {
		return nil, errors.New("Wrangler auth list output could not be parsed safely")
	}
	sort.Strings(profiles)
	return profiles, nil
}

func inspectWranglerProfileAccounts(
	wrangler string,
	profile string,
	base http.RoundTripper,
) ([]activeWranglerAccount, error) {
	accounts, authenticated, err := tryInspectWranglerProfileAccounts(wrangler, profile, base)
	if err != nil {
		return nil, err
	}
	if !authenticated {
		return nil, errors.New("Wrangler profile is not OAuth-authenticated")
	}
	return accounts, nil
}

func tryInspectWranglerProfileAccounts(
	wrangler string,
	profile string,
	base http.RoundTripper,
) ([]activeWranglerAccount, bool, error) {
	token, err := readNamedWranglerOAuthToken(wrangler, profile)
	if err != nil {
		return nil, false, nil
	}
	defer zeroBytes(token)
	accounts, err := fetchCloudflareAccounts(base, token)
	if err != nil {
		return nil, true, err
	}
	return accounts, true, nil
}

func bestEffortDeleteWranglerProfile(wrangler, profile string) bool {
	output, err := runOperatorCapture(wrangler, []string{"auth", "delete", profile}, "", nil, 30*time.Second)
	zeroBytes(output)
	if err != nil {
		return false
	}
	output, err = runOperatorCapture(wrangler, []string{"auth", "token", "--profile", profile, "--json"}, "", nil, 30*time.Second)
	zeroBytes(output)
	return err != nil
}
