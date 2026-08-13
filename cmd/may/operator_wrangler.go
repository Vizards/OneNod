package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"time"
)

func createTemporaryWranglerProfile(wrangler string, console *operatorConsole) (string, error) {
	id, err := newUUIDv4()
	if err != nil {
		return "", errors.New("generate temporary Wrangler profile name failed")
	}
	profile := "onenod-operator-" + strings.ReplaceAll(id, "-", "")[:12]
	fmt.Fprintf(console.stdout, "Wrangler will open browser OAuth for temporary named profile %s. Use the dedicated Cloudflare account, not your everyday account.\n", profile)
	if err := runOperatorCommand(wrangler, []string{"auth", "create", profile}, "", nil, console, operatorCommandTimeout); err != nil {
		return "", errors.New("create temporary Wrangler OAuth profile failed")
	}
	return profile, nil
}

func inspectWranglerIdentity(
	wrangler string,
	profile string,
	base http.RoundTripper,
) (wranglerIdentity, error) {
	accounts, err := inspectWranglerProfileAccounts(wrangler, profile, base)
	if err != nil {
		return wranglerIdentity{}, errors.New("Wrangler named profile is not OAuth-authenticated")
	}
	if len(accounts) == 0 {
		return wranglerIdentity{}, errors.New("Wrangler OAuth cannot access any Cloudflare account")
	}
	return wranglerIdentity{AuthType: "OAuth Token", Accounts: accounts}, nil
}

func selectWranglerAccount(identity wranglerIdentity, console *operatorConsole) (activeWranglerAccount, error) {
	if len(identity.Accounts) == 1 {
		return identity.Accounts[0], nil
	}
	fmt.Fprintln(console.stdout, "Wrangler OAuth exposes multiple Cloudflare accounts:")
	for index, account := range identity.Accounts {
		fmt.Fprintf(console.stdout, "  %d. %s (%s)\n", index+1, account.Name, account.ID)
	}
	value, err := console.readRequiredValue("Select the dedicated Cloudflare account number")
	if err != nil {
		return activeWranglerAccount{}, err
	}
	var selected int
	if _, err := fmt.Sscanf(value, "%d", &selected); err != nil || selected < 1 || selected > len(identity.Accounts) || fmt.Sprintf("%d", selected) != value {
		return activeWranglerAccount{}, errors.New("Cloudflare account selection is invalid")
	}
	return identity.Accounts[selected-1], nil
}

func selectOrCreateWranglerProfile(
	wrangler string,
	requiredAccountID string,
	base http.RoundTripper,
	console *operatorConsole,
) (operatorWranglerSelection, error) {
	profiles, err := listWranglerProfiles(wrangler)
	if err != nil {
		return operatorWranglerSelection{}, err
	}
	var candidates []operatorWranglerSelection
	for _, profile := range profiles {
		accounts, authenticated, inspectErr := tryInspectWranglerProfileAccounts(
			wrangler, profile, base,
		)
		if inspectErr != nil {
			return operatorWranglerSelection{}, fmt.Errorf("cannot inspect authenticated Wrangler profile %q: %w", profile, inspectErr)
		}
		if !authenticated {
			continue
		}
		for _, account := range accounts {
			if requiredAccountID == "" || account.ID == requiredAccountID {
				candidates = append(candidates, operatorWranglerSelection{
					Account: account, Profile: profile,
				})
			}
		}
	}
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].Profile != candidates[right].Profile {
			return candidates[left].Profile < candidates[right].Profile
		}
		if candidates[left].Account.Name != candidates[right].Account.Name {
			return candidates[left].Account.Name < candidates[right].Account.Name
		}
		return candidates[left].Account.ID < candidates[right].Account.ID
	})
	if len(candidates) == 1 {
		selected := candidates[0]
		fmt.Fprintf(
			console.stdout,
			"Using existing Wrangler profile %s for Cloudflare account %s (%s).\n",
			selected.Profile, selected.Account.Name, selected.Account.ID,
		)
		return selected, nil
	}
	if len(candidates) > 1 {
		fmt.Fprintln(console.stdout, "Authenticated Wrangler profiles expose multiple eligible Cloudflare accounts:")
		for index, candidate := range candidates {
			fmt.Fprintf(
				console.stdout, "  %d. %s — %s (%s)\n",
				index+1, candidate.Profile, candidate.Account.Name, candidate.Account.ID,
			)
		}
		fmt.Fprintf(console.stdout, "  %d. Sign in to another Cloudflare account\n", len(candidates)+1)
		value, readErr := console.readRequiredValue("Select the dedicated Cloudflare account number")
		if readErr != nil {
			return operatorWranglerSelection{}, readErr
		}
		var selected int
		if _, scanErr := fmt.Sscanf(value, "%d", &selected); scanErr != nil ||
			selected < 1 || selected > len(candidates)+1 || fmt.Sprintf("%d", selected) != value {
			return operatorWranglerSelection{}, errors.New("Cloudflare account selection is invalid")
		}
		if selected <= len(candidates) {
			return candidates[selected-1], nil
		}
	}
	return createAndSelectTemporaryWranglerProfile(
		wrangler, requiredAccountID, base, console,
	)
}

func createAndSelectTemporaryWranglerProfile(
	wrangler string,
	requiredAccountID string,
	base http.RoundTripper,
	console *operatorConsole,
) (selection operatorWranglerSelection, returnErr error) {
	profile, err := createTemporaryWranglerProfile(wrangler, console)
	if err != nil {
		return operatorWranglerSelection{}, err
	}
	keepProfile := false
	defer func() {
		if returnErr != nil && !keepProfile && !bestEffortDeleteWranglerProfile(wrangler, profile) {
			fmt.Fprintf(console.stderr, "SECURITY WARNING: cleanup of incomplete Cloudflare profile %s failed. Revoke it now with: wrangler auth delete %s\n", profile, profile)
		}
	}()
	identity, err := inspectWranglerIdentity(wrangler, profile, base)
	if err != nil {
		return operatorWranglerSelection{}, err
	}
	var account activeWranglerAccount
	if requiredAccountID == "" {
		account, err = selectWranglerAccount(identity, console)
	} else {
		var found bool
		account, found = accountByID(identity.Accounts, requiredAccountID)
		if !found {
			err = errors.New("new Wrangler profile does not expose the deployment receipt's dedicated Cloudflare account")
		}
	}
	if err != nil {
		return operatorWranglerSelection{}, err
	}
	keepProfile = true
	return operatorWranglerSelection{
		Account: account, CreatedByMay: true, Profile: profile,
	}, nil
}

func readNamedWranglerOAuthToken(wrangler, profile string) ([]byte, error) {
	output, err := runOperatorCapture(wrangler, []string{"auth", "token", "--profile", profile, "--json"}, "", nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return nil, errors.New("Wrangler OAuth credential cannot be loaded from the named profile")
	}
	var credential struct {
		Type  string `json:"type"`
		Token string `json:"token"`
	}
	if json.Unmarshal(output, &credential) != nil || credential.Type != "oauth" || credential.Token == "" {
		return nil, errors.New("Wrangler named profile did not return an OAuth credential")
	}
	return []byte(credential.Token), nil
}

func readBinaryProductionTargetIdentity(accountID, accountSubdomain string, console *operatorConsole) (productionTargetIdentity, error) {
	fmt.Fprintf(console.stdout, "Cloudflare workers.dev account subdomain: %s (automatically discovered)\n", accountSubdomain)
	deploymentID, err := newDeploymentID()
	if err != nil {
		return productionTargetIdentity{}, errors.New("generate Cloudflare deployment ID failed")
	}
	gateway, err := console.readValue(
		"Public Gateway Worker name",
		defaultGatewayWorkerBaseName+"-"+deploymentID,
	)
	if err != nil {
		return productionTargetIdentity{}, err
	}
	executor, err := console.readValue(
		"Private Executor Worker name",
		defaultExecutorWorkerBaseName+"-"+deploymentID,
	)
	if err != nil {
		return productionTargetIdentity{}, err
	}
	origin := workersDevOrigin(gateway, accountSubdomain)
	return validateProductionTargetIdentity(productionTargetIdentity{
		AccountID: accountID, AccountSubdomain: accountSubdomain,
		GatewayName: gateway, ExecutorName: executor, Origin: origin,
		RPID: strings.TrimPrefix(origin, "https://"),
	})
}

func runOperatorCapture(
	name string,
	arguments []string,
	directory string,
	overrides map[string]string,
	timeout time.Duration,
	input ...[]byte,
) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	command.Env = operatorEnvironment(overrides)
	if len(input) > 0 {
		command.Stdin = bytes.NewReader(input[0])
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if ctx.Err() != nil {
		zeroBytes(stdout.Bytes())
		zeroBytes(stderr.Bytes())
		return nil, fmt.Errorf("command %s timed out", name)
	}
	if err != nil {
		combined := append([]byte(nil), stdout.Bytes()...)
		combined = append(combined, stderr.Bytes()...)
		zeroBytes(stdout.Bytes())
		zeroBytes(stderr.Bytes())
		return combined, err
	}
	result := append([]byte(nil), stdout.Bytes()...)
	zeroBytes(stdout.Bytes())
	zeroBytes(stderr.Bytes())
	return result, nil
}

func runOperatorCommand(
	name string,
	arguments []string,
	directory string,
	input []byte,
	console *operatorConsole,
	timeout time.Duration,
) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	command.Env = operatorEnvironment(nil)
	if input != nil {
		command.Stdin = bytes.NewReader(input)
	} else {
		command.Stdin = console.stdin
	}
	command.Stdout = console.stdout
	command.Stderr = console.stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("command %s timed out", name)
		}
		return fmt.Errorf("command %s failed", name)
	}
	return nil
}

func runWranglerCapture(
	wrangler, profile, cwd string,
	arguments []string,
	input []byte,
	timeout time.Duration,
) ([]byte, error) {
	arguments = append(append([]string(nil), arguments...), "--profile", profile, "--cwd", cwd)
	if input == nil {
		return runOperatorCapture(wrangler, arguments, "", nil, timeout)
	}
	return runOperatorCapture(wrangler, arguments, "", nil, timeout, input)
}

func runWranglerStreaming(
	wrangler, profile, cwd string,
	arguments []string,
	input []byte,
	console *operatorConsole,
	timeout time.Duration,
) error {
	arguments = append(append([]string(nil), arguments...), "--profile", profile, "--cwd", cwd)
	return runOperatorCommand(wrangler, arguments, "", input, console, timeout)
}
