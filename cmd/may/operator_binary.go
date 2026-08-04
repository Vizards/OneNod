package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	cloudflareAccountPageSize     = 50
	maxCloudflareAccountPages     = 100
	maxCloudflareAccountResponse  = 256 * 1024
	operatorReceiptSchema         = 1
	operatorTransactionSchema     = 1
	operatorCommandTimeout        = 5 * time.Minute
	operatorInitializationTimeout = 45 * time.Minute
	gatewayReadinessTimeout       = 2 * time.Minute
	gatewayReadinessPollInterval  = 2 * time.Second
	updateConvergenceTimeout      = 30 * time.Second
	updateConvergencePollInterval = 2 * time.Second
	bootstrapCompletionTimeout    = 30 * time.Minute
	bootstrapPollInterval         = 2 * time.Second
	initializerReexecIdentity     = "ONENOD_INIT_REEXEC_IDENTITY"
	operatorUsage                 = "usage: may operator init [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] | may operator update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] | may operator revoke-cloudflare"
)

var workerVersionIDPattern = regexp.MustCompile(`(?i)Worker Version ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)
var wranglerProfileNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type operatorDeploymentReceipt struct {
	AccountID                string `json:"account_id"`
	AccountSubdomain         string `json:"account_subdomain"`
	Channel                  string `json:"channel"`
	CloudflareProfile        string `json:"cloudflare_profile"`
	CloudflareProfileRevoked bool   `json:"cloudflare_profile_revoked"`
	DeploymentArtifact       string `json:"deployment_artifact"`
	DeploymentArtifactSHA    string `json:"deployment_artifact_sha256"`
	ExecutorVersionID        string `json:"executor_version_id"`
	ExecutorWorker           string `json:"executor_worker"`
	GatewayVersionID         string `json:"gateway_version_id"`
	GatewayWorker            string `json:"gateway_worker"`
	OnePasswordAccount       string `json:"onepassword_account"`
	OnePasswordVaultID       string `json:"onepassword_vault_id"`
	Origin                   string `json:"origin"`
	RPID                     string `json:"rp_id"`
	ReleaseVersion           string `json:"release_version"`
	SchemaVersion            int    `json:"schema_version"`
	SourceCommit             string `json:"source_commit"`
	UpdatedAt                string `json:"updated_at"`
	VAPIDPublicKey           string `json:"vapid_public_key"`
}

type operatorUpdateTransaction struct {
	AccountID             string `json:"account_id"`
	DeploymentArtifact    string `json:"deployment_artifact"`
	DeploymentArtifactSHA string `json:"deployment_artifact_sha256"`
	ExecutorAfter         string `json:"executor_after,omitempty"`
	ExecutorBefore        string `json:"executor_before"`
	GatewayAfter          string `json:"gateway_after,omitempty"`
	GatewayBefore         string `json:"gateway_before"`
	ID                    string `json:"id"`
	Outcome               string `json:"outcome"`
	Phase                 string `json:"phase"`
	ProfileRevoked        bool   `json:"profile_revoked"`
	ReleaseFrom           string `json:"release_from"`
	ReleaseTo             string `json:"release_to"`
	SchemaVersion         int    `json:"schema_version"`
	UpdatedAt             string `json:"updated_at"`
}

type activeWranglerAccount struct {
	ID   string
	Name string
}

type humanRecoveryVault struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type onePasswordProvisioningPlan struct {
	Account            string
	AgentVaultName     string
	RecoveryVaultName  string
	ServiceAccountName string
}

type createdOnePasswordResource struct {
	ID       string
	Name     string
	ParentID string
	Status   string
	Type     string
}

type onePasswordProvisioningInventory struct {
	Resources []createdOnePasswordResource
}

const independentCloudflareAccountWarning = "IMPORTANT: deploy OneNod to a dedicated Cloudflare account, not the account used by your primary or everyday Wrangler workflow."

type wranglerIdentity struct {
	AuthType string
	Accounts []activeWranglerAccount
}

type operatorWranglerSelection struct {
	Account      activeWranglerAccount
	CreatedByMay bool
	Profile      string
}

type operatorTools struct {
	Node        string
	OnePassword string
	Wrangler    string
}

type remoteOutcomeUnknownError struct {
	ObservedVersion string
	Operation       string
	Worker          string
}

func (value *remoteOutcomeUnknownError) Error() string {
	detail := ""
	if value.ObservedVersion != "" {
		detail = "; possible Worker Version ID " + value.ObservedVersion
	}
	return fmt.Sprintf(
		"remote_outcome_unknown: %s for %s could not be proven%s; inspect authoritative Cloudflare state before retrying",
		value.Operation, value.Worker, detail,
	)
}

type observedDeploymentError struct {
	ObservedVersion  string
	RequestedVersion string
	Worker           string
}

func (value *observedDeploymentError) Error() string {
	return fmt.Sprintf(
		"deploy Worker version for %s failed; authoritative traffic remains on %s instead of %s",
		value.Worker, value.ObservedVersion, value.RequestedVersion,
	)
}

func runBinaryFirstProductionDeployment(
	console *operatorConsole,
	deps dependencies,
	selection releaseSelection,
) (returnErr error) {
	channel := selection.Channel
	var onePasswordInventory onePasswordProvisioningInventory
	onePasswordCleanupActive := false
	defer func() {
		if returnErr != nil && onePasswordCleanupActive && len(onePasswordInventory.Resources) > 0 {
			writeOnePasswordCleanupInventory(console.stderr, onePasswordInventory)
		}
	}()
	fmt.Fprintln(console.stdout, independentCloudflareAccountWarning)
	if err := assertNoCloudflareCredentialEnvironment(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), operatorInitializationTimeout)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	currentChannel := releaseChannelStable
	currentVersion := ""
	if initializer, found, readErr := readInitializerInstallReceipt(); readErr != nil {
		return readErr
	} else if found {
		currentChannel = releaseChannel(initializer.Channel)
		currentVersion = initializer.ReleaseVersion
	}
	if currentVersion != "" && compareProductVersions(release.Manifest.ReleaseVersion, currentVersion) < 0 {
		if awaitingCompatibleRelease(
			currentVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				console.stdout, currentVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return errors.New("anti_rollback: selected official release is older than the installed initializer")
	}
	if os.Getenv(initializerReexecIdentity) == "" {
		if err := confirmHigherRiskChannel(
			console.stdin, console.stdout, currentChannel, channel, "Operator initialization",
		); err != nil {
			return err
		}
	}
	reexecuted, err := ensureCurrentInitializer(ctx, release, deps, selection)
	if err != nil {
		return err
	}
	if reexecuted {
		return nil
	}
	bundle, err := stageVerifiedDeploymentBundle(ctx, release)
	if err != nil {
		return err
	}
	defer os.RemoveAll(bundle.Stage)
	tools, err := checkBinaryOperatorTools(release.Manifest, true)
	if err != nil {
		return err
	}
	wranglerSelection, err := selectOrCreateWranglerProfile(
		tools.Wrangler, "", deps.cloudflareTransport, console,
	)
	if err != nil {
		return err
	}
	profile := wranglerSelection.Profile
	account := wranglerSelection.Account
	profileRevoked := false
	profileRetainedByHuman := false
	defer func() {
		if wranglerSelection.CreatedByMay && !profileRevoked && !profileRetainedByHuman {
			if bestEffortDeleteWranglerProfile(tools.Wrangler, profile) {
				profileRevoked = true
			} else {
				fmt.Fprintf(console.stderr, "SECURITY WARNING: automatic cleanup of Cloudflare profile %s failed. Revoke it now with: wrangler auth delete %s\n", profile, profile)
			}
		}
	}()
	token, err := readNamedWranglerOAuthToken(tools.Wrangler, profile)
	if err != nil {
		return err
	}
	accountSubdomain, err := fetchCloudflareAccountSubdomain(deps.cloudflareTransport, account.ID, token)
	zeroBytes(token)
	if err != nil {
		return err
	}
	identityTarget, err := readBinaryProductionTargetIdentity(account.ID, accountSubdomain, console)
	if err != nil {
		return err
	}
	onePasswordPlan, err := readOnePasswordProvisioningPlanBinary(console)
	if err != nil {
		return err
	}
	if err := assertOnePasswordProvisioningPristineBinary(onePasswordPlan, console); err != nil {
		return err
	}
	for _, worker := range []string{identityTarget.ExecutorName, identityTarget.GatewayName} {
		if err := assertWorkerAbsentBinary(tools.Wrangler, profile, worker); err != nil {
			return err
		}
	}
	writeFirstDeploymentPlan(
		console.stdout, release, bundle.Artifact, account, identityTarget,
		onePasswordPlan, profile, wranglerSelection.CreatedByMay,
	)
	confirmed, err := promptYesNo(console.stdin, console.stdout, "Deploy this OneNod plan now?", false)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("first deployment was not confirmed; no Cloudflare or 1Password production resources were created")
	}
	onePasswordCleanupActive = true
	provisioning, inventory, err := provisionFirstDeploymentOnePasswordBinary(onePasswordPlan, console)
	onePasswordInventory = inventory
	if err != nil {
		return fmt.Errorf("1Password provisioning stopped in a partial state; use the exact cleanup inventory below before retrying: %w", err)
	}
	defer func() { provisioning.ServiceAccountToken = "" }()
	material, err := newProductionInitializationMaterial(provisioning, identityTarget)
	if err != nil {
		return err
	}
	defer destroyProductionInitializationSecrets(material)
	recoveryItemIndex := onePasswordInventory.begin(
		"item", productionRecoveryItemTitle(material), "", material.RecoveryVault,
	)
	if err := storeProductionRecoveryItemBinary(material, console); err != nil {
		return err
	}
	onePasswordInventory.confirm(console.stdout, recoveryItemIndex, material.RecoveryItemID)
	if err := renderDeploymentConfigs(bundle, release.Manifest, material); err != nil {
		return err
	}
	executorVersion, gatewayVersion, err := deployFirstReleaseBundle(
		ctx, tools.Wrangler, profile, bundle, release, material, console,
	)
	if err != nil {
		return fmt.Errorf("Cloudflare deployment stopped in a partial state; exact cleanup targets are Executor %s and Gateway %s in account %s: %w",
			material.ExecutorName, material.GatewayName, material.AccountID, err)
	}
	fmt.Fprintln(console.stdout, "Waiting for the public Gateway route to report the exact deployed release before opening the one-time bootstrap URL.")
	if err := waitForGatewayReadiness(
		ctx, deps.httpClient, material.Origin, release.Manifest.ReleaseVersion,
		gatewayReadinessTimeout, gatewayReadinessPollInterval,
	); err != nil {
		return fmt.Errorf("Gateway did not become publicly ready after deployment; BOOTSTRAP_TOKEN was retained and the one-time URL was not opened: %w", err)
	}
	fmt.Fprintln(console.stdout, "The public Gateway route is ready.")
	if err := completeBootstrapCeremony(ctx, tools.Wrangler, profile, bundle, material, deps, console); err != nil {
		return err
	}
	currentGatewayVersion, err := readExactDeploymentVersion(
		tools.Wrangler, profile, bundleGatewayConfig(bundle), material.GatewayName,
	)
	if err != nil {
		return errors.New("cannot capture the exact post-bootstrap Gateway version for the deployment receipt")
	}
	gatewayVersion = currentGatewayVersion
	receipt := operatorDeploymentReceipt{
		AccountID: material.AccountID, AccountSubdomain: material.AccountSubdomain,
		Channel:           string(selectedReleaseChannel(release)),
		CloudflareProfile: profile, DeploymentArtifact: bundle.Artifact.Name,
		DeploymentArtifactSHA: bundle.Artifact.SHA256, ExecutorVersionID: executorVersion,
		ExecutorWorker: material.ExecutorName, GatewayVersionID: gatewayVersion,
		GatewayWorker: material.GatewayName, OnePasswordAccount: material.OnePasswordAccount,
		OnePasswordVaultID: material.AgentVaultID, Origin: material.Origin, RPID: material.RPID,
		ReleaseVersion: release.Manifest.ReleaseVersion, SchemaVersion: operatorReceiptSchema,
		SourceCommit: release.Manifest.Source.Commit, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		VAPIDPublicKey: material.VAPID.PublicKey,
	}
	if err := writeOperatorDeploymentReceipt(receipt); err != nil {
		return err
	}
	onePasswordCleanupActive = false
	profileRevoked, err = promptAndRevokeWranglerProfile(
		tools.Wrangler, profile, account.ID, deps.cloudflareTransport, console, true,
	)
	profileRetainedByHuman = err == nil && !profileRevoked
	receipt.CloudflareProfileRevoked = profileRevoked
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if writeErr := writeOperatorDeploymentReceipt(receipt); err == nil && writeErr != nil {
		err = writeErr
	}
	if err != nil {
		return err
	}
	installNow, installPromptErr := console.confirmDefaultYes("Install the OneNod local runtime, requester support, and managed Skill for this macOS user now?")
	var localInstallErr error
	if installNow {
		localInstallErr = installVerifiedRelease(ctx, release, material.Origin, deps, true)
	}
	if installPromptErr != nil {
		return installPromptErr
	}
	if localInstallErr != nil {
		return fmt.Errorf("remote deployment completed and Cloudflare profile handling finished, but local installation failed: %w", localInstallErr)
	}
	if profileRevoked {
		fmt.Fprintln(console.stdout, "OneNod first deployment is complete and this Mac's Cloudflare deployment authority was revoked.")
	} else {
		fmt.Fprintln(console.stdout, "OneNod first deployment is complete, but Cloudflare deployment authority remains on this Mac by explicit choice.")
	}
	return nil
}

func ensureCurrentInitializer(
	ctx context.Context,
	release *verifiedRelease,
	deps dependencies,
	selection releaseSelection,
) (bool, error) {
	expectedIdentity := release.Manifest.ReleaseVersion + "@" + release.Manifest.Source.Commit
	marker := os.Getenv(initializerReexecIdentity)
	exact, err := runningReleaseCanConsume(release.Manifest)
	if err != nil {
		return false, err
	}
	if marker != "" && (marker != expectedIdentity || !exact) {
		return false, errors.New("initializer_reexec_identity_mismatch: verified initializer did not restart as the expected exact Release")
	}
	if exact {
		return false, nil
	}
	if marker != "" {
		return false, errors.New("initializer_reexec_loop: refusing to restart the initializer more than once")
	}
	if err := installVerifiedInitializer(ctx, release, deps); err != nil {
		return false, fmt.Errorf("install current verified initializer failed: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return false, errors.New("resolve installed initializer path failed")
	}
	path := filepath.Join(home, userAgentDirectoryName, "bin", "may")
	selectionArgs := releaseSelectionArguments(selection)
	commandArgs := append([]string{"operator", "init"}, selectionArgs...)
	command := exec.CommandContext(ctx, path, commandArgs...)
	command.Dir = home
	command.Env = initializerReexecEnvironment(expectedIdentity)
	command.Stdin = deps.stdin
	command.Stdout = deps.stdout
	command.Stderr = deps.stderr
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return false, errors.New("re-executed initializer timed out")
		}
		return false, errors.New("re-executed verified initializer failed")
	}
	return true, nil
}

func initializerReexecEnvironment(expectedIdentity string) []string {
	allowed := map[string]bool{
		"HOME": true, "LANG": true, "LOGNAME": true, "PATH": true,
		"SHELL": true, "TERM": true, "TMPDIR": true, "USER": true,
		"__CF_USER_TEXT_ENCODING": true,
	}
	environment := make([]string, 0, 16)
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && (allowed[name] || strings.HasPrefix(name, "LC_")) {
			environment = append(environment, entry)
		}
	}
	return append(environment,
		"WRANGLER_LOG_SANITIZE=true",
		"WRANGLER_WRITE_LOGS=false",
		initializerReexecIdentity+"="+expectedIdentity,
	)
}

func readOnePasswordProvisioningPlanBinary(console *operatorConsole) (onePasswordProvisioningPlan, error) {
	account, err := selectOnePasswordAccount(console)
	if err != nil {
		return onePasswordProvisioningPlan{}, err
	}
	fmt.Fprintf(console.stdout, "1Password Agent Vault: %s (fixed name)\n", defaultAgentVaultName)
	recovery, err := console.readValue("Human-only Recovery Vault name", defaultRecoveryVaultName)
	if err != nil {
		return onePasswordProvisioningPlan{}, err
	}
	serviceAccount, err := console.readValue("Executor Service Account name", defaultServiceAccountName)
	if err != nil {
		return onePasswordProvisioningPlan{}, err
	}
	plan := onePasswordProvisioningPlan{
		Account: account, AgentVaultName: defaultAgentVaultName,
		RecoveryVaultName: recovery, ServiceAccountName: serviceAccount,
	}
	if err := validateOnePasswordObjectName(plan.RecoveryVaultName); err != nil {
		return onePasswordProvisioningPlan{}, fmt.Errorf("invalid Recovery Vault name: %w", err)
	}
	if err := validateOnePasswordObjectName(plan.ServiceAccountName); err != nil {
		return onePasswordProvisioningPlan{}, fmt.Errorf("invalid Service Account name: %w", err)
	}
	if plan.AgentVaultName == plan.RecoveryVaultName {
		return onePasswordProvisioningPlan{}, errors.New("Agent and Recovery Vault names must differ")
	}
	return plan, nil
}

func selectOnePasswordAccount(console *operatorConsole) (string, error) {
	output, err := runOperatorCapture("op", []string{"account", "list", "--format", "json"}, "",
		map[string]string{"OP_BIOMETRIC_UNLOCK_ENABLED": "true"}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return "", errors.New("1Password CLI cannot list local accounts")
	}
	accounts, err := supportedOnePasswordAccounts(output)
	if err != nil {
		return "", err
	}
	if len(accounts) == 1 {
		fmt.Fprintf(console.stdout, "1Password account: %s (automatically selected)\n", accounts[0])
		return accounts[0], nil
	}
	fmt.Fprintln(console.stdout, "Multiple 1Password accounts are available:")
	for index, account := range accounts {
		fmt.Fprintf(console.stdout, "  %d. %s\n", index+1, account)
	}
	value, err := console.readRequiredValue("Select the 1Password account number")
	if err != nil {
		return "", err
	}
	var selected int
	if _, err := fmt.Sscanf(value, "%d", &selected); err != nil || selected < 1 ||
		selected > len(accounts) || fmt.Sprintf("%d", selected) != value {
		return "", errors.New("1Password account selection is invalid")
	}
	return accounts[selected-1], nil
}

func supportedOnePasswordAccounts(output []byte) ([]string, error) {
	var records []struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(output, &records) != nil {
		return nil, errors.New("1Password CLI returned an invalid account list")
	}
	var accounts []string
	seen := map[string]struct{}{}
	for _, record := range records {
		account, err := normalizeOnePasswordAccountHost(record.URL)
		if err != nil {
			return nil, fmt.Errorf("1Password account URL %q is outside supported .com/.ca/.eu regions", record.URL)
		}
		if _, duplicate := seen[account]; !duplicate {
			seen[account] = struct{}{}
			accounts = append(accounts, account)
		}
	}
	sort.Strings(accounts)
	if len(accounts) == 0 {
		return nil, errors.New("no supported 1Password CLI account is configured")
	}
	return accounts, nil
}

func normalizeOnePasswordAccountHost(value string) (string, error) {
	account := strings.ToLower(strings.TrimSpace(value))
	account = strings.TrimPrefix(account, "https://")
	account = strings.TrimSuffix(account, "/")
	if !onePasswordAccountPattern.MatchString(account) {
		return "", errors.New("unsupported 1Password account host")
	}
	return account, nil
}

func validateOnePasswordObjectName(value string) error {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("name must be 1-128 printable characters without leading or trailing whitespace")
	}
	return nil
}

func checkBinaryOperatorTools(manifest releaseManifest, requireOnePassword bool) (operatorTools, error) {
	node, err := checkExternalTool("node", manifest.Requirements.Node, nil)
	if err != nil {
		return operatorTools{}, err
	}
	wrangler, err := checkExternalTool("wrangler", manifest.Requirements.Wrangler, [][]string{
		{"auth", "create", "--help"}, {"auth", "delete", "--help"}, {"auth", "list", "--help"},
		{"auth", "token", "--help"},
		{"versions", "upload", "--help"}, {"versions", "deploy", "--help"},
		{"deployments", "status", "--help"}, {"secret", "put", "--help"},
		{"triggers", "deploy", "--help"},
	})
	if err != nil {
		return operatorTools{}, err
	}
	var op string
	if requireOnePassword {
		op, err = checkExternalTool("op", manifest.Requirements.OnePasswordCLI, [][]string{
			{"vault", "create", "--help"}, {"service-account", "create", "--help"},
		})
		if err != nil {
			return operatorTools{}, err
		}
	}
	return operatorTools{Node: node, OnePassword: op, Wrangler: wrangler}, nil
}

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

func assertOnePasswordProvisioningPristineBinary(plan onePasswordProvisioningPlan, console *operatorConsole) error {
	output, err := runOperatorCapture("op", []string{
		"vault", "list", "--account", plan.Account, "--format", "json",
	}, "", map[string]string{"OP_BIOMETRIC_UNLOCK_ENABLED": "true"}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return fmt.Errorf("1Password CLI cannot list Vaults in %s", plan.Account)
	}
	var vaults []humanRecoveryVault
	if json.Unmarshal(output, &vaults) != nil {
		return errors.New("1Password CLI returned an invalid Vault list")
	}
	for _, vault := range vaults {
		if vault.Name == plan.AgentVaultName || vault.Name == plan.RecoveryVaultName {
			return fmt.Errorf("1Password Vault %q already exists; operator init requires pristine names", vault.Name)
		}
	}
	return nil
}

func assertWorkerAbsentBinary(wrangler, profile, worker string) error {
	output, err := runOperatorCapture(wrangler, []string{
		"deployments", "list", "--name", worker, "--profile", profile, "--json",
	}, "", nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err == nil {
		return fmt.Errorf("Worker %q already exists; operator init supports only first deployment", worker)
	}
	if bytes.Contains(output, []byte("[code: 10007]")) || bytes.Contains(output, []byte(`"code":10007`)) {
		return nil
	}
	return fmt.Errorf("cannot prove that Worker %q is absent", worker)
}

func writeFirstDeploymentPlan(
	output io.Writer,
	release *verifiedRelease,
	artifact releaseArtifact,
	account activeWranglerAccount,
	target productionTargetIdentity,
	onePassword onePasswordProvisioningPlan,
	profile string,
	profileCreatedByMay bool,
) {
	profileMode := "reused existing login"
	if profileCreatedByMay {
		profileMode = "created for this ceremony"
	}
	fmt.Fprintln(output, "\nOneNod first-deployment plan")
	fmt.Fprintf(output, "  Verified release: %s (%s)\n", release.Manifest.ReleaseVersion, release.Manifest.Source.Commit)
	fmt.Fprintf(output, "  Release channel: %s (artifact channel %s)\n",
		selectedReleaseChannel(release), release.Manifest.Channel)
	fmt.Fprintf(output, "  Deployment bundle: %s (%s)\n", artifact.Name, artifact.SHA256)
	fmt.Fprintf(output, "  Wrangler profile: %s (%s)\n", profile, profileMode)
	fmt.Fprintf(output, "  Cloudflare account: %s (%s)\n", account.Name, account.ID)
	fmt.Fprintf(output, "  Gateway: %s at %s\n", target.GatewayName, target.Origin)
	fmt.Fprintf(output, "  Executor: %s (private)\n", target.ExecutorName)
	fmt.Fprintf(output, "  Durable Objects: ApprovalCoordinator and OnePasswordExecutor (SQLite)\n")
	fmt.Fprintf(output, "  1Password account: %s\n", onePassword.Account)
	fmt.Fprintf(output, "  Vaults to create: %s and %s (human-only recovery)\n", onePassword.AgentVaultName, onePassword.RecoveryVaultName)
	fmt.Fprintf(output, "  Service Account: %s; read_items,write_items on %s only\n", onePassword.ServiceAccountName, onePassword.AgentVaultName)
	fmt.Fprintln(output, "  Bootstrap: one-time URL fragment, removed from the Worker after the first Passkey is registered")
	fmt.Fprintln(output, "  Final gate: offer to revoke every local Wrangler profile for this account (default yes)")
}

func provisionFirstDeploymentOnePasswordBinary(
	plan onePasswordProvisioningPlan,
	console *operatorConsole,
) (onePasswordProvisioning, onePasswordProvisioningInventory, error) {
	var inventory onePasswordProvisioningInventory
	recoveryVaultIndex := inventory.begin("vault", plan.RecoveryVaultName, "", "")
	recoveryVault, err := createOnePasswordVaultBinary(plan.Account, plan.RecoveryVaultName,
		"Human-only recovery material for OneNod. Never grant Service Account access.", console)
	if err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	inventory.confirm(console.stdout, recoveryVaultIndex, recoveryVault.ID)
	agentVaultIndex := inventory.begin("vault", plan.AgentVaultName, "", "")
	agentVault, err := createOnePasswordVaultBinary(plan.Account, plan.AgentVaultName,
		"Credentials made available to Agents only through the human approval Gateway.", console)
	if err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	inventory.confirm(console.stdout, agentVaultIndex, agentVault.ID)
	serviceAccountIndex := inventory.begin("service_account", plan.ServiceAccountName, "", agentVault.ID)
	token, err := createAgentServiceAccountTokenBinary(plan.Account, plan.ServiceAccountName, agentVault.ID, console)
	if err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	inventory.confirm(console.stdout, serviceAccountIndex, "not returned by op --raw")
	template, err := serviceAccountTokenItemTemplate(plan.ServiceAccountName, agentVault, token)
	if err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	defer zeroBytes(template)
	tokenItemIndex := inventory.begin("item", serviceAccountTokenItemTitle, "", recoveryVault.ID)
	itemID, err := createOnePasswordItemBinary(plan.Account, recoveryVault.ID, template, console)
	if err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	inventory.confirm(console.stdout, tokenItemIndex, itemID)
	if err := verifyAgentServiceAccountScopeBinary([]byte(token), agentVault); err != nil {
		return onePasswordProvisioning{}, inventory, err
	}
	return onePasswordProvisioning{
		Account: plan.Account, AgentVault: agentVault, RecoveryVault: recoveryVault,
		ServiceAccountName: plan.ServiceAccountName, ServiceAccountToken: token,
		ServiceAccountTokenItem: itemID,
	}, inventory, nil
}

func (inventory *onePasswordProvisioningInventory) begin(resourceType, name, id, parentID string) int {
	resource := createdOnePasswordResource{
		Type: resourceType, Name: name, ID: id, ParentID: parentID, Status: "outcome_unknown",
	}
	inventory.Resources = append(inventory.Resources, resource)
	return len(inventory.Resources) - 1
}

func (inventory *onePasswordProvisioningInventory) confirm(output io.Writer, index int, id string) {
	if index < 0 || index >= len(inventory.Resources) {
		return
	}
	inventory.Resources[index].ID = id
	inventory.Resources[index].Status = "confirmed"
	resource := inventory.Resources[index]
	fmt.Fprintf(output, "Created 1Password %s: %s (ID: %s)\n", resource.Type, resource.Name, resource.ID)
}

func writeOnePasswordCleanupInventory(output io.Writer, inventory onePasswordProvisioningInventory) {
	fmt.Fprintln(output, "1Password cleanup required before retrying (no resources were deleted automatically):")
	for _, resource := range inventory.Resources {
		id := resource.ID
		if id == "" {
			id = "unknown"
		}
		parent := ""
		if resource.ParentID != "" {
			parent = ", vault ID: " + resource.ParentID
		}
		fmt.Fprintf(output, "  - %s: %s (ID: %s%s; status: %s)\n",
			resource.Type, resource.Name, id, parent, resource.Status)
	}
}

func createOnePasswordVaultBinary(account, name, description string, console *operatorConsole) (humanRecoveryVault, error) {
	output, err := runOperatorCapture("op", []string{
		"vault", "create", name, "--description", description,
		"--account", account, "--format", "json",
	}, "", map[string]string{"OP_BIOMETRIC_UNLOCK_ENABLED": "true"}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return humanRecoveryVault{}, fmt.Errorf("create 1Password Vault %q failed", name)
	}
	var vault humanRecoveryVault
	if json.Unmarshal(output, &vault) != nil || !onePasswordVaultIDPattern.MatchString(vault.ID) || vault.Name != name {
		return humanRecoveryVault{}, fmt.Errorf("1Password returned invalid metadata for created Vault %q", name)
	}
	return vault, nil
}

func createAgentServiceAccountTokenBinary(account, name, vaultID string, console *operatorConsole) (string, error) {
	output, err := runOperatorCapture("op", agentServiceAccountCreateArguments(account, name, vaultID), "",
		map[string]string{"OP_BIOMETRIC_UNLOCK_ENABLED": "true"}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return "", errors.New("create Agent-only 1Password Service Account failed")
	}
	token := strings.TrimSpace(string(output))
	if !validServiceAccountToken(token) {
		return "", errors.New("1Password did not return a valid Service Account token; revoke the created Service Account immediately")
	}
	return token, nil
}

func createOnePasswordItemBinary(account, vault string, template []byte, console *operatorConsole) (string, error) {
	output, err := runOperatorCapture("op", []string{
		"item", "create", "--account", account, "--vault", vault, "--format", "json", "-",
	}, "", map[string]string{"OP_BIOMETRIC_UNLOCK_ENABLED": "true"}, operatorCommandTimeout, template)
	defer zeroBytes(output)
	if err != nil {
		return "", errors.New("create 1Password Recovery item failed")
	}
	var created struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(output, &created) != nil || created.ID == "" {
		return "", errors.New("1Password did not return a Recovery item ID")
	}
	return created.ID, nil
}

func verifyAgentServiceAccountScopeBinary(token []byte, agentVault humanRecoveryVault) error {
	output, err := runOperatorCapture("op", []string{"vault", "list", "--format", "json"}, "",
		map[string]string{"OP_SERVICE_ACCOUNT_TOKEN": string(token)}, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return errors.New("created Service Account cannot list its assigned Agent Vault")
	}
	var vaults []humanRecoveryVault
	if json.Unmarshal(output, &vaults) != nil || len(vaults) != 1 ||
		vaults[0].ID != agentVault.ID || vaults[0].Name != agentVault.Name {
		return errors.New("created Service Account scope is not exactly the Agent Vault; revoke it immediately")
	}
	return nil
}

func storeProductionRecoveryItemBinary(material *productionInitializationMaterial, console *operatorConsole) error {
	template, err := productionRecoveryItemTemplate(material)
	if err != nil {
		return err
	}
	defer zeroBytes(template)
	itemID, err := createOnePasswordItemBinary(material.OnePasswordAccount, material.RecoveryVault, template, console)
	if err != nil {
		return err
	}
	material.RecoveryItemID = itemID
	return nil
}

func deployFirstReleaseBundle(
	ctx context.Context,
	wrangler, profile string,
	bundle *stagedDeploymentBundle,
	release *verifiedRelease,
	material *productionInitializationMaterial,
	console *operatorConsole,
) (string, string, error) {
	_ = ctx
	executorConfig := bundleExecutorConfig(bundle)
	gatewayConfig := bundleGatewayConfig(bundle)
	if _, err := deployPrivateWorkerScaffold(wrangler, profile, executorConfig,
		material.ExecutorName, "OneNod "+release.Manifest.ReleaseVersion+" executor scaffold", console); err != nil {
		return "", "", err
	}
	for _, secret := range []struct{ name, value string }{
		{name: "EXECUTOR_AUTH_TOKEN", value: material.ExecutorAuthToken},
		{name: "OP_SERVICE_ACCOUNT_TOKEN", value: material.OnePasswordServiceAccountToken},
	} {
		if err := putWorkerSecret(wrangler, profile, filepath.Dir(executorConfig), executorConfig, material.ExecutorName, secret.name, secret.value, console); err != nil {
			return "", "", err
		}
	}
	executorVersion, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, "OneNod "+release.Manifest.ReleaseVersion+" executor", console)
	if err != nil {
		return "", "", err
	}
	if err := inspectWorkerVersionBindings(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, executorVersion, []string{"EXECUTOR_AUTH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"}); err != nil {
		return "", "", err
	}
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, executorVersion, "OneNod executor", console); err != nil {
		return "", "", err
	}
	if err := deployWorkerTriggers(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, console); err != nil {
		return "", "", err
	}

	if _, err := deployPrivateWorkerScaffold(wrangler, profile, gatewayConfig,
		material.GatewayName, "OneNod "+release.Manifest.ReleaseVersion+" gateway scaffold", console); err != nil {
		return "", "", err
	}
	for _, secret := range []struct{ name, value string }{
		{name: "EXECUTOR_AUTH_TOKEN", value: material.ExecutorAuthToken},
		{name: "GATEWAY_MASTER_KEY", value: material.GatewayMasterKey},
		{name: "VAPID_PRIVATE_KEY", value: material.VAPID.PrivateKey},
		{name: "BOOTSTRAP_TOKEN", value: material.BootstrapToken},
	} {
		if err := putWorkerSecret(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig, material.GatewayName, secret.name, secret.value, console); err != nil {
			return "", "", err
		}
	}
	gatewayVersion, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, "OneNod "+release.Manifest.ReleaseVersion+" gateway", console)
	if err != nil {
		return "", "", err
	}
	if err := inspectWorkerVersionBindings(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, gatewayVersion, []string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY", "BOOTSTRAP_TOKEN"}); err != nil {
		return "", "", err
	}
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, gatewayVersion, "OneNod gateway", console); err != nil {
		return "", "", err
	}
	if err := deployWorkerTriggers(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, console); err != nil {
		return "", "", err
	}
	return executorVersion, gatewayVersion, nil
}

// Wrangler versions upload cannot create a Worker. The first deploy therefore
// uses a derived config with every public trigger disabled; the real config is
// not applied until the secret-bearing version has been inspected.
func deployPrivateWorkerScaffold(
	wrangler, profile, config, worker, message string,
	console *operatorConsole,
) (string, error) {
	scaffoldConfig, err := stagePrivateWorkerConfig(config)
	if err != nil {
		return "", err
	}
	defer os.Remove(scaffoldConfig)

	output, commandErr := runWranglerCapture(wrangler, profile, filepath.Dir(config), []string{
		"deploy", "--config", scaffoldConfig, "--name", worker,
		"--strict", "--message", message,
	}, nil, operatorCommandTimeout)
	defer zeroBytes(output)
	match := workerVersionIDPattern.FindSubmatch(output)
	requested := ""
	if len(match) == 2 {
		requested = strings.ToLower(string(match[1]))
	}
	if commandErr != nil {
		writeWranglerFailureDiagnostic(console.stderr, output)
	}

	observed, absent, inspectErr := readWorkerDeploymentState(
		wrangler, profile, scaffoldConfig, worker,
	)
	if inspectErr != nil {
		return "", &remoteOutcomeUnknownError{
			ObservedVersion: requested, Operation: "create private Worker scaffold", Worker: worker,
		}
	}
	if absent {
		if commandErr != nil {
			return "", fmt.Errorf("create private Worker scaffold for %s failed; Cloudflare confirms that the Worker is absent", worker)
		}
		return "", &remoteOutcomeUnknownError{
			ObservedVersion: requested, Operation: "create private Worker scaffold", Worker: worker,
		}
	}
	if requested != "" && requested != observed {
		return "", &observedDeploymentError{
			ObservedVersion: observed, RequestedVersion: requested, Worker: worker,
		}
	}
	if commandErr != nil {
		if requested == "" {
			return "", &remoteOutcomeUnknownError{
				ObservedVersion: observed, Operation: "create private Worker scaffold", Worker: worker,
			}
		}
		fmt.Fprintf(console.stderr,
			"Wrangler reported an error for %s, but authoritative deployment status confirms private scaffold %s at 100%%. Continuing without retry.\n",
			worker, observed,
		)
	} else {
		fmt.Fprint(console.stdout, string(output))
	}
	return observed, nil
}

func stagePrivateWorkerConfig(config string) (string, error) {
	encoded, exists, err := readOptionalRegularFile(config, 4<<20)
	if err != nil || !exists {
		return "", errors.New("read Worker scaffold configuration failed")
	}
	var document map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if decoder.Decode(&document) != nil || ensureDecoderEOF(decoder) != nil || document == nil {
		return "", errors.New("Worker scaffold configuration is not strict JSON")
	}
	document["workers_dev"] = json.RawMessage("false")
	document["preview_urls"] = json.RawMessage("false")
	delete(document, "route")
	delete(document, "routes")
	delete(document, "triggers")
	privateConfig, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return "", errors.New("encode private Worker scaffold configuration failed")
	}
	privateConfig = append(privateConfig, '\n')
	staged, err := os.CreateTemp(filepath.Dir(config), ".onenod-private-scaffold-*.jsonc")
	if err != nil {
		return "", errors.New("stage private Worker scaffold configuration failed")
	}
	path := staged.Name()
	remove := true
	defer func() {
		if remove {
			_ = staged.Close()
			_ = os.Remove(path)
		}
	}()
	if staged.Chmod(0o600) != nil {
		return "", errors.New("secure private Worker scaffold configuration failed")
	}
	if _, err := staged.Write(privateConfig); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return "", errors.New("write private Worker scaffold configuration failed")
	}
	remove = false
	return path, nil
}

func bundleExecutorConfig(bundle *stagedDeploymentBundle) string {
	return filepath.Join(bundle.Root, filepath.FromSlash(bundle.Descriptor.Executor.Config))
}

func bundleGatewayConfig(bundle *stagedDeploymentBundle) string {
	return filepath.Join(bundle.Root, filepath.FromSlash(bundle.Descriptor.Gateway.Config))
}

func uploadWorkerVersion(
	wrangler, profile, cwd, config, worker, message string,
	console *operatorConsole,
) (string, error) {
	output, err := runWranglerCapture(wrangler, profile, cwd, []string{
		"versions", "upload", "--config", config, "--name", worker,
		"--strict", "--message", message,
	}, nil, operatorCommandTimeout)
	defer zeroBytes(output)
	match := workerVersionIDPattern.FindSubmatch(output)
	if err != nil {
		writeWranglerFailureDiagnostic(console.stderr, output)
		observed := ""
		if len(match) == 2 {
			observed = strings.ToLower(string(match[1]))
		}
		return "", &remoteOutcomeUnknownError{
			ObservedVersion: observed, Operation: "upload Worker version", Worker: worker,
		}
	}
	fmt.Fprint(console.stdout, string(output))
	if len(match) != 2 {
		return "", &remoteOutcomeUnknownError{
			Operation: "parse uploaded Worker version", Worker: worker,
		}
	}
	return strings.ToLower(string(match[1])), nil
}

func writeWranglerFailureDiagnostic(output io.Writer, commandOutput []byte) {
	plain := ansiEscapePattern.ReplaceAll(commandOutput, nil)
	defer zeroBytes(plain)
	diagnostic := strings.TrimSpace(strings.ToValidUTF8(string(plain), ""))
	const maxDiagnosticBytes = 2048
	if len(diagnostic) > maxDiagnosticBytes {
		diagnostic = "…" + strings.ToValidUTF8(diagnostic[len(diagnostic)-maxDiagnosticBytes:], "")
	}
	if diagnostic != "" {
		fmt.Fprintf(output, "Wrangler diagnostic (the operation will not be retried):\n%s\n", diagnostic)
	}
}

func deployWorkerVersion(
	wrangler, profile, cwd, config, worker, versionID, message string,
	console *operatorConsole,
) error {
	if !uuidPattern.MatchString(versionID) {
		return errors.New("refusing to deploy an invalid Worker Version ID")
	}
	err := runWranglerStreaming(wrangler, profile, cwd, []string{
		"versions", "deploy", versionID + "@100", "--config", config,
		"--name", worker, "--message", message, "-y",
	}, nil, console, operatorCommandTimeout)
	observed, inspectErr := readExactDeploymentVersion(wrangler, profile, config, worker)
	if inspectErr != nil {
		return &remoteOutcomeUnknownError{Operation: "deploy Worker version", Worker: worker}
	}
	if observed == versionID {
		if err != nil {
			fmt.Fprintf(console.stderr,
				"Wrangler reported an error for %s, but authoritative deployment status confirms %s at 100%%. Continuing without retry.\n",
				worker, versionID,
			)
		}
		return nil
	}
	return &observedDeploymentError{
		ObservedVersion: observed, RequestedVersion: versionID, Worker: worker,
	}
}

func deployWorkerTriggers(
	wrangler, profile, cwd, config, worker string,
	console *operatorConsole,
) error {
	if err := runWranglerStreaming(wrangler, profile, cwd, []string{
		"triggers", "deploy", "--config", config, "--name", worker,
	}, nil, console, operatorCommandTimeout); err != nil {
		return &remoteOutcomeUnknownError{Operation: "apply Worker triggers", Worker: worker}
	}
	return nil
}

func putWorkerSecret(
	wrangler, profile, cwd, config, worker, name, secret string,
	console *operatorConsole,
) error {
	if secret == "" || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("refusing to write an invalid Worker secret")
	}
	input := append([]byte(secret), '\n')
	defer zeroBytes(input)
	if err := runWranglerStreaming(wrangler, profile, cwd, []string{
		"secret", "put", name, "--config", config, "--name", worker,
	}, input, console, operatorCommandTimeout); err != nil {
		return fmt.Errorf("write Worker secret %s for %s failed", name, worker)
	}
	return nil
}

func inspectWorkerVersionBindings(
	wrangler, profile, cwd, config, worker, versionID string,
	requiredSecrets []string,
) error {
	return inspectWorkerVersionSecretBindings(
		wrangler, profile, cwd, config, worker, versionID, requiredSecrets, nil,
	)
}

func inspectWorkerVersionSecretBindings(
	wrangler, profile, cwd, config, worker, versionID string,
	requiredSecrets, forbiddenSecrets []string,
) error {
	output, err := runWranglerCapture(wrangler, profile, cwd, []string{
		"versions", "view", versionID, "--config", config, "--name", worker, "--json",
	}, nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return fmt.Errorf("inspect uploaded Worker version %s failed", worker)
	}
	var view struct {
		ID        string `json:"id"`
		Resources struct {
			Bindings []struct {
				Name string `json:"name"`
				Type string `json:"type"`
			} `json:"bindings"`
		} `json:"resources"`
	}
	if json.Unmarshal(output, &view) != nil || view.ID != versionID {
		return fmt.Errorf("Wrangler returned invalid version metadata for %s", worker)
	}
	present := map[string]string{}
	for _, binding := range view.Resources.Bindings {
		if _, duplicate := present[binding.Name]; duplicate {
			return fmt.Errorf("uploaded Worker %s contains duplicate binding %s", worker, binding.Name)
		}
		present[binding.Name] = binding.Type
	}
	for _, name := range requiredSecrets {
		if present[name] != "secret_text" {
			return fmt.Errorf("uploaded Worker %s is missing secret binding %s", worker, name)
		}
	}
	for _, name := range forbiddenSecrets {
		if present[name] != "" {
			return fmt.Errorf("uploaded Worker %s still contains forbidden secret binding %s", worker, name)
		}
	}
	return nil
}

func readExactDeploymentVersion(wrangler, profile, config, worker string) (string, error) {
	version, absent, err := readWorkerDeploymentState(wrangler, profile, config, worker)
	if err != nil {
		return "", err
	}
	if absent {
		return "", fmt.Errorf("Worker %s does not exist", worker)
	}
	return version, nil
}

func readWorkerDeploymentState(wrangler, profile, config, worker string) (string, bool, error) {
	output, err := runWranglerCapture(wrangler, profile, filepath.Dir(config), []string{
		"deployments", "status", "--config", config, "--name", worker, "--json",
	}, nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		if bytes.Contains(output, []byte("[code: 10007]")) || bytes.Contains(output, []byte(`"code":10007`)) {
			return "", true, nil
		}
		return "", false, fmt.Errorf("read deployment status for %s failed", worker)
	}
	var status struct {
		Versions []struct {
			VersionID  string  `json:"version_id"`
			Percentage float64 `json:"percentage"`
		} `json:"versions"`
	}
	if json.Unmarshal(output, &status) != nil || len(status.Versions) != 1 ||
		status.Versions[0].Percentage != 100 || !uuidPattern.MatchString(status.Versions[0].VersionID) {
		return "", false, fmt.Errorf("deployment %s is not an exact single-version 100%% state", worker)
	}
	return status.Versions[0].VersionID, false, nil
}

func completeBootstrapCeremony(
	ctx context.Context,
	wrangler, profile string,
	bundle *stagedDeploymentBundle,
	material *productionInitializationMaterial,
	deps dependencies,
	console *operatorConsole,
) error {
	fragment := base64.RawURLEncoding.EncodeToString([]byte(material.BootstrapToken))
	bootstrapURL := material.Origin + "/#bootstrap=" + fragment
	fmt.Fprintln(console.stdout, "\nOpen this one-time bootstrap URL in the browser where you will register the first Passkey.")
	fmt.Fprintln(console.stdout, "Do not share it. The fragment is removed from browser history immediately and the Worker secret is deleted after initialization.")
	fmt.Fprintln(console.stdout, bootstrapURL)
	if err := openSensitiveBootstrapURL([]byte(bootstrapURL)); err != nil {
		fmt.Fprintln(console.stderr, "The default browser could not be opened automatically; open the URL printed above manually.")
	}
	fmt.Fprintf(console.stdout, "Waiting up to %s for the first owner Passkey registration. Keep this terminal open; no confirmation keystroke is required.\n", bootstrapCompletionTimeout)
	if err := waitForRemoteInitialization(
		ctx, deps.httpClient, material.Origin,
		bootstrapCompletionTimeout, bootstrapPollInterval,
	); err != nil {
		return fmt.Errorf("Gateway did not report an initialized owner identity before the wait ended; BOOTSTRAP_TOKEN was retained: %w", err)
	}
	fmt.Fprintln(console.stdout, "Owner identity established; deleting the one-time bootstrap Worker Secret.")
	config := bundleGatewayConfig(bundle)
	if err := runWranglerStreaming(wrangler, profile, filepath.Dir(config), []string{
		"secret", "delete", "BOOTSTRAP_TOKEN", "--config", config,
		"--name", material.GatewayName,
	}, []byte("y\n"), console, operatorCommandTimeout); err != nil {
		return errors.New("delete BOOTSTRAP_TOKEN failed after initialization; revoke it before resuming Agents")
	}
	material.BootstrapToken = ""
	currentVersion, err := readExactDeploymentVersion(wrangler, profile, config, material.GatewayName)
	if err != nil {
		return errors.New("cannot prove the exact Gateway deployment after BOOTSTRAP_TOKEN deletion")
	}
	if err := inspectWorkerVersionSecretBindings(
		wrangler, profile, filepath.Dir(config), config, material.GatewayName, currentVersion,
		[]string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"},
		[]string{"BOOTSTRAP_TOKEN"},
	); err != nil {
		return errors.New("cannot prove BOOTSTRAP_TOKEN absence after initialization")
	}
	if initialized, err := readRemoteInitializationState(deps.httpClient, material.Origin); err != nil || !initialized {
		return errors.New("Gateway initialization did not remain healthy after BOOTSTRAP_TOKEN deletion")
	}
	select {
	case <-ctx.Done():
		return errors.New("bootstrap ceremony timed out")
	default:
		return nil
	}
}

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

func operatorReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for operator receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "operator", "deployment.json"), nil
}

func writeOperatorDeploymentReceipt(receipt operatorDeploymentReceipt) error {
	path, err := operatorReceiptPath()
	if err != nil {
		return err
	}
	if err := ensurePrivateInstallDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	receipt.SchemaVersion = operatorReceiptSchema
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	receipt.Channel = string(channel)
	return writeAtomicPrivateJSON(path, receipt)
}

func readOperatorDeploymentReceipt() (*operatorDeploymentReceipt, error) {
	path, err := operatorReceiptPath()
	if err != nil {
		return nil, err
	}
	var receipt operatorDeploymentReceipt
	if err := readStrictPrivateJSON(path, &receipt); err != nil {
		return nil, err
	}
	if receipt.SchemaVersion != operatorReceiptSchema || !cloudflareAccountIDPattern.MatchString(receipt.AccountID) ||
		!dnsLabelPattern.MatchString(receipt.AccountSubdomain) || !validProductVersion(receipt.ReleaseVersion) ||
		!commitPattern.MatchString(receipt.SourceCommit) || !digestPattern.MatchString(receipt.DeploymentArtifactSHA) ||
		!uuidPattern.MatchString(receipt.ExecutorVersionID) || !uuidPattern.MatchString(receipt.GatewayVersionID) ||
		!onePasswordVaultIDPattern.MatchString(receipt.OnePasswordVaultID) {
		return nil, errors.New("operator deployment receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return nil, errors.New("operator deployment receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	if _, err := parseGatewayOrigin(receipt.Origin); err != nil || receipt.RPID != strings.TrimPrefix(receipt.Origin, "https://") {
		return nil, errors.New("operator deployment receipt has an invalid immutable Origin")
	}
	return &receipt, nil
}

func writeAtomicPrivateJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode private receipt failed")
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	staged, err := os.CreateTemp(directory, ".receipt-")
	if err != nil {
		return errors.New("stage private receipt failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if staged.Chmod(0o600) != nil {
		staged.Close()
		return errors.New("secure private receipt failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write private receipt failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("activate private receipt failed")
	}
	return nil
}

func readStrictPrivateJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return errors.New("private receipt is missing, unsafe, or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read private receipt failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("private receipt JSON is invalid")
	}
	return nil
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

func runBinaryOperatorUpdate(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("operator update", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may operator update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]")
	}
	if err := assertNoCloudflareCredentialEnvironment(); err != nil {
		return err
	}
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil {
		return err
	}
	currentChannel := releaseChannel(receipt.Channel)
	selection, err := releaseSelectionFromFlags(*channelValue, *versionValue, currentChannel)
	if err != nil {
		return err
	}
	channel := selection.Channel
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	release, err := resolveSelectedRelease(ctx, releaseSourceFor(deps), selection)
	if err != nil {
		return err
	}
	if err := requireSupportedReleaseHost(release.Manifest, deps); err != nil {
		return err
	}
	if compareProductVersions(release.Manifest.ReleaseVersion, receipt.ReleaseVersion) < 0 {
		if awaitingCompatibleRelease(
			receipt.ReleaseVersion, currentChannel,
			release.Manifest.ReleaseVersion, channel,
		) {
			writeAwaitingCompatibleRelease(
				deps.stdout, receipt.ReleaseVersion, currentChannel,
				release.Manifest.ReleaseVersion, channel,
			)
			return nil
		}
		return errors.New("anti_rollback: latest official release is older than the deployed receipt")
	}
	if _, err := runningReleaseCanConsume(release.Manifest); err != nil {
		return err
	}
	localReceipt, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	helperPlan := buildKeychainHelperUpdatePlan(release, localReceipt)
	if err := confirmHigherRiskChannel(
		deps.stdin, deps.stdout, currentChannel, channel, "Operator updates",
	); err != nil {
		return err
	}
	if release.Manifest.ReleaseVersion == receipt.ReleaseVersion {
		if release.Manifest.Source.Commit != receipt.SourceCommit ||
			receipt.DeploymentArtifactSHA != artifactDigestByName(release.Manifest, receipt.DeploymentArtifact) {
			return errors.New("same_version_identity_mismatch: deployed receipt differs from the signed release")
		}
		remote, complete := readRemoteRuntimeVersion(receipt.Origin, deps.httpClient)
		if complete && remote.GatewayVersion == receipt.ReleaseVersion && remote.ExecutorVersion == receipt.ReleaseVersion && remote.PwaVersion == receipt.ReleaseVersion {
			if localInstallExactlyMatchesRelease(release, receipt.Origin) {
				if receipt.Channel != string(selectedReleaseChannel(release)) {
					receipt.Channel = string(selectedReleaseChannel(release))
					receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
					if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
						return err
					}
				}
				fmt.Fprintf(deps.stdout, "OneNod remote deployment and this Mac are already on %s.\n", receipt.ReleaseVersion)
				return nil
			}
			fmt.Fprintf(deps.stdout, "OneNod remote deployment is already on %s; reconciling this Mac without Cloudflare authorization.\n", receipt.ReleaseVersion)
			writeKeychainHelperUpdatePlan(deps.stdout, helperPlan)
			if helperPlan.Replace {
				confirmed, confirmErr := promptYesNo(deps.stdin, deps.stdout, "Update the OneNod Keychain helper while reconciling this Mac?", false)
				if confirmErr != nil {
					return confirmErr
				}
				if !confirmed {
					return errors.New("local Keychain helper reconciliation was not approved; Cloudflare was not accessed")
				}
			}
			if err := installVerifiedRelease(ctx, release, receipt.Origin, deps, helperPlan.Replace); err != nil {
				return fmt.Errorf("remote deployment is current but local reconciliation failed: %w", err)
			}
			receipt.Channel = string(selectedReleaseChannel(release))
			receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
				return err
			}
			return nil
		}
	}
	bundle, err := stageVerifiedDeploymentBundle(ctx, release)
	if err != nil {
		return err
	}
	defer os.RemoveAll(bundle.Stage)
	tools, err := checkBinaryOperatorTools(release.Manifest, false)
	if err != nil {
		return err
	}
	console := &operatorConsole{stdin: deps.stdin, stdout: deps.stdout, stderr: deps.stderr}
	wranglerSelection, err := selectOrCreateWranglerProfile(
		tools.Wrangler, receipt.AccountID, deps.cloudflareTransport, console,
	)
	if err != nil {
		return err
	}
	profile := wranglerSelection.Profile
	account := wranglerSelection.Account
	profileRevoked := false
	profileRetainedByHuman := false
	defer func() {
		if wranglerSelection.CreatedByMay && !profileRevoked && !profileRetainedByHuman {
			if bestEffortDeleteWranglerProfile(tools.Wrangler, profile) {
				profileRevoked = true
			} else {
				fmt.Fprintf(console.stderr, "SECURITY WARNING: automatic cleanup of Cloudflare profile %s failed. Revoke it now with: wrangler auth delete %s\n", profile, profile)
			}
		}
	}()
	token, err := readNamedWranglerOAuthToken(tools.Wrangler, profile)
	if err != nil {
		return err
	}
	subdomain, err := fetchCloudflareAccountSubdomain(deps.cloudflareTransport, account.ID, token)
	zeroBytes(token)
	if err != nil || subdomain != receipt.AccountSubdomain {
		return errors.New("Cloudflare workers.dev subdomain differs from the immutable deployment receipt")
	}
	material := &productionInitializationMaterial{
		AccountID: receipt.AccountID, AccountSubdomain: receipt.AccountSubdomain,
		ExecutorName: receipt.ExecutorWorker, GatewayName: receipt.GatewayWorker,
		OnePasswordAccount: receipt.OnePasswordAccount, AgentVaultID: receipt.OnePasswordVaultID,
		Origin: receipt.Origin, RPID: receipt.RPID, VAPID: vapidCredential{PublicKey: receipt.VAPIDPublicKey},
	}
	if err := renderDeploymentConfigs(bundle, release.Manifest, material); err != nil {
		return err
	}
	executorBefore, err := readExactDeploymentVersion(tools.Wrangler, profile, bundleExecutorConfig(bundle), receipt.ExecutorWorker)
	if err != nil {
		return err
	}
	gatewayBefore, err := readExactDeploymentVersion(tools.Wrangler, profile, bundleGatewayConfig(bundle), receipt.GatewayWorker)
	if err != nil {
		return err
	}
	transaction, transactionPath, resuming, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, bundle.Artifact, executorBefore, gatewayBefore,
	)
	if err != nil {
		return err
	}
	if !resuming {
		if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
			return err
		}
	}
	if resuming {
		if err := inspectWorkerVersionBindings(
			tools.Wrangler, profile, filepath.Dir(bundleExecutorConfig(bundle)), bundleExecutorConfig(bundle),
			receipt.ExecutorWorker, transaction.ExecutorAfter,
			[]string{"EXECUTOR_AUTH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"},
		); err != nil {
			return fmt.Errorf("cannot reconcile the recorded Executor version before resuming: %w", err)
		}
		if transaction.GatewayAfter != "" {
			if err := inspectWorkerVersionBindings(
				tools.Wrangler, profile, filepath.Dir(bundleGatewayConfig(bundle)), bundleGatewayConfig(bundle),
				receipt.GatewayWorker, transaction.GatewayAfter,
				[]string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"},
			); err != nil {
				return fmt.Errorf("cannot reconcile the recorded Gateway version before resuming: %w", err)
			}
		}
	}
	fmt.Fprintln(console.stdout, "\nOneNod operator update plan")
	fmt.Fprintf(console.stdout, "  Cloudflare account: %s (%s)\n", account.Name, account.ID)
	fmt.Fprintf(console.stdout, "  Origin / RP ID: %s / %s (unchanged)\n", receipt.Origin, receipt.RPID)
	fmt.Fprintf(console.stdout, "  Release: %s -> %s\n", receipt.ReleaseVersion, release.Manifest.ReleaseVersion)
	fmt.Fprintf(console.stdout, "  Channel: %s -> %s (artifact channel %s)\n",
		currentChannel, channel, release.Manifest.Channel)
	fmt.Fprintf(console.stdout, "  Executor baseline: %s\n  Gateway baseline: %s\n", executorBefore, gatewayBefore)
	fmt.Fprintf(console.stdout, "  Bundle: %s (%s)\n", bundle.Artifact.Name, bundle.Artifact.SHA256)
	fmt.Fprintf(console.stdout, "  Promotion order: %s; rollback safe: %t\n", strings.Join(release.Manifest.Upgrade.Order, " -> "), release.Manifest.Upgrade.RemoteRollbackSafe)
	if resuming {
		fmt.Fprintf(console.stdout, "  Resume transaction: %s (%s)\n", transaction.ID, transaction.Phase)
		fmt.Fprintf(console.stdout, "  Reuse verified Executor version: %s\n", transaction.ExecutorAfter)
		if transaction.GatewayAfter == "" {
			fmt.Fprintln(console.stdout, "  Gateway retry: prior upload produced no version; upload once after confirmation")
		} else {
			fmt.Fprintf(console.stdout, "  Reuse verified Gateway version: %s\n", transaction.GatewayAfter)
		}
	}
	writeKeychainHelperUpdatePlan(console.stdout, helperPlan)
	confirmed, err := promptYesNo(console.stdin, console.stdout, "Deploy this OneNod update now?", false)
	if err != nil || !confirmed {
		if !resuming {
			transaction.Outcome = "not_confirmed"
			transaction.Phase = "planned"
			_ = writeAtomicPrivateJSON(transactionPath, transaction)
		}
		if err != nil {
			return err
		}
		return errors.New("operator update was not confirmed; production traffic was unchanged")
	}
	executorAfter, gatewayAfter, deployErr := deployVerifiedUpdate(
		ctx, deps.httpClient,
		tools.Wrangler, profile, bundle, release, receipt, executorBefore, gatewayBefore,
		console, transaction, transactionPath, resuming,
	)
	if deployErr != nil {
		return deployErr
	}
	transaction.ExecutorAfter = executorAfter
	transaction.GatewayAfter = gatewayAfter
	transaction.Phase = "remote_verified"
	transaction.Outcome = "remote_complete"
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	profileRevoked, err = promptAndRevokeWranglerProfile(
		tools.Wrangler, profile, account.ID, deps.cloudflareTransport, console, true,
	)
	profileRetainedByHuman = err == nil && !profileRevoked
	transaction.ProfileRevoked = profileRevoked
	if !profileRevoked {
		transaction.Outcome = "deployment_authority_retained"
	} else {
		transaction.Phase = "cloudflare_revoked"
	}
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	if err != nil {
		return err
	}
	receipt.ReleaseVersion = release.Manifest.ReleaseVersion
	receipt.Channel = string(selectedReleaseChannel(release))
	receipt.SourceCommit = release.Manifest.Source.Commit
	receipt.DeploymentArtifact = bundle.Artifact.Name
	receipt.DeploymentArtifactSHA = bundle.Artifact.SHA256
	receipt.ExecutorVersionID = executorAfter
	receipt.GatewayVersionID = gatewayAfter
	receipt.CloudflareProfile = profile
	receipt.CloudflareProfileRevoked = profileRevoked
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
		return err
	}
	if err := installVerifiedRelease(ctx, release, receipt.Origin, deps, helperPlan.Replace); err != nil {
		transaction.Outcome = "remote_complete_local_pending"
		_ = writeAtomicPrivateJSON(transactionPath, transaction)
		return err
	}
	transaction.Phase = "complete"
	if profileRevoked {
		transaction.Outcome = "complete"
	} else {
		transaction.Outcome = "deployment_authority_retained"
	}
	return writeAtomicPrivateJSON(transactionPath, transaction)
}

func localInstallExactlyMatchesRelease(release *verifiedRelease, origin string) bool {
	receipt, found, err := readLocalInstallReceipt()
	if err != nil || !found || receipt.Origin != origin ||
		receipt.Channel != string(selectedReleaseChannel(release)) ||
		receipt.ReleaseVersion != release.Manifest.ReleaseVersion ||
		validateReceiptReleaseIdentity(receipt, release.Manifest) != nil ||
		validateInstalledReceiptState(receipt) != nil {
		return false
	}
	helper, err := inspectInstalledKeychainHelper()
	return err == nil && helperMatchesRelease(release, receipt, helper)
}

func accountByID(accounts []activeWranglerAccount, id string) (activeWranglerAccount, bool) {
	var matched activeWranglerAccount
	matches := 0
	for _, account := range accounts {
		if account.ID == id {
			matched = account
			matches++
		}
	}
	return matched, matches == 1
}

func artifactDigestByName(manifest releaseManifest, name string) string {
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == name {
			return artifact.SHA256
		}
	}
	return ""
}

func newOperatorUpdateTransaction(
	receipt *operatorDeploymentReceipt,
	release *verifiedRelease,
	artifact releaseArtifact,
	executorBefore, gatewayBefore string,
) (*operatorUpdateTransaction, string, error) {
	id, err := newUUIDv4()
	if err != nil {
		return nil, "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	directory := filepath.Join(home, userAgentDirectoryName, "update", "transactions")
	if err := ensurePrivateInstallDirectory(filepath.Join(home, userAgentDirectoryName)); err != nil {
		return nil, "", err
	}
	if err := ensurePrivateInstallDirectory(filepath.Join(home, userAgentDirectoryName, "update")); err != nil {
		return nil, "", err
	}
	if err := ensurePrivateInstallDirectory(directory); err != nil {
		return nil, "", err
	}
	transaction := &operatorUpdateTransaction{
		AccountID: receipt.AccountID, DeploymentArtifact: artifact.Name,
		DeploymentArtifactSHA: artifact.SHA256, ExecutorBefore: executorBefore,
		GatewayBefore: gatewayBefore, ID: id, Outcome: "pending", Phase: "planned",
		ReleaseFrom: receipt.ReleaseVersion, ReleaseTo: release.Manifest.ReleaseVersion,
		SchemaVersion: operatorTransactionSchema, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return transaction, filepath.Join(directory, id+".json"), nil
}

func recoverOrCreateOperatorUpdateTransaction(
	receipt *operatorDeploymentReceipt,
	release *verifiedRelease,
	artifact releaseArtifact,
	executorBefore, gatewayBefore string,
) (*operatorUpdateTransaction, string, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", false, err
	}
	directory := filepath.Join(home, userAgentDirectoryName, "update", "transactions")
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		transaction, path, createErr := newOperatorUpdateTransaction(
			receipt, release, artifact, executorBefore, gatewayBefore,
		)
		return transaction, path, false, createErr
	}
	if err != nil {
		return nil, "", false, errors.New("inspect operator update transactions failed")
	}
	var matched *operatorUpdateTransaction
	var matchedPath string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		var transaction operatorUpdateTransaction
		if err := readStrictPrivateJSON(path, &transaction); err != nil {
			return nil, "", false, fmt.Errorf("read operator update transaction %s failed", entry.Name())
		}
		if transaction.AccountID != receipt.AccountID ||
			transaction.ReleaseFrom != receipt.ReleaseVersion ||
			transaction.ReleaseTo != release.Manifest.ReleaseVersion ||
			transaction.DeploymentArtifact != artifact.Name ||
			transaction.DeploymentArtifactSHA != artifact.SHA256 ||
			transaction.Outcome != "remote_needs_attention" {
			continue
		}
		if transaction.SchemaVersion != operatorTransactionSchema ||
			!uuidPattern.MatchString(transaction.ID) || entry.Name() != transaction.ID+".json" {
			return nil, "", false, errors.New("recoverable operator update transaction identity is invalid")
		}
		if transaction.Phase != "gateway_upload_unknown" {
			return nil, "", false, fmt.Errorf(
				"operator update transaction %s requires manual reconciliation at phase %s",
				transaction.ID, transaction.Phase,
			)
		}
		if transaction.ExecutorBefore != executorBefore || transaction.GatewayBefore != gatewayBefore {
			return nil, "", false, fmt.Errorf(
				"operator update transaction %s cannot resume because Cloudflare traffic changed",
				transaction.ID,
			)
		}
		if !uuidPattern.MatchString(transaction.ExecutorAfter) ||
			(transaction.GatewayAfter != "" && !uuidPattern.MatchString(transaction.GatewayAfter)) {
			return nil, "", false, errors.New("recoverable operator update transaction has invalid uploaded versions")
		}
		if matched != nil {
			return nil, "", false, errors.New("multiple recoverable operator update transactions match the selected Release")
		}
		copy := transaction
		matched = &copy
		matchedPath = path
	}
	if matched != nil {
		return matched, matchedPath, true, nil
	}
	transaction, path, createErr := newOperatorUpdateTransaction(
		receipt, release, artifact, executorBefore, gatewayBefore,
	)
	return transaction, path, false, createErr
}

func deployVerifiedUpdate(
	ctx context.Context,
	httpClient *http.Client,
	wrangler, profile string,
	bundle *stagedDeploymentBundle,
	release *verifiedRelease,
	receipt *operatorDeploymentReceipt,
	executorBefore, gatewayBefore string,
	console *operatorConsole,
	transaction *operatorUpdateTransaction,
	transactionPath string,
	resuming bool,
) (string, string, error) {
	executorConfig := bundleExecutorConfig(bundle)
	gatewayConfig := bundleGatewayConfig(bundle)
	knownExecutor := ""
	knownGateway := ""
	if resuming {
		knownExecutor = transaction.ExecutorAfter
		knownGateway = transaction.GatewayAfter
	}
	executorAfter, err := uploadOrReuseWorkerVersion(
		wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, knownExecutor,
		"OneNod "+release.Manifest.ReleaseVersion+" executor", console,
		[]string{"EXECUTOR_AUTH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"},
	)
	if err != nil {
		if knownExecutor != "" {
			return "", "", err
		}
		var unknown *remoteOutcomeUnknownError
		if errors.As(err, &unknown) && uuidPattern.MatchString(unknown.ObservedVersion) {
			transaction.ExecutorAfter = unknown.ObservedVersion
		}
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "executor_upload_unknown")
		return "", "", err
	}
	transaction.ExecutorAfter = executorAfter
	transaction.Phase = "executor_uploaded"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	gatewayAfter, err := uploadOrReuseWorkerVersion(
		wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, knownGateway,
		"OneNod "+release.Manifest.ReleaseVersion+" gateway", console,
		[]string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"},
	)
	if err != nil {
		if knownGateway != "" {
			return "", "", err
		}
		var unknown *remoteOutcomeUnknownError
		if errors.As(err, &unknown) && uuidPattern.MatchString(unknown.ObservedVersion) {
			transaction.GatewayAfter = unknown.ObservedVersion
		}
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "gateway_upload_unknown")
		return "", "", err
	}
	transaction.GatewayAfter = gatewayAfter
	transaction.Phase = "gateway_uploaded"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, executorAfter, "OneNod executor update", console); err != nil {
		var observed *observedDeploymentError
		if errors.As(err, &observed) && observed.ObservedVersion == executorBefore {
			transaction.Outcome = "remote_failed_no_change"
			transaction.Phase = "executor_deploy_failed"
			transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			_ = writeAtomicPrivateJSON(transactionPath, transaction)
			return "", "", err
		}
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "executor_deploy_unknown")
		return "", "", err
	}
	transaction.Phase = "executor_deployed"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, gatewayAfter, "OneNod gateway update", console); err != nil {
		var observed *observedDeploymentError
		if !errors.As(err, &observed) || observed.ObservedVersion != gatewayBefore {
			markOperatorUpdateNeedsAttention(transaction, transactionPath, "gateway_deploy_unknown")
			return "", "", err
		}
		return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, err)
	}
	transaction.Phase = "gateway_deployed"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	actualExecutor, executorErr := readExactDeploymentVersion(wrangler, profile, executorConfig, receipt.ExecutorWorker)
	actualGateway, gatewayErr := readExactDeploymentVersion(wrangler, profile, gatewayConfig, receipt.GatewayWorker)
	if executorErr != nil || gatewayErr != nil || actualExecutor != executorAfter || actualGateway != gatewayAfter {
		verifyErr := errors.New("authoritative Cloudflare traffic verification failed")
		return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, verifyErr)
	}
	fmt.Fprintf(
		console.stdout,
		"Waiting up to %s for the public Gateway runtime declaration to converge.\n",
		updateConvergenceTimeout,
	)
	if err := waitForRemoteRuntimeVersion(
		ctx, httpClient, receipt.Origin, release.Manifest.ReleaseVersion,
		updateConvergenceTimeout, updateConvergencePollInterval,
	); err != nil {
		verifyErr := fmt.Errorf("public runtime version did not converge: %w", err)
		return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, verifyErr)
	}
	return executorAfter, gatewayAfter, nil
}

func uploadOrReuseWorkerVersion(
	wrangler, profile, cwd, config, worker, knownVersion, message string,
	console *operatorConsole,
	requiredSecrets []string,
) (string, error) {
	version := knownVersion
	if version == "" {
		var err error
		version, err = uploadWorkerVersion(
			wrangler, profile, cwd, config, worker, message, console,
		)
		if err != nil {
			return "", err
		}
	} else {
		fmt.Fprintf(console.stdout, "Reusing previously uploaded %s version %s after read-only reconciliation.\n", worker, version)
	}
	if !uuidPattern.MatchString(version) {
		return "", fmt.Errorf("Worker %s version identity is invalid", worker)
	}
	if err := inspectWorkerVersionBindings(
		wrangler, profile, cwd, config, worker, version, requiredSecrets,
	); err != nil {
		return "", err
	}
	return version, nil
}

func markOperatorUpdateNeedsAttention(
	transaction *operatorUpdateTransaction,
	transactionPath, phase string,
) {
	transaction.Outcome = "remote_needs_attention"
	transaction.Phase = phase
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
}

func rollbackOperatorUpdate(
	wrangler, profile string,
	bundle *stagedDeploymentBundle,
	receipt *operatorDeploymentReceipt,
	executorBefore, gatewayBefore string,
	release *verifiedRelease,
	console *operatorConsole,
	transaction *operatorUpdateTransaction,
	transactionPath string,
	cause error,
) error {
	if !release.Manifest.Upgrade.RemoteRollbackSafe {
		transaction.Outcome = "remote_needs_attention"
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeAtomicPrivateJSON(transactionPath, transaction)
		return fmt.Errorf("remote update failed and signed manifest does not permit automatic rollback: %w", cause)
	}
	gatewayConfig := bundleGatewayConfig(bundle)
	executorConfig := bundleExecutorConfig(bundle)
	gatewayErr := deployWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, gatewayBefore, "OneNod automatic gateway rollback", console)
	executorErr := deployWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, executorBefore, "OneNod automatic executor rollback", console)
	actualGateway, verifyGatewayErr := readExactDeploymentVersion(wrangler, profile, gatewayConfig, receipt.GatewayWorker)
	actualExecutor, verifyExecutorErr := readExactDeploymentVersion(wrangler, profile, executorConfig, receipt.ExecutorWorker)
	if gatewayErr != nil || executorErr != nil || verifyGatewayErr != nil || verifyExecutorErr != nil ||
		actualGateway != gatewayBefore || actualExecutor != executorBefore {
		transaction.Outcome = "remote_needs_attention"
		transaction.Phase = "rollback_failed"
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		_ = writeAtomicPrivateJSON(transactionPath, transaction)
		return fmt.Errorf("remote update failed and exact rollback could not be verified: %w", cause)
	}
	transaction.Outcome = "remote_rolled_back"
	transaction.Phase = "rolled_back"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	return fmt.Errorf("remote update failed; Gateway and Executor were rolled back to their exact prior versions: %w", cause)
}

func agentServiceAccountCreateArguments(account, name, agentVaultID string) []string {
	return []string{
		"service-account", "create", name,
		"--vault", agentVaultID + ":read_items,write_items",
		"--raw", "--account", account,
	}
}

func fetchCloudflareAccounts(
	base http.RoundTripper,
	oauthToken []byte,
) ([]activeWranglerAccount, error) {
	if len(oauthToken) == 0 {
		return nil, errors.New("Wrangler OAuth token is empty")
	}
	client := secureCloudflareAPIClient(base)
	seen := map[string]struct{}{}
	var accounts []activeWranglerAccount
	for page := 1; page <= maxCloudflareAccountPages; page++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		address := fmt.Sprintf(
			"https://api.cloudflare.com/client/v4/accounts?page=%d&per_page=%d",
			page, cloudflareAccountPageSize,
		)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			cancel()
			return nil, errors.New("build Cloudflare accounts request failed")
		}
		request.Header.Set("Authorization", "Bearer "+string(oauthToken))
		response, err := client.Do(request)
		if err != nil {
			cancel()
			return nil, errors.New("list Cloudflare accounts for Wrangler profile failed")
		}
		encoded, readErr := io.ReadAll(io.LimitReader(
			response.Body, maxCloudflareAccountResponse+1,
		))
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || len(encoded) > maxCloudflareAccountResponse {
			zeroBytes(encoded)
			return nil, errors.New("read Cloudflare accounts response failed")
		}
		var envelope struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(encoded, &envelope) != nil || !envelope.Success {
			zeroBytes(encoded)
			return nil, errors.New("Wrangler OAuth cannot list Cloudflare accounts")
		}
		zeroBytes(encoded)
		for _, account := range envelope.Result {
			if !cloudflareAccountIDPattern.MatchString(account.ID) ||
				strings.TrimSpace(account.Name) == "" {
				return nil, errors.New("Cloudflare returned an invalid account")
			}
			if _, duplicate := seen[account.ID]; duplicate {
				return nil, errors.New("Cloudflare returned a duplicate account")
			}
			seen[account.ID] = struct{}{}
			accounts = append(accounts, activeWranglerAccount{
				ID: account.ID, Name: account.Name,
			})
		}
		if len(envelope.Result) < cloudflareAccountPageSize {
			return accounts, nil
		}
	}
	return nil, errors.New("Cloudflare account discovery exceeded its page limit")
}

func fetchCloudflareAccountSubdomain(base http.RoundTripper, accountID string, oauthToken []byte) (string, error) {
	client := secureCloudflareAPIClient(base)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/accounts/"+accountID+"/workers/subdomain", nil)
	if err != nil {
		return "", errors.New("build Cloudflare subdomain request failed")
	}
	request.Header.Set("Authorization", "Bearer "+string(oauthToken))
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("read Cloudflare workers.dev account subdomain failed")
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", errors.New("read Cloudflare subdomain response failed")
	}
	defer zeroBytes(encoded)
	var envelope struct {
		Success bool `json:"success"`
		Result  struct {
			Subdomain string `json:"subdomain"`
		} `json:"result"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(encoded, &envelope) != nil ||
		!envelope.Success || !dnsLabelPattern.MatchString(envelope.Result.Subdomain) {
		return "", errors.New("the selected account has no readable workers.dev subdomain; configure it in Cloudflare Dashboard before starting")
	}
	return envelope.Result.Subdomain, nil
}

func secureCloudflareAPIClient(base http.RoundTripper) *http.Client {
	if base == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		base = transport
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: exactHostTransport{base: base, host: "api.cloudflare.com"},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Cloudflare API redirects are forbidden")
		},
	}
}

func assertNoCloudflareCredentialEnvironment() error {
	for _, name := range []string{
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
		"CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("unset %s before an operator Cloudflare action; OneNod manages only named Wrangler OAuth profiles", name)
		}
	}
	return nil
}

func readRemoteInitializationState(client *http.Client, origin string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return readRemoteInitializationStateContext(ctx, client, origin)
}

func readRemoteInitializationStateContext(
	ctx context.Context,
	client *http.Client,
	origin string,
) (bool, error) {
	client = safePublicHTTPClient(client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/human/state", nil)
	if err != nil {
		return false, errors.New("build bootstrap verification request failed")
	}
	response, err := client.Do(request)
	if err != nil {
		return false, errors.New("verify remote bootstrap state failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, errors.New("Gateway bootstrap state check returned a non-200 status")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return false, errors.New("read Gateway bootstrap state failed")
	}
	defer zeroBytes(encoded)
	var state struct {
		Initialized bool `json:"initialized"`
	}
	if json.Unmarshal(encoded, &state) != nil {
		return false, errors.New("Gateway bootstrap state is invalid")
	}
	return state.Initialized, nil
}

func waitForGatewayReadiness(
	ctx context.Context,
	client *http.Client,
	origin string,
	expectedVersion string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 || !validProductVersion(expectedVersion) {
		return errors.New("invalid public Gateway readiness wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		var health struct {
			Environment string `json:"environment"`
			OK          bool   `json:"ok"`
			Service     string `json:"service"`
			Version     string `json:"version"`
		}
		if err := readOperatorGatewayJSON(probeContext, client, origin, "/api/health", &health); err != nil {
			return false, err
		}
		if !health.OK || health.Environment != "prod" || health.Service != "onenod-gateway" {
			return false, errors.New("public Gateway health returned an unexpected service identity")
		}
		if health.Version != expectedVersion {
			return false, fmt.Errorf(
				"public Gateway reports release %s instead of %s",
				health.Version, expectedVersion,
			)
		}
		return true, nil
	})
}

func waitForRemoteRuntimeVersion(
	ctx context.Context,
	client *http.Client,
	origin string,
	expectedVersion string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 || !validProductVersion(expectedVersion) {
		return errors.New("invalid public runtime version wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		var response remoteRuntimeVersionResponse
		if err := readOperatorGatewayJSON(probeContext, client, origin, "/api/version", &response); err != nil {
			return false, err
		}
		remote, complete := parseRemoteRuntimeVersion(response)
		if !complete {
			return false, errors.New("public runtime version declaration is internally inconsistent")
		}
		if remote.GatewayVersion != expectedVersion || remote.ExecutorVersion != expectedVersion ||
			remote.PwaVersion != expectedVersion {
			return false, fmt.Errorf(
				"public runtime reports Gateway %s, Executor %s, and PWA %s instead of %s",
				remote.GatewayVersion, remote.ExecutorVersion, remote.PwaVersion, expectedVersion,
			)
		}
		return true, nil
	})
}

func waitForRemoteInitialization(
	ctx context.Context,
	client *http.Client,
	origin string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 {
		return errors.New("invalid owner initialization wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		initialized, err := readRemoteInitializationStateContext(probeContext, client, origin)
		if err != nil {
			return false, err
		}
		if !initialized {
			return false, errors.New("owner identity is not initialized yet")
		}
		return true, nil
	})
}

func waitForOperatorCondition(
	ctx context.Context,
	timeout time.Duration,
	pollInterval time.Duration,
	probe func(context.Context) (bool, error),
) error {
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		probeContext, cancelProbe := context.WithTimeout(waitContext, requesterPreflightTimeout)
		ready, err := probe(probeContext)
		cancelProbe()
		if ready && err == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-waitContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if lastErr != nil {
				return fmt.Errorf("wait ended: %w", lastErr)
			}
			return errors.New("wait ended before the condition became ready")
		case <-timer.C:
		}
	}
}

func readOperatorGatewayJSON(
	ctx context.Context,
	client *http.Client,
	origin string,
	path string,
	result any,
) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("invalid Gateway readiness path")
	}
	client = safePublicHTTPClient(client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return errors.New("build Gateway readiness request failed")
	}
	request.Header.Set("accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Gateway readiness request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Gateway readiness returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(response.Header.Get("content-type")); mediaType != "" && !strings.HasPrefix(mediaType, "application/json") {
		return errors.New("Gateway readiness returned a non-JSON response")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 64*1024 {
		return errors.New("read Gateway readiness response failed")
	}
	defer zeroBytes(encoded)
	if json.Unmarshal(encoded, result) != nil {
		return errors.New("Gateway readiness response is invalid")
	}
	return nil
}
