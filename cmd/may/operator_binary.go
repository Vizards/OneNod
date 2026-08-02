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
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	operatorReceiptSchema     = 1
	operatorTransactionSchema = 1
	operatorCommandTimeout    = 5 * time.Minute
	initializerReexecIdentity = "ONENOD_INIT_REEXEC_IDENTITY"
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
	ID          string
	Name        string
	Permissions []string
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
	AuthType    string
	Permissions []string
	Accounts    []activeWranglerAccount
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
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
	profile, err := createTemporaryWranglerProfile(tools.Wrangler, console)
	if err != nil {
		return err
	}
	profileRevoked := false
	profileRetainedByHuman := false
	defer func() {
		if !profileRevoked && !profileRetainedByHuman {
			if bestEffortDeleteWranglerProfile(tools.Wrangler, profile) {
				profileRevoked = true
			} else {
				fmt.Fprintf(console.stderr, "SECURITY WARNING: automatic cleanup of Cloudflare profile %s failed. Revoke it now with: wrangler auth delete %s\n", profile, profile)
			}
		}
	}()
	identity, err := inspectWranglerIdentity(tools.Wrangler, profile)
	if err != nil {
		return err
	}
	account, err := selectWranglerAccount(identity, console)
	if err != nil {
		return err
	}
	if err := assertNoOtherWranglerProfileAccess(tools.Wrangler, profile, account.ID, true); err != nil {
		return err
	}
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
	writeFirstDeploymentPlan(console.stdout, release, bundle.Artifact, account, identityTarget, onePasswordPlan, profile)
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
	installNow, installPromptErr := console.confirmDefaultYes("Install the OneNod local runtime, requester support, and managed Skill for this macOS user now?")
	var localInstallErr error
	if installNow {
		localInstallErr = installVerifiedRelease(ctx, release, material.Origin, deps, true)
	}
	profileRevoked, err = promptAndRevokeWranglerProfile(tools.Wrangler, profile, account.ID, console)
	profileRetainedByHuman = err == nil && !profileRevoked
	receipt.CloudflareProfileRevoked = profileRevoked
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if writeErr := writeOperatorDeploymentReceipt(receipt); err == nil && writeErr != nil {
		err = writeErr
	}
	if err != nil {
		return err
	}
	if installPromptErr != nil {
		return installPromptErr
	}
	if localInstallErr != nil {
		return fmt.Errorf("remote deployment completed and Cloudflare profile handling finished, but local installation failed: %w", localInstallErr)
	}
	if profileRevoked {
		fmt.Fprintln(console.stdout, "OneNod first deployment is complete and this Mac's temporary Cloudflare profile was revoked.")
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

func inspectWranglerIdentity(wrangler, profile string) (wranglerIdentity, error) {
	output, err := runOperatorCapture(wrangler, []string{"whoami", "--profile", profile, "--json"}, "", nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return wranglerIdentity{}, errors.New("Wrangler named profile is not OAuth-authenticated")
	}
	var raw struct {
		LoggedIn         bool     `json:"loggedIn"`
		AuthType         string   `json:"authType"`
		TokenPermissions []string `json:"tokenPermissions"`
		Accounts         []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if json.Unmarshal(output, &raw) != nil || !raw.LoggedIn || raw.AuthType != "OAuth Token" || len(raw.Accounts) == 0 {
		return wranglerIdentity{}, errors.New("Wrangler must use an OAuth named profile with at least one account")
	}
	for _, required := range []string{"account:read", "workers_scripts:write"} {
		if !slices.Contains(raw.TokenPermissions, required) {
			return wranglerIdentity{}, fmt.Errorf("Wrangler OAuth is missing required permission %s", required)
		}
	}
	identity := wranglerIdentity{AuthType: raw.AuthType, Permissions: append([]string(nil), raw.TokenPermissions...)}
	for _, rawAccount := range raw.Accounts {
		if !cloudflareAccountIDPattern.MatchString(rawAccount.ID) || strings.TrimSpace(rawAccount.Name) == "" {
			return wranglerIdentity{}, errors.New("Wrangler returned an invalid Cloudflare account")
		}
		identity.Accounts = append(identity.Accounts, activeWranglerAccount{ID: rawAccount.ID, Name: rawAccount.Name, Permissions: identity.Permissions})
	}
	return identity, nil
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

func readNamedWranglerOAuthToken(wrangler, profile string) ([]byte, error) {
	output, err := runOperatorCapture(wrangler, []string{"auth", "token", "--profile", profile, "--json"}, "", nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return nil, errors.New("Wrangler OAuth token cannot be loaded for account subdomain discovery")
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
	gateway, err := console.readValue("Public Gateway Worker name", defaultGatewayWorkerName)
	if err != nil {
		return productionTargetIdentity{}, err
	}
	executor, err := console.readValue("Private Executor Worker name", defaultExecutorWorkerName)
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
) {
	fmt.Fprintln(output, "\nOneNod first-deployment plan")
	fmt.Fprintf(output, "  Verified release: %s (%s)\n", release.Manifest.ReleaseVersion, release.Manifest.Source.Commit)
	fmt.Fprintf(output, "  Release channel: %s (artifact channel %s)\n",
		selectedReleaseChannel(release), release.Manifest.Channel)
	fmt.Fprintf(output, "  Deployment bundle: %s (%s)\n", artifact.Name, artifact.SHA256)
	fmt.Fprintf(output, "  Temporary Wrangler profile: %s\n", profile)
	fmt.Fprintf(output, "  Cloudflare account: %s (%s)\n", account.Name, account.ID)
	fmt.Fprintf(output, "  Gateway: %s at %s\n", target.GatewayName, target.Origin)
	fmt.Fprintf(output, "  Executor: %s (private)\n", target.ExecutorName)
	fmt.Fprintf(output, "  Durable Objects: ApprovalCoordinator and OnePasswordExecutor (SQLite)\n")
	fmt.Fprintf(output, "  1Password account: %s\n", onePassword.Account)
	fmt.Fprintf(output, "  Vaults to create: %s and %s (human-only recovery)\n", onePassword.AgentVaultName, onePassword.RecoveryVaultName)
	fmt.Fprintf(output, "  Service Account: %s; read_items,write_items on %s only\n", onePassword.ServiceAccountName, onePassword.AgentVaultName)
	fmt.Fprintln(output, "  Bootstrap: one-time URL fragment, removed from the Worker after the first Passkey is registered")
	fmt.Fprintln(output, "  Final gate: revoke only this temporary Wrangler profile (default yes)")
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
	executorVersion, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, "OneNod "+release.Manifest.ReleaseVersion+" executor scaffold", console)
	if err != nil {
		return "", "", err
	}
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		material.ExecutorName, executorVersion, "OneNod executor scaffold", console); err != nil {
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
	executorVersion, err = uploadWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
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

	gatewayVersion, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, "OneNod "+release.Manifest.ReleaseVersion+" gateway scaffold", console)
	if err != nil {
		return "", "", err
	}
	if err := deployWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		material.GatewayName, gatewayVersion, "OneNod gateway scaffold", console); err != nil {
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
	gatewayVersion, err = uploadWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
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
	output, err := runWranglerCapture(wrangler, profile, filepath.Dir(config), []string{
		"deployments", "status", "--config", config, "--name", worker, "--json",
	}, nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return "", fmt.Errorf("read deployment status for %s failed", worker)
	}
	var status struct {
		Versions []struct {
			VersionID  string  `json:"version_id"`
			Percentage float64 `json:"percentage"`
		} `json:"versions"`
	}
	if json.Unmarshal(output, &status) != nil || len(status.Versions) != 1 ||
		status.Versions[0].Percentage != 100 || !uuidPattern.MatchString(status.Versions[0].VersionID) {
		return "", fmt.Errorf("deployment %s is not an exact single-version 100%% state", worker)
	}
	return status.Versions[0].VersionID, nil
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
	if _, err := console.readLine("Press Enter after Passkey registration reaches the approval screen: "); err != nil {
		return err
	}
	initialized, err := readRemoteInitializationState(deps.httpClient, material.Origin)
	if err != nil || !initialized {
		return errors.New("Gateway does not report an initialized human identity; BOOTSTRAP_TOKEN was retained for a safe retry")
	}
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

func promptAndRevokeWranglerProfile(wrangler, profile, accountID string, console *operatorConsole) (bool, error) {
	revoke, err := console.confirmDefaultYes("Revoke this Mac's Cloudflare deployment authority now?")
	if err != nil {
		return false, err
	}
	if !revoke {
		fmt.Fprintf(console.stderr, "Cloudflare profile %s was retained by explicit choice.\n", profile)
		return false, nil
	}
	if err := runOperatorCommand(wrangler, []string{"auth", "delete", profile}, "", nil, console, operatorCommandTimeout); err != nil {
		return false, errors.New("delete temporary Wrangler profile failed")
	}
	output, err := runOperatorCapture(wrangler, []string{"auth", "token", "--profile", profile, "--json"}, "", nil, 30*time.Second)
	defer zeroBytes(output)
	if err == nil {
		return false, errors.New("Wrangler profile still yields an OAuth token after deletion")
	}
	if err := assertNoOtherWranglerProfileAccess(wrangler, profile, accountID, false); err != nil {
		return false, fmt.Errorf("temporary profile was deleted, but current-Mac Cloudflare revocation could not be proven: %w", err)
	}
	return true, nil
}

func assertNoOtherWranglerProfileAccess(wrangler, temporaryProfile, accountID string, requireTemporaryProfile bool) error {
	profiles, err := listWranglerProfiles(wrangler)
	if err != nil {
		return err
	}
	temporaryMatches := 0
	var matching []string
	for _, profile := range profiles {
		if profile == temporaryProfile {
			temporaryMatches++
			continue
		}
		accounts, err := inspectWranglerProfileAccounts(wrangler, profile)
		if err != nil {
			return fmt.Errorf("cannot safely inspect Wrangler profile %q; clean it up manually and retry", profile)
		}
		for _, account := range accounts {
			if account.ID == accountID {
				matching = append(matching, profile)
				break
			}
		}
	}
	if temporaryMatches > 1 {
		return errors.New("Wrangler auth list returned the temporary profile more than once")
	}
	if requireTemporaryProfile && temporaryMatches != 1 {
		return errors.New("Wrangler auth list does not contain the temporary operator profile")
	}
	if len(matching) > 0 {
		sort.Strings(matching)
		return fmt.Errorf(
			"other Wrangler profiles still expose the dedicated Cloudflare account: %s; delete those profiles manually and retry",
			strings.Join(matching, ", "),
		)
	}
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

func inspectWranglerProfileAccounts(wrangler, profile string) ([]activeWranglerAccount, error) {
	output, err := runOperatorCapture(wrangler, []string{"whoami", "--profile", profile, "--json"}, "", nil, operatorCommandTimeout)
	defer zeroBytes(output)
	if err != nil {
		return nil, err
	}
	var raw struct {
		LoggedIn bool `json:"loggedIn"`
		Accounts []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"accounts"`
	}
	if json.Unmarshal(output, &raw) != nil {
		return nil, errors.New("Wrangler profile returned invalid identity JSON")
	}
	if !raw.LoggedIn {
		return []activeWranglerAccount{}, nil
	}
	accounts := make([]activeWranglerAccount, 0, len(raw.Accounts))
	seen := map[string]struct{}{}
	for _, account := range raw.Accounts {
		if !cloudflareAccountIDPattern.MatchString(account.ID) || strings.TrimSpace(account.Name) == "" {
			return nil, errors.New("Wrangler profile returned an invalid Cloudflare account")
		}
		if _, duplicate := seen[account.ID]; duplicate {
			return nil, errors.New("Wrangler profile returned duplicate Cloudflare accounts")
		}
		seen[account.ID] = struct{}{}
		accounts = append(accounts, activeWranglerAccount{ID: account.ID, Name: account.Name})
	}
	return accounts, nil
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
	profile, err := createTemporaryWranglerProfile(tools.Wrangler, console)
	if err != nil {
		return err
	}
	profileRevoked := false
	profileRetainedByHuman := false
	defer func() {
		if !profileRevoked && !profileRetainedByHuman {
			if bestEffortDeleteWranglerProfile(tools.Wrangler, profile) {
				profileRevoked = true
			} else {
				fmt.Fprintf(console.stderr, "SECURITY WARNING: automatic cleanup of Cloudflare profile %s failed. Revoke it now with: wrangler auth delete %s\n", profile, profile)
			}
		}
	}()
	identity, err := inspectWranglerIdentity(tools.Wrangler, profile)
	if err != nil {
		return err
	}
	account, found := accountByID(identity.Accounts, receipt.AccountID)
	if !found {
		return errors.New("temporary Wrangler profile does not expose the receipt's dedicated Cloudflare account")
	}
	if err := assertNoOtherWranglerProfileAccess(tools.Wrangler, profile, account.ID, true); err != nil {
		return err
	}
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
	transaction, transactionPath, err := newOperatorUpdateTransaction(receipt, release, bundle.Artifact, executorBefore, gatewayBefore)
	if err != nil {
		return err
	}
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
		return err
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
	writeKeychainHelperUpdatePlan(console.stdout, helperPlan)
	confirmed, err := promptYesNo(console.stdin, console.stdout, "Deploy this OneNod update now?", false)
	if err != nil || !confirmed {
		transaction.Outcome = "not_confirmed"
		transaction.Phase = "planned"
		_ = writeAtomicPrivateJSON(transactionPath, transaction)
		if err != nil {
			return err
		}
		return errors.New("operator update was not confirmed; production traffic was unchanged")
	}
	executorAfter, gatewayAfter, deployErr := deployVerifiedUpdate(
		tools.Wrangler, profile, bundle, release, receipt, executorBefore, gatewayBefore, console, transaction, transactionPath,
	)
	if deployErr != nil {
		return deployErr
	}
	transaction.ExecutorAfter = executorAfter
	transaction.GatewayAfter = gatewayAfter
	transaction.Phase = "remote_verified"
	transaction.Outcome = "remote_complete"
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	profileRevoked, err = promptAndRevokeWranglerProfile(tools.Wrangler, profile, account.ID, console)
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

func deployVerifiedUpdate(
	wrangler, profile string,
	bundle *stagedDeploymentBundle,
	release *verifiedRelease,
	receipt *operatorDeploymentReceipt,
	executorBefore, gatewayBefore string,
	console *operatorConsole,
	transaction *operatorUpdateTransaction,
	transactionPath string,
) (string, string, error) {
	executorConfig := bundleExecutorConfig(bundle)
	gatewayConfig := bundleGatewayConfig(bundle)
	executorAfter, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, "OneNod "+release.Manifest.ReleaseVersion+" executor", console)
	if err != nil {
		var unknown *remoteOutcomeUnknownError
		if errors.As(err, &unknown) && uuidPattern.MatchString(unknown.ObservedVersion) {
			transaction.ExecutorAfter = unknown.ObservedVersion
		}
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "executor_upload_unknown")
		return "", "", err
	}
	if err := inspectWorkerVersionBindings(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, executorAfter, []string{"EXECUTOR_AUTH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"}); err != nil {
		return "", "", err
	}
	transaction.ExecutorAfter = executorAfter
	transaction.Phase = "executor_uploaded"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	_ = writeAtomicPrivateJSON(transactionPath, transaction)
	gatewayAfter, err := uploadWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, "OneNod "+release.Manifest.ReleaseVersion+" gateway", console)
	if err != nil {
		var unknown *remoteOutcomeUnknownError
		if errors.As(err, &unknown) && uuidPattern.MatchString(unknown.ObservedVersion) {
			transaction.GatewayAfter = unknown.ObservedVersion
		}
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "gateway_upload_unknown")
		return "", "", err
	}
	if err := inspectWorkerVersionBindings(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, gatewayAfter, []string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"}); err != nil {
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
	remote, complete := readRemoteRuntimeVersion(receipt.Origin, nil)
	if executorErr != nil || gatewayErr != nil || actualExecutor != executorAfter || actualGateway != gatewayAfter ||
		!complete || remote.GatewayVersion != release.Manifest.ReleaseVersion ||
		remote.ExecutorVersion != release.Manifest.ReleaseVersion || remote.PwaVersion != release.Manifest.ReleaseVersion {
		verifyErr := errors.New("authoritative Cloudflare or runtime version verification failed")
		return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, verifyErr)
	}
	return executorAfter, gatewayAfter, nil
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
			return fmt.Errorf("unset %s before operator deployment; OneNod requires a temporary named Wrangler OAuth profile", name)
		}
	}
	return nil
}

func readRemoteInitializationState(client *http.Client, origin string) (bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
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
