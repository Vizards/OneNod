package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	operatorUpdateReexecIdentity  = "ONENOD_UPDATE_REEXEC_IDENTITY"
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

func ensureCurrentOperatorUpdater(
	ctx context.Context,
	release *verifiedRelease,
	deps dependencies,
) (bool, error) {
	expectedIdentity := release.Manifest.ReleaseVersion + "@" + release.Manifest.Source.Commit
	marker := os.Getenv(operatorUpdateReexecIdentity)
	exact, err := runningReleaseCanConsume(release.Manifest)
	if err != nil {
		return false, err
	}
	if marker != "" && (marker != expectedIdentity || !exact) {
		return false, errors.New("operator_update_reexec_identity_mismatch: verified updater did not restart as the expected exact Release")
	}
	if exact {
		return false, nil
	}
	if marker != "" {
		return false, errors.New("operator_update_reexec_loop: refusing to restart the updater more than once")
	}
	path, stage, err := stageVerifiedReleaseMay(ctx, release)
	if err != nil {
		return false, fmt.Errorf("stage current verified operator updater failed: %w", err)
	}
	defer os.RemoveAll(stage)
	home, err := os.UserHomeDir()
	if err != nil {
		return false, errors.New("resolve user home for operator updater failed")
	}
	command := exec.CommandContext(
		ctx, path,
		"operator", "update", "--version", release.Manifest.ReleaseVersion,
	)
	command.Dir = home
	command.Env = releaseReexecEnvironment(operatorUpdateReexecIdentity, expectedIdentity)
	command.Stdin = deps.stdin
	command.Stdout = deps.stdout
	command.Stderr = deps.stderr
	fmt.Fprintf(
		deps.stdout,
		"Restarting with verified OneNod %s to plan and execute its own update; the installed runtime is unchanged.\n",
		release.Manifest.ReleaseVersion,
	)
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return false, errors.New("re-executed operator updater timed out")
		}
		return false, errors.New("re-executed verified operator updater failed")
	}
	return true, nil
}

func initializerReexecEnvironment(expectedIdentity string) []string {
	return releaseReexecEnvironment(initializerReexecIdentity, expectedIdentity)
}

func releaseReexecEnvironment(markerName, expectedIdentity string) []string {
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
		markerName+"="+expectedIdentity,
	)
}
