package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

func runBinaryOperatorUpdate(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("operator update", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	channelValue := flags.String("channel", "", "release channel: stable, beta, or alpha")
	versionValue := flags.String("version", "", "exact immutable release version")
	executorLocation := flags.String("executor-location", "", "move the Executor to the us jurisdiction")
	acknowledgeJournal := flags.Bool("acknowledge-executor-journal-boundary", false, "confirm remote writes are drained and the prior journal will not be copied")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateExplicitReleaseSelection(*channelValue, *versionValue); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New(operatorUpdateUsage)
	}
	if err := assertNoCloudflareCredentialEnvironment(); err != nil {
		return err
	}
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil {
		return err
	}
	if *executorLocation != "" && *executorLocation != "us" {
		return errors.New("unsupported Executor location; the available migration target is us")
	}
	targetLocation := receipt.ExecutorLocation
	if *executorLocation != "" {
		targetLocation = *executorLocation
	}
	locationChanged := targetLocation != receipt.ExecutorLocation
	if locationChanged && !*acknowledgeJournal {
		return errors.New("moving the Executor requires --acknowledge-executor-journal-boundary after draining and reconciling remote writes")
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
	if os.Getenv(operatorUpdateReexecIdentity) == "" {
		if err := confirmHigherRiskChannel(
			deps.stdin, deps.stdout, currentChannel, channel, "Operator updates",
		); err != nil {
			return err
		}
	}
	var reexecOptions []string
	if *executorLocation != "" {
		reexecOptions = append(reexecOptions, "--executor-location", *executorLocation)
	}
	if *acknowledgeJournal {
		reexecOptions = append(reexecOptions, "--acknowledge-executor-journal-boundary")
	}
	reexecuted, err := ensureCurrentOperatorUpdater(ctx, release, deps, reexecOptions...)
	if err != nil {
		return err
	}
	if reexecuted {
		return nil
	}
	unlock, err := acquireOperatorDeploymentLock()
	if err != nil {
		return err
	}
	defer unlock()
	lockedReceipt, err := readOperatorDeploymentReceipt()
	if err != nil || !reflect.DeepEqual(receipt, lockedReceipt) {
		return errors.New("operator deployment changed while preparing the update; inspect it and retry")
	}
	if err := ensureNoPendingBeholderTransaction(receipt); err != nil {
		return err
	}
	if _, err := validateInstalledLocalUpdateHandoff(
		receipt.Origin, release.Manifest.ReleaseVersion, release.Manifest.Source.Commit,
	); err != nil {
		return err
	}
	localReceipt, _, err := readLocalInstallReceipt()
	if err != nil {
		return err
	}
	helperPlan := buildKeychainHelperUpdatePlan(release, localReceipt)
	if release.Manifest.ReleaseVersion == receipt.ReleaseVersion {
		if release.Manifest.Source.Commit != receipt.SourceCommit ||
			receipt.DeploymentArtifactSHA != artifactDigestByName(release.Manifest, receipt.DeploymentArtifact) {
			return errors.New("same_version_identity_mismatch: deployed receipt differs from the signed release")
		}
	}
	if release.Manifest.ReleaseVersion == receipt.ReleaseVersion && !locationChanged {
		remote, complete := readRemoteRuntimeVersion(receipt.Origin, deps.httpClient)
		if complete && remote.GatewayVersion == receipt.ReleaseVersion && remote.ExecutorVersion == receipt.ReleaseVersion && remote.PwaVersion == receipt.ReleaseVersion {
			if !transportUpdateJournalExists() && localInstallExactlyMatchesRelease(release, receipt.Origin) {
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
			if err := runInstalledLocalUpdate(
				ctx, receipt.Origin, release.Manifest.ReleaseVersion,
				release.Manifest.Source.Commit, deps,
			); err != nil {
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
	if receipt.Beholder != nil && !bundle.Beholder {
		return errors.New("verified Release does not include the configured Beholder Worker; refusing to remove its Gateway binding")
	}
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
		ExecutorName: receipt.ExecutorWorker, ExecutorLocation: targetLocation, GatewayName: receipt.GatewayWorker,
		OnePasswordAccount: receipt.OnePasswordAccount, AgentVaultID: receipt.OnePasswordVaultID,
		Origin: receipt.Origin, RPID: receipt.RPID, VAPID: vapidCredential{PublicKey: receipt.VAPIDPublicKey},
		Beholder: receipt.Beholder,
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
	expectedBeholderWorker := ""
	if receipt.Beholder != nil {
		expectedBeholderWorker = receipt.Beholder.Worker
	}
	if err := inspectBeholderServiceBinding(tools.Wrangler, profile, bundleGatewayConfig(bundle),
		receipt.GatewayWorker, gatewayBefore, expectedBeholderWorker); err != nil {
		return fmt.Errorf("Gateway Beholder binding differs from the deployment receipt: %w", err)
	}
	beholderCurrent := ""
	if receipt.Beholder != nil {
		beholderCurrent, err = readExactDeploymentVersion(tools.Wrangler, profile, bundleBeholderConfig(bundle), receipt.Beholder.Worker)
		if err != nil {
			return errors.New("cannot inspect Beholder Worker traffic")
		}
	}
	baselineExecutor, baselineGateway := executorBefore, gatewayBefore
	if receipt.Beholder != nil {
		baselineExecutor, baselineGateway = receipt.ExecutorVersionID, receipt.GatewayVersionID
	}
	transaction, transactionPath, resuming, err := recoverOrCreateOperatorUpdateTransaction(
		receipt, release, bundle.Artifact, baselineExecutor, baselineGateway,
	)
	if err != nil {
		return err
	}
	if resuming {
		if transaction.ExecutorLocationBefore != receipt.ExecutorLocation || transaction.ExecutorLocationAfter != targetLocation {
			return errors.New("recoverable operator update has a different Executor location; resume the original plan")
		}
	} else {
		transaction.ExecutorLocationBefore = receipt.ExecutorLocation
		transaction.ExecutorLocationAfter = targetLocation
	}
	activeLocation := receipt.ExecutorLocation
	if resuming && executorBefore == transaction.ExecutorAfter {
		activeLocation = targetLocation
	}
	if err := inspectExecutorLocation(tools.Wrangler, profile, bundleExecutorConfig(bundle), receipt.ExecutorWorker, executorBefore, activeLocation); err != nil {
		return fmt.Errorf("deployed Executor location differs from the recorded plan: %w", err)
	}
	if receipt.Beholder != nil {
		if err := validateBeholderUpdateTraffic(transaction, resuming, beholderCurrent, executorBefore, gatewayBefore); err != nil {
			return err
		}
		executorBefore, gatewayBefore = baselineExecutor, baselineGateway
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
		if receipt.Beholder != nil && transaction.BeholderAfter != "" {
			if err := inspectWorkerVersionBindings(
				tools.Wrangler, profile, filepath.Dir(bundleBeholderConfig(bundle)), bundleBeholderConfig(bundle),
				receipt.Beholder.Worker, transaction.BeholderAfter,
				[]string{"BEHOLDER_PROVIDER_KEY", "BEHOLDER_TRACE_KEY"},
			); err != nil {
				return fmt.Errorf("cannot reconcile the recorded Beholder version before resuming: %w", err)
			}
			if err := inspectBeholderWorkerConfiguration(tools.Wrangler, profile, bundleBeholderConfig(bundle), transaction.BeholderAfter, receipt.Beholder); err != nil {
				return fmt.Errorf("cannot reconcile the recorded Beholder configuration before resuming: %w", err)
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
	if locationChanged {
		fmt.Fprintln(console.stdout, "  Executor location: existing object -> US jurisdiction (western North America preferred)")
		fmt.Fprintln(console.stdout, "  The new object has a separate write journal; the old journal remains in place.")
		fmt.Fprintln(console.stdout, "  Remote writes must remain stopped until the migration is verified; reconcile all pending or unknown writes first.")
		fmt.Fprintln(console.stdout, "  Do not return to the old object after new remote writes without reconciling both journals.")
	} else if targetLocation == "us" {
		fmt.Fprintln(console.stdout, "  Executor location: US jurisdiction (unchanged)")
	}
	if receipt.Beholder != nil {
		fmt.Fprintf(console.stdout, "  Beholder: %s, baseline %s (private; existing provider and trace key retained)\n", receipt.Beholder.Worker, receipt.Beholder.VersionID)
	}
	fmt.Fprintf(console.stdout, "  Bundle: %s (%s)\n", bundle.Artifact.Name, bundle.Artifact.SHA256)
	rollbackSafe := release.Manifest.Upgrade.RemoteRollbackSafe && !locationChanged
	if receipt.Beholder != nil {
		fmt.Fprintf(console.stdout, "  Promotion order: Beholder -> %s; automatic rollback safe: %t\n", strings.Join(release.Manifest.Upgrade.Order, " -> "), rollbackSafe)
	} else {
		fmt.Fprintf(console.stdout, "  Promotion order: %s; automatic rollback safe: %t\n", strings.Join(release.Manifest.Upgrade.Order, " -> "), rollbackSafe)
	}
	if resuming {
		fmt.Fprintf(console.stdout, "  Resume transaction: %s (%s)\n", transaction.ID, transaction.Phase)
		fmt.Fprintf(console.stdout, "  Reuse verified Executor version: %s\n", transaction.ExecutorAfter)
		if transaction.Phase == "executor_upload_unknown" {
			fmt.Fprintln(console.stdout, "  Gateway upload: not yet attempted; upload once after confirmation")
		} else if transaction.GatewayAfter == "" {
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
	receipt.ExecutorLocation = targetLocation
	receipt.GatewayVersionID = gatewayAfter
	if receipt.Beholder != nil {
		receipt.Beholder.VersionID = transaction.BeholderAfter
	}
	receipt.CloudflareProfile = profile
	receipt.CloudflareProfileRevoked = profileRevoked
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
		return err
	}
	if helperPlan.Replace {
		fmt.Fprintln(console.stdout, "\nRemote deployment verified. The installed current OneNod release will now own the separate local Keychain helper ceremony.")
		fmt.Fprintln(console.stdout, "Pause every Agent harness running as this macOS user before approving the helper change.")
	}
	if err := runPostDeploymentLocalUpdate(
		ctx, receipt.Origin, release.Manifest.ReleaseVersion,
		release.Manifest.Source.Commit, transaction, transactionPath, deps,
	); err != nil {
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

func transportUpdateJournalExists() bool {
	_, found, err := readTransportUpdateJournal()
	return err != nil || found
}

func runPostDeploymentLocalUpdate(
	ctx context.Context,
	operatorOrigin, targetVersion, targetSourceCommit string,
	transaction *operatorUpdateTransaction,
	transactionPath string,
	deps dependencies,
) error {
	if err := runInstalledLocalUpdate(
		ctx, operatorOrigin, targetVersion, targetSourceCommit, deps,
	); err != nil {
		transaction.Outcome = "remote_complete_local_pending"
		_ = writeAtomicPrivateJSON(transactionPath, transaction)
		return err
	}
	return nil
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
	if receipt.Beholder != nil {
		transaction.BeholderBefore = receipt.Beholder.VersionID
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
		if receipt.Beholder != nil && transaction.AccountID == receipt.AccountID &&
			transaction.ReleaseFrom == receipt.ReleaseVersion && transaction.Outcome == "remote_needs_attention" &&
			(transaction.ReleaseTo != release.Manifest.ReleaseVersion || transaction.DeploymentArtifact != artifact.Name ||
				transaction.DeploymentArtifactSHA != artifact.SHA256) {
			return nil, "", false, errors.New("another incomplete operator update requires reconciliation before selecting a different Release")
		}
		if transaction.AccountID != receipt.AccountID ||
			transaction.ReleaseFrom != receipt.ReleaseVersion ||
			transaction.ReleaseTo != release.Manifest.ReleaseVersion ||
			transaction.DeploymentArtifact != artifact.Name ||
			transaction.DeploymentArtifactSHA != artifact.SHA256 ||
			(transaction.Outcome != "remote_needs_attention" &&
				!(receipt.Beholder != nil && (transaction.Outcome == "remote_complete" || transaction.Outcome == "deployment_authority_retained"))) {
			continue
		}
		if transaction.SchemaVersion != operatorTransactionSchema ||
			!uuidPattern.MatchString(transaction.ID) || entry.Name() != transaction.ID+".json" {
			return nil, "", false, errors.New("recoverable operator update transaction identity is invalid")
		}
		if receipt.Beholder != nil && (transaction.Phase == "beholder_deploy_unknown" || transaction.Phase == "beholder_deployed" ||
			transaction.Phase == "executor_deploy_unknown" || transaction.Phase == "executor_deployed" ||
			transaction.Phase == "gateway_deploy_unknown" || transaction.Phase == "gateway_deployed" ||
			transaction.Phase == "remote_verified" || transaction.Phase == "cloudflare_revoked") {
			if !uuidPattern.MatchString(transaction.ExecutorAfter) || !uuidPattern.MatchString(transaction.BeholderAfter) ||
				!uuidPattern.MatchString(transaction.GatewayAfter) {
				return nil, "", false, errors.New("recoverable operator update transaction has invalid uploaded versions")
			}
		} else if transaction.Phase != "executor_upload_unknown" && !(receipt.Beholder != nil && transaction.Phase == "executor_uploaded") && transaction.Phase != "beholder_upload_unknown" &&
			transaction.Phase != "beholder_uploaded" && transaction.Phase != "gateway_upload_unknown" &&
			transaction.Phase != "gateway_uploaded" {
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
		if (receipt.Beholder == nil && (transaction.BeholderBefore != "" || transaction.BeholderAfter != "")) ||
			(receipt.Beholder != nil && transaction.BeholderBefore != receipt.Beholder.VersionID) {
			return nil, "", false, errors.New("recoverable Beholder baseline differs from the deployment receipt")
		}
		if !uuidPattern.MatchString(transaction.ExecutorAfter) ||
			((transaction.Phase == "executor_upload_unknown" || transaction.Phase == "executor_uploaded") && transaction.GatewayAfter != "") ||
			((transaction.Phase == "executor_upload_unknown" || transaction.Phase == "executor_uploaded") && transaction.BeholderAfter != "") ||
			(transaction.Phase == "beholder_upload_unknown" && (receipt.Beholder == nil ||
				!uuidPattern.MatchString(transaction.BeholderAfter) || transaction.GatewayAfter != "")) ||
			(transaction.Phase == "beholder_uploaded" && (receipt.Beholder == nil ||
				!uuidPattern.MatchString(transaction.BeholderAfter) || transaction.GatewayAfter != "")) ||
			((transaction.Phase == "gateway_upload_unknown" || transaction.Phase == "gateway_uploaded") &&
				receipt.Beholder != nil && (!uuidPattern.MatchString(transaction.BeholderAfter) || !uuidPattern.MatchString(transaction.GatewayAfter))) ||
			(transaction.Phase == "gateway_uploaded" && (receipt.Beholder == nil || !uuidPattern.MatchString(transaction.GatewayAfter))) ||
			(transaction.BeholderAfter != "" && !uuidPattern.MatchString(transaction.BeholderAfter)) ||
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

// Only a prefix of the recorded promotion sequence is resumable. Unknown IDs,
// unrelated traffic, partial splits, and out-of-order promotions fail closed.
func validateBeholderUpdateTraffic(transaction *operatorUpdateTransaction, resuming bool, beholder, executor, gateway string) error {
	if transaction == nil {
		return errors.New("missing Beholder update transaction")
	}
	if !resuming {
		if beholder != transaction.BeholderBefore || executor != transaction.ExecutorBefore || gateway != transaction.GatewayBefore {
			return errors.New("Cloudflare traffic differs from the deployment receipt; reconcile before updating")
		}
		return nil
	}
	before := beholder == transaction.BeholderBefore && executor == transaction.ExecutorBefore && gateway == transaction.GatewayBefore
	if before {
		return nil
	}
	if !uuidPattern.MatchString(transaction.BeholderAfter) || !uuidPattern.MatchString(transaction.ExecutorAfter) || !uuidPattern.MatchString(transaction.GatewayAfter) {
		return errors.New("Cloudflare traffic changed without all recorded target versions")
	}
	if beholder == transaction.BeholderAfter &&
		((executor == transaction.ExecutorBefore && gateway == transaction.GatewayBefore) ||
			(executor == transaction.ExecutorAfter && gateway == transaction.GatewayBefore) ||
			(executor == transaction.ExecutorAfter && gateway == transaction.GatewayAfter)) {
		return nil
	}
	return errors.New("Cloudflare traffic is not a recorded prefix of the Beholder update; reconcile it manually")
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
	knownBeholder := ""
	if resuming {
		knownExecutor = transaction.ExecutorAfter
		knownGateway = transaction.GatewayAfter
		knownBeholder = transaction.BeholderAfter
	}
	if receipt.Beholder != nil && knownExecutor == "" {
		transaction.Outcome, transaction.Phase = "remote_needs_attention", "executor_upload_unknown"
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
			return "", "", errors.New("cannot persist Executor upload intent")
		}
	}
	executorAfter, err := uploadOrReuseWorkerVersion(
		wrangler, profile, filepath.Dir(executorConfig), executorConfig,
		receipt.ExecutorWorker, knownExecutor,
		"OneNod "+release.Manifest.ReleaseVersion+" executor", console,
		[]string{"EXECUTOR_AUTH_TOKEN", "OP_SERVICE_ACCOUNT_TOKEN"},
	)
	if err != nil {
		if uuidPattern.MatchString(executorAfter) {
			transaction.ExecutorAfter = executorAfter
		}
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
	if err := inspectExecutorLocation(wrangler, profile, executorConfig, receipt.ExecutorWorker, executorAfter, transaction.ExecutorLocationAfter); err != nil {
		markOperatorUpdateNeedsAttention(transaction, transactionPath, "executor_upload_unknown")
		return "", "", fmt.Errorf("uploaded Executor location could not be verified: %w", err)
	}
	if knownExecutor == "" {
		transaction.Phase = "executor_uploaded"
	}
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil && receipt.Beholder != nil {
		return "", "", errors.New("cannot persist uploaded Executor version; reconciliation is required")
	}
	if receipt.Beholder != nil {
		beholderConfig := bundleBeholderConfig(bundle)
		if knownBeholder == "" {
			transaction.Outcome, transaction.Phase = "remote_needs_attention", "beholder_upload_unknown"
			transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
				return "", "", errors.New("cannot persist Beholder upload intent")
			}
		}
		beholderAfter, err := uploadOrReuseWorkerVersion(
			wrangler, profile, filepath.Dir(beholderConfig), beholderConfig,
			receipt.Beholder.Worker, knownBeholder,
			"OneNod "+release.Manifest.ReleaseVersion+" beholder", console,
			[]string{"BEHOLDER_PROVIDER_KEY", "BEHOLDER_TRACE_KEY"},
		)
		if err != nil {
			if uuidPattern.MatchString(beholderAfter) {
				transaction.BeholderAfter = beholderAfter
			}
			if knownBeholder == "" {
				markOperatorUpdateNeedsAttention(transaction, transactionPath, "beholder_upload_unknown")
			}
			return "", "", err
		}
		if err := inspectBeholderWorkerConfiguration(wrangler, profile, beholderConfig, beholderAfter, receipt.Beholder); err != nil {
			transaction.BeholderAfter = beholderAfter
			markOperatorUpdateNeedsAttention(transaction, transactionPath, "beholder_upload_unknown")
			return "", "", err
		}
		transaction.BeholderAfter = beholderAfter
		if knownBeholder == "" {
			transaction.Phase = "beholder_uploaded"
		}
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
			return "", "", errors.New("cannot persist uploaded Beholder version; reconciliation is required")
		}
	}
	if receipt.Beholder != nil && knownGateway == "" {
		transaction.Outcome, transaction.Phase = "remote_needs_attention", "gateway_upload_unknown"
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
			return "", "", errors.New("cannot persist Gateway upload intent")
		}
	}
	gatewayAfter, err := uploadOrReuseWorkerVersion(
		wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, knownGateway,
		"OneNod "+release.Manifest.ReleaseVersion+" gateway", console,
		[]string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"},
	)
	if err != nil {
		if uuidPattern.MatchString(gatewayAfter) {
			transaction.GatewayAfter = gatewayAfter
		}
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
	if receipt.Beholder != nil {
		if err := inspectBeholderServiceBinding(wrangler, profile, gatewayConfig, receipt.GatewayWorker,
			gatewayAfter, receipt.Beholder.Worker); err != nil {
			transaction.GatewayAfter = gatewayAfter
			markOperatorUpdateNeedsAttention(transaction, transactionPath, "gateway_upload_unknown")
			return "", "", err
		}
	}
	transaction.GatewayAfter = gatewayAfter
	if knownGateway == "" {
		transaction.Phase = "gateway_uploaded"
	}
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil && receipt.Beholder != nil {
		return "", "", errors.New("cannot persist uploaded Gateway version; reconciliation is required")
	}
	if receipt.Beholder != nil {
		beholderConfig := bundleBeholderConfig(bundle)
		if err := deployRecordedUpdateVersion(wrangler, profile, beholderConfig, receipt.Beholder.Worker,
			transaction.BeholderBefore, transaction.BeholderAfter, "beholder", console, transaction, transactionPath); err != nil {
			return "", "", err
		}
		transaction.Phase = "beholder_deployed"
		transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
			return "", "", errors.New("cannot persist deployed Beholder version; reconciliation is required")
		}
	}
	var executorDeployErr error
	if receipt.Beholder != nil {
		executorDeployErr = deployRecordedUpdateVersion(wrangler, profile, executorConfig, receipt.ExecutorWorker,
			executorBefore, executorAfter, "executor", console, transaction, transactionPath)
	} else {
		executorDeployErr = deployWorkerVersion(wrangler, profile, filepath.Dir(executorConfig), executorConfig,
			receipt.ExecutorWorker, executorAfter, "OneNod executor update", console)
	}
	if err := executorDeployErr; err != nil {
		var observed *observedDeploymentError
		if errors.As(err, &observed) && observed.ObservedVersion == executorBefore {
			if receipt.Beholder != nil {
				return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, err)
			}
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
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil && receipt.Beholder != nil {
		return "", "", errors.New("cannot persist deployed Executor version; reconciliation is required")
	}
	var gatewayDeployErr error
	if receipt.Beholder != nil {
		gatewayDeployErr = deployRecordedUpdateVersion(wrangler, profile, gatewayConfig, receipt.GatewayWorker,
			gatewayBefore, gatewayAfter, "gateway", console, transaction, transactionPath)
	} else {
		gatewayDeployErr = deployWorkerVersion(wrangler, profile, filepath.Dir(gatewayConfig), gatewayConfig,
			receipt.GatewayWorker, gatewayAfter, "OneNod gateway update", console)
	}
	if err := gatewayDeployErr; err != nil {
		var observed *observedDeploymentError
		if !errors.As(err, &observed) || observed.ObservedVersion != gatewayBefore {
			markOperatorUpdateNeedsAttention(transaction, transactionPath, "gateway_deploy_unknown")
			return "", "", err
		}
		return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, err)
	}
	transaction.Phase = "gateway_deployed"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil && receipt.Beholder != nil {
		return "", "", errors.New("cannot persist deployed Gateway version; reconciliation is required")
	}
	actualExecutor, executorErr := readExactDeploymentVersion(wrangler, profile, executorConfig, receipt.ExecutorWorker)
	actualGateway, gatewayErr := readExactDeploymentVersion(wrangler, profile, gatewayConfig, receipt.GatewayWorker)
	beholderVerified := true
	if receipt.Beholder != nil {
		actual, err := readExactDeploymentVersion(wrangler, profile, bundleBeholderConfig(bundle), receipt.Beholder.Worker)
		beholderVerified = err == nil && actual == transaction.BeholderAfter
	}
	if executorErr != nil || gatewayErr != nil || actualExecutor != executorAfter || actualGateway != gatewayAfter || !beholderVerified {
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
	if receipt.Beholder != nil {
		if err := waitForBeholderRuntimeVersion(ctx, httpClient, receipt.Origin, release.Manifest.ReleaseVersion,
			release.Manifest.Source.Commit, updateConvergenceTimeout, updateConvergencePollInterval); err != nil {
			verifyErr := fmt.Errorf("Beholder runtime version did not converge: %w", err)
			return "", "", rollbackOperatorUpdate(wrangler, profile, bundle, receipt, executorBefore, gatewayBefore, release, console, transaction, transactionPath, verifyErr)
		}
	}
	return executorAfter, gatewayAfter, nil
}

func deployRecordedUpdateVersion(wrangler, profile, config, worker, before, after, label string,
	console *operatorConsole, transaction *operatorUpdateTransaction, transactionPath string) error {
	actual, err := readExactDeploymentVersion(wrangler, profile, config, worker)
	if err != nil {
		return err
	}
	if actual == after {
		fmt.Fprintf(console.stdout, "Confirmed %s version %s is already serving 100%%; not deploying it again.\n", worker, after)
		return nil
	}
	if actual != before {
		return errors.New("Worker traffic changed outside the recorded update; manual reconciliation is required")
	}
	transaction.Outcome, transaction.Phase = "remote_needs_attention", label+"_deploy_unknown"
	transaction.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeAtomicPrivateJSON(transactionPath, transaction); err != nil {
		return errors.New("cannot persist Worker deployment intent")
	}
	return deployWorkerVersion(wrangler, profile, filepath.Dir(config), config, worker, after, "OneNod "+label+" update", console)
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
			var unknown *remoteOutcomeUnknownError
			if errors.As(err, &unknown) && uuidPattern.MatchString(unknown.ObservedVersion) {
				return unknown.ObservedVersion, err
			}
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
		return version, err
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
	if transaction.ExecutorLocationBefore != transaction.ExecutorLocationAfter {
		markOperatorUpdateNeedsAttention(transaction, transactionPath, transaction.Phase)
		return fmt.Errorf("remote update failed; automatic rollback across an Executor journal boundary is prohibited; keep remote writes stopped and reconcile or resume the recorded update: %w", cause)
	}
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
	var beholderErr, verifyBeholderErr error
	var actualBeholder string
	if receipt.Beholder != nil {
		beholderConfig := bundleBeholderConfig(bundle)
		beholderErr = deployWorkerVersion(wrangler, profile, filepath.Dir(beholderConfig), beholderConfig,
			receipt.Beholder.Worker, transaction.BeholderBefore, "OneNod automatic beholder rollback", console)
		actualBeholder, verifyBeholderErr = readExactDeploymentVersion(wrangler, profile, beholderConfig, receipt.Beholder.Worker)
	}
	if gatewayErr != nil || executorErr != nil || verifyGatewayErr != nil || verifyExecutorErr != nil ||
		actualGateway != gatewayBefore || actualExecutor != executorBefore || beholderErr != nil || verifyBeholderErr != nil ||
		(receipt.Beholder != nil && actualBeholder != transaction.BeholderBefore) {
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
	return fmt.Errorf("remote update failed; configured Workers were rolled back to their exact prior versions: %w", cause)
}
