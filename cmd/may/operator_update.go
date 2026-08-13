package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

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
	if os.Getenv(operatorUpdateReexecIdentity) == "" {
		if err := confirmHigherRiskChannel(
			deps.stdin, deps.stdout, currentChannel, channel, "Operator updates",
		); err != nil {
			return err
		}
	}
	reexecuted, err := ensureCurrentOperatorUpdater(ctx, release, deps)
	if err != nil {
		return err
	}
	if reexecuted {
		return nil
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
	if helperPlan.Replace {
		if confirmErr := confirmPostDeploymentHelperUpdate(
			console.stdin, console.stdout, release.Manifest.ReleaseVersion,
		); confirmErr != nil {
			transaction.Outcome = "remote_complete_local_pending"
			_ = writeAtomicPrivateJSON(transactionPath, transaction)
			return confirmErr
		}
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

func confirmPostDeploymentHelperUpdate(
	input io.Reader,
	output io.Writer,
	version string,
) error {
	fmt.Fprintln(output, "\nRemote deployment verified. The remaining local Keychain helper change is a separate security ceremony.")
	fmt.Fprintln(output, "Pause every Agent harness running as this macOS user before continuing, and keep them paused through any macOS authorization dialogs.")
	confirmed, err := promptYesNo(
		input,
		output,
		"Update the exact OneNod Keychain helper on this Mac now?",
		false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return fmt.Errorf(
			"remote deployment is complete; local helper update was not approved—after pausing same-user Agent harnesses, run may update --version %s",
			version,
		)
	}
	return nil
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
