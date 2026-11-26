package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// status is deliberately local and does not expose the configured provider or any secrets.
func showOperatorBeholderStatus(deps dependencies) error {
	transaction, found, err := readBeholderTransaction()
	if err != nil {
		return err
	}
	if !found {
		fmt.Fprintln(deps.stdout, "No Beholder enable transaction is recorded.")
		return nil
	}
	fmt.Fprintf(deps.stdout, "Beholder transaction: %s\n  Worker: %s\n  Release: %s\n  State: %s (%s)\n", transaction.ID, transaction.Worker, transaction.ReleaseVersion, transaction.Outcome, transaction.Phase)
	fmt.Fprintf(deps.stdout, "  Gateway before: %s\n", transaction.GatewayBefore)
	if transaction.GatewayAfter != "" {
		fmt.Fprintf(deps.stdout, "  Gateway after: %s\n", transaction.GatewayAfter)
	}
	if transaction.WorkerAfter != "" {
		fmt.Fprintf(deps.stdout, "  Worker after: %s\n", transaction.WorkerAfter)
	}
	if transaction.Outcome == "needs_attention" {
		fmt.Fprintln(deps.stdout, "Run may operator beholder rollback in an attended terminal to reconcile the Gateway. The private Worker and its data will be retained.")
	}
	return nil
}

// This narrowly reverses the initial binding within the same authenticated
// release. It does not roll back durable state or a later release update.
func rollbackOperatorBeholder(deps dependencies) error {
	if err := requireHumanOperatorTerminal(deps.stdin); err != nil {
		return err
	}
	if err := assertNoCloudflareCredentialEnvironment(); err != nil {
		return err
	}
	unlock, err := acquireOperatorDeploymentLock()
	if err != nil {
		return err
	}
	defer unlock()
	transaction, found, err := readBeholderTransaction()
	if err != nil {
		return err
	}
	if !found || transaction.Outcome == "rolled_back" {
		return errors.New("no active Beholder enable transaction to roll back")
	}
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil {
		return err
	}
	if receipt.AccountID != transaction.AccountID || receipt.ReleaseVersion != transaction.ReleaseVersion ||
		receipt.SourceCommit != transaction.SourceCommit || receipt.DeploymentArtifactSHA != transaction.ArtifactSHA {
		return errors.New("the current deployment has changed since Beholder enable; this rollback cannot be used")
	}
	if receipt.Beholder != nil && (receipt.Beholder.Worker != transaction.Worker ||
		receipt.Beholder.ProviderURL != transaction.ProviderURL || receipt.Beholder.Model != transaction.Model ||
		receipt.Beholder.VersionID != transaction.WorkerAfter || receipt.GatewayVersionID != transaction.GatewayAfter) {
		return errors.New("the current deployment receipt differs from the Beholder enable transaction")
	}
	if receipt.Beholder == nil && receipt.GatewayVersionID != transaction.GatewayBefore {
		return errors.New("the Gateway receipt differs from the original Beholder baseline")
	}
	ctx, cancel := context.WithTimeout(context.Background(), operatorInitializationTimeout)
	defer cancel()
	release, err := releaseSourceFor(deps).Exact(ctx, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	if release.Manifest.Source.Commit != receipt.SourceCommit || artifactDigestByName(release.Manifest, receipt.DeploymentArtifact) != receipt.DeploymentArtifactSHA {
		return errors.New("the recorded release no longer matches the verified release artifact")
	}
	exact, err := runningReleaseCanConsume(release.Manifest)
	if err != nil || !exact {
		return errors.New("run Beholder rollback with the exact installed Release")
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
	selection, err := existingOperatorProfile(tools.Wrangler, receipt.AccountID, deps, console)
	if err != nil {
		return err
	}
	token, err := readNamedWranglerOAuthToken(tools.Wrangler, selection.Profile)
	if err != nil {
		return err
	}
	subdomain, err := fetchCloudflareAccountSubdomain(deps.cloudflareTransport, receipt.AccountID, token)
	zeroBytes(token)
	if err != nil || subdomain != receipt.AccountSubdomain {
		return errors.New("Cloudflare account does not match the immutable deployment receipt")
	}
	material := &productionInitializationMaterial{
		AccountID: receipt.AccountID, AccountSubdomain: receipt.AccountSubdomain,
		ExecutorName: receipt.ExecutorWorker, ExecutorLocation: receipt.ExecutorLocation, GatewayName: receipt.GatewayWorker,
		OnePasswordAccount: receipt.OnePasswordAccount, AgentVaultID: receipt.OnePasswordVaultID,
		Origin: receipt.Origin, RPID: receipt.RPID, VAPID: vapidCredential{PublicKey: receipt.VAPIDPublicKey},
	}
	if err := renderDeploymentConfigs(bundle, release.Manifest, material); err != nil {
		return err
	}
	config := bundleGatewayConfig(bundle)
	actual, err := readExactDeploymentVersion(tools.Wrangler, selection.Profile, config, receipt.GatewayWorker)
	if err != nil || (actual != transaction.GatewayBefore && (transaction.GatewayAfter == "" || actual != transaction.GatewayAfter)) {
		return errors.New("Gateway traffic is not on a known version from this Beholder transaction; reconcile it manually")
	}
	if err := inspectBeholderServiceBinding(tools.Wrangler, selection.Profile, config, receipt.GatewayWorker, transaction.GatewayBefore, ""); err != nil {
		return errors.New("the prior Gateway version does not have the expected binding state")
	}
	if err := inspectWorkerVersionBindings(tools.Wrangler, selection.Profile, filepath.Dir(config), config, receipt.GatewayWorker,
		transaction.GatewayBefore, []string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"}); err != nil {
		return err
	}
	fmt.Fprintf(console.stdout, "\nBeholder rollback plan\n  Account: %s (%s)\n  Gateway: %s\n  Current version: %s\n  Restore version: %s\n  Release: %s (%s)\n", selection.Account.Name, receipt.AccountID, receipt.GatewayWorker, actual, transaction.GatewayBefore, receipt.ReleaseVersion, receipt.SourceCommit)
	fmt.Fprintln(console.stdout, "  The private Beholder Worker, its secrets, and its durable data remain in Cloudflare. No later release or data migration is rolled back.")
	confirmed, err := console.confirmDefaultNo("Restore the original Gateway binding state now?")
	if err != nil || !confirmed {
		return errors.New("Beholder rollback was not confirmed; Cloudflare was unchanged")
	}
	current, currentErr := readExactDeploymentVersion(tools.Wrangler, selection.Profile, config, receipt.GatewayWorker)
	if currentErr != nil || current != actual {
		return errors.New("Gateway traffic changed while reviewing the rollback; no mutation was attempted")
	}
	transaction.Outcome = "needs_attention"
	if err := writeBeholderPhase(transaction, "rollback_unknown"); err != nil {
		return err
	}
	if actual != transaction.GatewayBefore {
		if err := deployWorkerVersion(tools.Wrangler, selection.Profile, filepath.Dir(config), config, receipt.GatewayWorker, transaction.GatewayBefore, "OneNod Beholder binding rollback", console); err != nil {
			return err
		}
	}
	if err := waitForRemoteRuntimeVersion(ctx, deps.httpClient, receipt.Origin, receipt.ReleaseVersion, updateConvergenceTimeout, updateConvergencePollInterval); err != nil {
		return fmt.Errorf("Gateway rollback requires reconciliation: %w", err)
	}
	receipt.Beholder = nil
	receipt.GatewayVersionID = transaction.GatewayBefore
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
		return err
	}
	transaction.Outcome = "rolled_back"
	if err := writeBeholderPhase(transaction, "rolled_back"); err != nil {
		return err
	}
	fmt.Fprintln(console.stdout, "The original Gateway version is restored; the private Worker and its data were retained.")
	return nil
}
