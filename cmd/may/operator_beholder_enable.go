package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/term"
)

func runOperatorBeholder(args []string, deps dependencies) error {
	if len(args) != 1 {
		return errors.New("usage: may operator beholder <enable|status|rollback>")
	}
	switch args[0] {
	case "enable":
		return enableOperatorBeholder(deps)
	case "status":
		return showOperatorBeholderStatus(deps)
	case "rollback":
		return rollbackOperatorBeholder(deps)
	default:
		return errors.New("usage: may operator beholder <enable|status|rollback>")
	}
}

func requireHumanOperatorTerminal(input any) error {
	file, ok := input.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) || os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return errors.New("Beholder deployment and secret entry require a human-controlled local terminal")
	}
	return nil
}

func existingOperatorProfile(wrangler, accountID string, deps dependencies, console *operatorConsole) (operatorWranglerSelection, error) {
	profiles, err := listWranglerProfiles(wrangler)
	if err != nil {
		return operatorWranglerSelection{}, err
	}
	var candidates []operatorWranglerSelection
	for _, profile := range profiles {
		accounts, authenticated, inspectErr := tryInspectWranglerProfileAccounts(wrangler, profile, deps.cloudflareTransport)
		if inspectErr != nil {
			return operatorWranglerSelection{}, errors.New("cannot inspect a Wrangler profile")
		}
		if !authenticated {
			continue
		}
		for _, account := range accounts {
			if account.ID == accountID {
				candidates = append(candidates, operatorWranglerSelection{Profile: profile, Account: account})
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Profile < candidates[j].Profile })
	if len(candidates) == 0 {
		return operatorWranglerSelection{}, errors.New("no authenticated Wrangler profile matches the recorded Cloudflare account; authenticate it in a human-owned session first")
	}
	if len(candidates) == 1 {
		return candidates[0], nil
	}
	fmt.Fprintln(console.stdout, "Authenticated Wrangler profiles for the recorded account:")
	for index, candidate := range candidates {
		fmt.Fprintf(console.stdout, "  %d. %s\n", index+1, candidate.Profile)
	}
	selected, err := console.readRequiredValue("Choose profile number")
	var index int
	if err != nil {
		return operatorWranglerSelection{}, errors.New("Wrangler profile selection is invalid")
	}
	if _, scanErr := fmt.Sscanf(selected, "%d", &index); scanErr != nil || index < 1 || index > len(candidates) || fmt.Sprint(index) != selected {
		return operatorWranglerSelection{}, errors.New("Wrangler profile selection is invalid")
	}
	return candidates[index-1], nil
}

func enableOperatorBeholder(deps dependencies) error {
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
	receipt, err := readOperatorDeploymentReceipt()
	if err != nil {
		return err
	}
	if err := ensureNoPendingBeholderTransaction(receipt); err != nil {
		return err
	}
	if receipt.Beholder != nil {
		return errors.New("Beholder is already configured in the deployment receipt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), operatorInitializationTimeout)
	defer cancel()
	release, err := releaseSourceFor(deps).Exact(ctx, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	if release.Manifest.Source.Commit != receipt.SourceCommit ||
		artifactDigestByName(release.Manifest, receipt.DeploymentArtifact) != receipt.DeploymentArtifactSHA {
		return errors.New("deployed release differs from the authenticated operator receipt")
	}
	exact, err := runningReleaseCanConsume(release.Manifest)
	if err != nil || !exact {
		return errors.New("run Beholder enable with the exact installed Release")
	}
	if _, err := validateInstalledLocalUpdateHandoff(receipt.Origin, receipt.ReleaseVersion, receipt.SourceCommit); err != nil {
		return err
	}
	remote, complete := readRemoteRuntimeVersion(receipt.Origin, deps.httpClient)
	if !complete || remote.GatewayVersion != receipt.ReleaseVersion || remote.ExecutorVersion != receipt.ReleaseVersion || remote.PwaVersion != receipt.ReleaseVersion {
		return errors.New("deployed Gateway, Executor, and PWA must match the recorded Release")
	}
	bundle, err := stageVerifiedDeploymentBundle(ctx, release)
	if err != nil {
		return err
	}
	defer os.RemoveAll(bundle.Stage)
	if bundle.Descriptor.Beholder == nil {
		return errors.New("the verified Release does not include Beholder")
	}
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
	providerURL, err := console.readRequiredValue("Confirmed HTTPS model provider endpoint")
	if err != nil || !validBeholderProviderURL(providerURL) {
		return errors.New("model provider endpoint is invalid")
	}
	model, err := console.readRequiredValue("Confirmed model alias")
	if err != nil || !validBeholderModel(model) {
		return errors.New("model alias is invalid")
	}
	deploymentID, err := newDeploymentID()
	if err != nil {
		return err
	}
	worker := "onenod-beholder-" + deploymentID
	selected := &operatorBeholderReceipt{Worker: worker, ProviderURL: providerURL, Model: model}
	material := &productionInitializationMaterial{
		AccountID: receipt.AccountID, AccountSubdomain: receipt.AccountSubdomain,
		ExecutorName: receipt.ExecutorWorker, GatewayName: receipt.GatewayWorker,
		OnePasswordAccount: receipt.OnePasswordAccount, AgentVaultID: receipt.OnePasswordVaultID,
		Origin: receipt.Origin, RPID: receipt.RPID, VAPID: vapidCredential{PublicKey: receipt.VAPIDPublicKey}, Beholder: selected,
	}
	if err := renderDeploymentConfigs(bundle, release.Manifest, material); err != nil {
		return err
	}
	gatewayConfig, workerConfig := bundleGatewayConfig(bundle), bundleBeholderConfig(bundle)
	gatewayBefore, err := readExactDeploymentVersion(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker)
	if err != nil || gatewayBefore != receipt.GatewayVersionID {
		return errors.New("Gateway traffic differs from the deployment receipt")
	}
	if err := inspectBeholderServiceBinding(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker, gatewayBefore, ""); err != nil {
		return err
	}
	_, absent, err := readWorkerDeploymentState(tools.Wrangler, selection.Profile, workerConfig, worker)
	if err != nil || !absent {
		return errors.New("cannot prove the proposed Beholder Worker name is unused")
	}
	fmt.Fprintln(console.stdout, "\nBeholder deployment plan")
	fmt.Fprintf(console.stdout, "  Cloudflare account: %s (%s)\n  Worker: %s (private)\n", selection.Account.Name, receipt.AccountID, worker)
	fmt.Fprintf(console.stdout, "  Gateway: %s at %s, baseline %s\n", receipt.GatewayWorker, receipt.Origin, gatewayBefore)
	fmt.Fprintf(console.stdout, "  Release: %s, source %s\n  Provider: %s\n  Model: %s\n", receipt.ReleaseVersion, receipt.SourceCommit, providerURL, model)
	fmt.Fprintln(console.stdout, "  Model-selected task context is sent to this Worker and provider; review events are encrypted for seven days.")
	fmt.Fprintln(console.stdout, "  The human will enter the provider key directly into Wrangler. A fresh trace key is generated locally and sent to Cloudflare.")
	fmt.Fprintln(console.stdout, "  Rollback restores the exact prior Gateway version and retains the private Worker and its data.")
	confirmed, err := console.confirmDefaultNo("Create and bind this Beholder Worker now?")
	if err != nil || !confirmed {
		return errors.New("Beholder deployment was not confirmed; Cloudflare was unchanged")
	}
	currentGateway, currentErr := readExactDeploymentVersion(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker)
	_, stillAbsent, absentErr := readWorkerDeploymentState(tools.Wrangler, selection.Profile, workerConfig, worker)
	if currentErr != nil || currentGateway != gatewayBefore || absentErr != nil || !stillAbsent {
		return errors.New("Cloudflare state changed while reviewing the Beholder plan; no mutation was attempted")
	}
	id, err := newUUIDv4()
	if err != nil {
		return err
	}
	transaction := &operatorBeholderTransaction{
		SchemaVersion: 1, ID: id, AccountID: receipt.AccountID, ReleaseVersion: receipt.ReleaseVersion,
		SourceCommit: receipt.SourceCommit, ArtifactSHA: receipt.DeploymentArtifactSHA,
		Worker: worker, ProviderURL: providerURL, Model: model, GatewayBefore: gatewayBefore,
		Phase: "planned", Outcome: "needs_attention", UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := beginBeholderTransaction(transaction); err != nil {
		return err
	}
	if err := writeBeholderPhase(transaction, "scaffold_unknown"); err != nil {
		return err
	}
	if _, err := deployPrivateWorkerScaffold(tools.Wrangler, selection.Profile, workerConfig, worker, "OneNod Beholder private scaffold", console); err != nil {
		return err
	}
	if err := writeBeholderPhase(transaction, "provider_secret_unknown"); err != nil {
		return err
	}
	fmt.Fprintln(console.stdout, "Enter the dedicated model provider key in Wrangler's hidden prompt.")
	if err := runWranglerStreaming(tools.Wrangler, selection.Profile, filepath.Dir(workerConfig), []string{
		"secret", "put", "BEHOLDER_PROVIDER_KEY", "--config", workerConfig, "--name", worker,
	}, nil, console, operatorCommandTimeout); err != nil {
		return errors.New("provider secret outcome requires reconciliation")
	}
	if err := writeBeholderPhase(transaction, "trace_secret_unknown"); err != nil {
		return err
	}
	if err := putFreshBeholderTraceKey(tools.Wrangler, selection.Profile, workerConfig, worker, console); err != nil {
		return err
	}
	if err := writeBeholderPhase(transaction, "worker_upload_unknown"); err != nil {
		return err
	}
	workerAfter, err := uploadOrReuseWorkerVersion(tools.Wrangler, selection.Profile, filepath.Dir(workerConfig), workerConfig,
		worker, "", "OneNod "+receipt.ReleaseVersion+" beholder", console, []string{"BEHOLDER_PROVIDER_KEY", "BEHOLDER_TRACE_KEY"})
	if uuidPattern.MatchString(workerAfter) {
		transaction.WorkerAfter = workerAfter
	}
	if writeErr := writeBeholderPhase(transaction, "worker_upload_unknown"); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return err
	}
	if err := inspectBeholderWorkerConfiguration(tools.Wrangler, selection.Profile, workerConfig, workerAfter, selected); err != nil {
		return err
	}
	if err := writeBeholderPhase(transaction, "worker_deploy_unknown"); err != nil {
		return err
	}
	if err := deployWorkerVersion(tools.Wrangler, selection.Profile, filepath.Dir(workerConfig), workerConfig, worker, workerAfter, "OneNod Beholder enable", console); err != nil {
		return err
	}
	if err := writeBeholderPhase(transaction, "gateway_upload_unknown"); err != nil {
		return err
	}
	gatewayAfter, err := uploadOrReuseWorkerVersion(tools.Wrangler, selection.Profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, "", "OneNod "+receipt.ReleaseVersion+" Gateway Beholder binding", console,
		[]string{"EXECUTOR_AUTH_TOKEN", "GATEWAY_MASTER_KEY", "VAPID_PRIVATE_KEY"})
	if uuidPattern.MatchString(gatewayAfter) {
		transaction.GatewayAfter = gatewayAfter
	}
	if writeErr := writeBeholderPhase(transaction, "gateway_upload_unknown"); writeErr != nil {
		return writeErr
	}
	if err != nil {
		return err
	}
	if err := inspectBeholderServiceBinding(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker, gatewayAfter, worker); err != nil {
		return err
	}
	currentGateway, currentErr = readExactDeploymentVersion(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker)
	if currentErr != nil || currentGateway != gatewayBefore {
		return errors.New("Gateway traffic changed during Beholder enable; reconciliation is required")
	}
	if err := writeBeholderPhase(transaction, "gateway_deploy_unknown"); err != nil {
		return err
	}
	if err := deployWorkerVersion(tools.Wrangler, selection.Profile, filepath.Dir(gatewayConfig), gatewayConfig,
		receipt.GatewayWorker, gatewayAfter, "OneNod Beholder binding", console); err != nil {
		return err
	}
	if err := waitForRemoteRuntimeVersion(ctx, deps.httpClient, receipt.Origin, receipt.ReleaseVersion, updateConvergenceTimeout, updateConvergencePollInterval); err != nil {
		return err
	}
	if err := waitForBeholderRuntimeVersion(ctx, deps.httpClient, receipt.Origin, receipt.ReleaseVersion, receipt.SourceCommit, updateConvergenceTimeout, updateConvergencePollInterval); err != nil {
		return err
	}
	actualWorker, err := readExactDeploymentVersion(tools.Wrangler, selection.Profile, workerConfig, worker)
	if err != nil || actualWorker != workerAfter {
		return errors.New("Beholder Worker traffic could not be verified")
	}
	actualGateway, err := readExactDeploymentVersion(tools.Wrangler, selection.Profile, gatewayConfig, receipt.GatewayWorker)
	if err != nil || actualGateway != gatewayAfter {
		return errors.New("Gateway traffic could not be verified after Beholder enable")
	}
	if err := writeBeholderPhase(transaction, "gateway_verified"); err != nil {
		return err
	}
	selected.VersionID = workerAfter
	receipt.Beholder, receipt.GatewayVersionID = selected, gatewayAfter
	receipt.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := writeOperatorDeploymentReceipt(*receipt); err != nil {
		return err
	}
	transaction.Outcome = "complete"
	if err := writeBeholderPhase(transaction, "complete"); err != nil {
		return err
	}
	fmt.Fprintln(console.stdout, "Beholder Worker and Gateway binding are verified. The separate attended local Core and context-service installation remains required.")
	return nil
}

func beginBeholderTransaction(value *operatorBeholderTransaction) error {
	path, err := beholderTransactionPath()
	if err != nil {
		return err
	}
	previous, found, err := readBeholderTransaction()
	if err != nil {
		return err
	}
	if found {
		if previous.Outcome != "rolled_back" {
			return errors.New("an existing Beholder transaction must be reconciled first")
		}
		archive := filepath.Join(filepath.Dir(path), "beholder-transaction-"+previous.ID+".json")
		if _, err := os.Lstat(archive); !errors.Is(err, os.ErrNotExist) {
			return errors.New("Beholder transaction archive already exists")
		}
		if err := os.Rename(path, archive); err != nil {
			return errors.New("archive prior Beholder transaction failed")
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("claim Beholder deployment transaction failed")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		encoded = append(encoded, '\n')
		_, err = file.Write(encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("persist Beholder deployment transaction failed")
	}
	return nil
}

func writeBeholderPhase(value *operatorBeholderTransaction, phase string) error {
	value.Phase, value.UpdatedAt = phase, time.Now().UTC().Format(time.RFC3339)
	path, err := beholderTransactionPath()
	if err != nil {
		return err
	}
	return writeAtomicPrivateJSON(path, value)
}

func putFreshBeholderTraceKey(wrangler, profile, config, worker string, console *operatorConsole) error {
	raw := make([]byte, 32)
	defer zeroBytes(raw)
	if _, err := rand.Read(raw); err != nil {
		return errors.New("generate Beholder trace key failed")
	}
	input := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw))+1)
	defer zeroBytes(input)
	base64.RawURLEncoding.Encode(input[:len(input)-1], raw)
	input[len(input)-1] = '\n'
	if err := runWranglerStreaming(wrangler, profile, filepath.Dir(config), []string{
		"secret", "put", "BEHOLDER_TRACE_KEY", "--config", config, "--name", worker,
	}, input, console, operatorCommandTimeout); err != nil {
		return errors.New("trace key write outcome requires reconciliation")
	}
	return nil
}
