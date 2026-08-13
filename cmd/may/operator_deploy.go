package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

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
