package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

type operatorBeholderTransaction struct {
	SchemaVersion  int    `json:"schema_version"`
	ID             string `json:"id"`
	AccountID      string `json:"account_id"`
	ReleaseVersion string `json:"release_version"`
	SourceCommit   string `json:"source_commit"`
	ArtifactSHA    string `json:"artifact_sha256"`
	Worker         string `json:"worker"`
	ProviderURL    string `json:"provider_url"`
	Model          string `json:"model"`
	GatewayBefore  string `json:"gateway_before"`
	GatewayAfter   string `json:"gateway_after,omitempty"`
	WorkerAfter    string `json:"worker_after,omitempty"`
	Phase          string `json:"phase"`
	Outcome        string `json:"outcome"`
	UpdatedAt      string `json:"updated_at"`
}

func acquireOperatorDeploymentLock() (func(), error) {
	receiptPath, err := operatorReceiptPath()
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateInstallDirectory(filepath.Dir(receiptPath)); err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(receiptPath), "deployment.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, errors.New("open operator deployment lock failed")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	stat, ok := func() (*syscall.Stat_t, bool) {
		if err != nil {
			return nil, false
		}
		value, valid := info.Sys().(*syscall.Stat_t)
		return value, valid
	}()
	if err != nil || !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Getuid()) ||
		unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = file.Close()
		return nil, errors.New("another operator deployment is active or its lock is unsafe")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
}

func beholderTransactionPath() (string, error) {
	path, err := operatorReceiptPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "beholder-transaction.json"), nil
}

func readBeholderTransaction() (*operatorBeholderTransaction, bool, error) {
	path, err := beholderTransactionPath()
	if err != nil {
		return nil, false, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	var transaction operatorBeholderTransaction
	if err := readStrictPrivateJSON(path, &transaction); err != nil || transaction.SchemaVersion != 1 ||
		!uuidPattern.MatchString(transaction.ID) || !cloudflareAccountIDPattern.MatchString(transaction.AccountID) ||
		!validProductVersion(transaction.ReleaseVersion) || !commitPattern.MatchString(transaction.SourceCommit) || !digestPattern.MatchString(transaction.ArtifactSHA) ||
		!workerNamePattern.MatchString(transaction.Worker) || len(transaction.Worker) > 63 ||
		!validBeholderProviderURL(transaction.ProviderURL) || !validBeholderModel(transaction.Model) ||
		!uuidPattern.MatchString(transaction.GatewayBefore) ||
		(transaction.GatewayAfter != "" && !uuidPattern.MatchString(transaction.GatewayAfter)) ||
		(transaction.WorkerAfter != "" && !uuidPattern.MatchString(transaction.WorkerAfter)) {
		return nil, false, errors.New("Beholder deployment transaction is invalid")
	}
	return &transaction, true, nil
}

func ensureNoPendingBeholderTransaction(receipt *operatorDeploymentReceipt) error {
	transaction, found, err := readBeholderTransaction()
	if err != nil || !found {
		return err
	}
	if transaction.Outcome == "complete" {
		if receipt == nil || receipt.Beholder == nil || receipt.Beholder.Worker != transaction.Worker ||
			receipt.Beholder.ProviderURL != transaction.ProviderURL || receipt.Beholder.Model != transaction.Model {
			return errors.New("completed Beholder transaction differs from the deployment receipt")
		}
		return nil
	}
	if transaction.Outcome == "rolled_back" {
		if receipt != nil && receipt.Beholder != nil {
			return errors.New("rolled-back Beholder transaction differs from the deployment receipt")
		}
		return nil
	}
	if transaction.Phase == "gateway_verified" && receipt != nil && receipt.Beholder != nil &&
		receipt.AccountID == transaction.AccountID && receipt.ReleaseVersion == transaction.ReleaseVersion &&
		receipt.SourceCommit == transaction.SourceCommit && receipt.DeploymentArtifactSHA == transaction.ArtifactSHA && receipt.GatewayVersionID == transaction.GatewayAfter &&
		receipt.Beholder.Worker == transaction.Worker && receipt.Beholder.VersionID == transaction.WorkerAfter &&
		receipt.Beholder.ProviderURL == transaction.ProviderURL && receipt.Beholder.Model == transaction.Model {
		transaction.Outcome, transaction.Phase = "complete", "complete"
		path, pathErr := beholderTransactionPath()
		if pathErr == nil {
			pathErr = writeAtomicPrivateJSON(path, transaction)
		}
		return pathErr
	}
	return errors.New("an incomplete Beholder deployment requires reconciliation before another operator update")
}

func validBeholderProviderURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value &&
		!strings.ContainsAny(value, "\x00\r\n") && len(value) <= 2048
}

func validBeholderModel(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func bundleBeholderConfig(bundle *stagedDeploymentBundle) string {
	if bundle == nil || !bundle.Beholder {
		return ""
	}
	return filepath.Join(bundle.Root, "beholder", "wrangler.jsonc")
}

func renderBeholderDeploymentConfig(bundle *stagedDeploymentBundle, material *productionInitializationMaterial) error {
	if bundle == nil || !bundle.Beholder || material == nil || material.Beholder == nil {
		return errors.New("verified release does not include the configured Beholder Worker")
	}
	selected := material.Beholder
	if !workerNamePattern.MatchString(selected.Worker) || len(selected.Worker) > 63 ||
		selected.Worker == material.GatewayName || selected.Worker == material.ExecutorName ||
		!cloudflareAccountIDPattern.MatchString(material.AccountID) ||
		!validBeholderProviderURL(selected.ProviderURL) || !validBeholderModel(selected.Model) {
		return errors.New("Beholder deployment configuration is invalid")
	}
	workerPath := bundleBeholderConfig(bundle)
	workerBytes, found, err := readOptionalRegularFile(workerPath, 4<<20)
	if err != nil || !found {
		return errors.New("read verified Beholder Worker template failed")
	}
	var worker map[string]json.RawMessage
	if json.Unmarshal(workerBytes, &worker) != nil || worker == nil ||
		string(worker["name"]) != `"__BEHOLDER_NAME__"` || string(worker["account_id"]) != `"__ACCOUNT_ID__"` {
		return errors.New("verified Beholder Worker template is invalid")
	}
	var vars map[string]string
	if json.Unmarshal(worker["vars"], &vars) != nil || len(vars) != 2 ||
		vars["BEHOLDER_PROVIDER_URL"] != "__BEHOLDER_PROVIDER_URL__" || vars["BEHOLDER_MODEL"] != "__BEHOLDER_MODEL__" {
		return errors.New("verified Beholder Worker variables are invalid")
	}
	vars["BEHOLDER_PROVIDER_URL"], vars["BEHOLDER_MODEL"] = selected.ProviderURL, selected.Model
	worker["name"], _ = json.Marshal(selected.Worker)
	worker["account_id"], _ = json.Marshal(material.AccountID)
	worker["vars"], _ = json.Marshal(vars)
	encoded, err := json.MarshalIndent(worker, "", "  ")
	if err != nil || writeAtomicUserConfig(workerPath, append(encoded, '\n'), 0o600) != nil {
		return errors.New("render verified Beholder Worker configuration failed")
	}
	return attachBeholderServiceBinding(bundleGatewayConfig(bundle), selected.Worker)
}

func attachBeholderServiceBinding(path, workerName string) error {
	encoded, found, err := readOptionalRegularFile(path, 4<<20)
	if err != nil || !found {
		return errors.New("read rendered Gateway configuration failed")
	}
	var gateway map[string]json.RawMessage
	if json.Unmarshal(encoded, &gateway) != nil || gateway == nil {
		return errors.New("rendered Gateway configuration is invalid")
	}
	var services []json.RawMessage
	if json.Unmarshal(gateway["services"], &services) != nil {
		return errors.New("rendered Gateway service bindings are invalid")
	}
	for _, service := range services {
		var value struct {
			Binding string `json:"binding"`
		}
		if json.Unmarshal(service, &value) != nil || value.Binding == "" {
			return errors.New("rendered Gateway service binding is invalid")
		}
		if value.Binding == "BEHOLDER_SERVICE" {
			return errors.New("Gateway template already contains a Beholder binding")
		}
	}
	binding, _ := json.Marshal(struct {
		Binding string `json:"binding"`
		Service string `json:"service"`
	}{Binding: "BEHOLDER_SERVICE", Service: workerName})
	services = append(services, binding)
	gateway["services"], _ = json.Marshal(services)
	updated, err := json.MarshalIndent(gateway, "", "  ")
	if err != nil || writeAtomicUserConfig(path, append(updated, '\n'), 0o600) != nil {
		return errors.New("render Gateway Beholder binding failed")
	}
	return nil
}

func inspectBeholderServiceBinding(wrangler, profile, config, gateway, version, expectedWorker string) error {
	output, err := runWranglerCapture(wrangler, profile, filepath.Dir(config), []string{
		"versions", "view", version, "--config", config, "--name", gateway, "--json",
	}, nil, workerVersionInspectTimeout)
	defer zeroBytes(output)
	if err != nil {
		return errors.New("inspect Gateway Beholder binding failed")
	}
	var view struct {
		ID        string `json:"id"`
		Resources struct {
			Bindings []struct {
				Name        string `json:"name"`
				Type        string `json:"type"`
				Service     string `json:"service"`
				Environment string `json:"environment"`
				Entrypoint  string `json:"entrypoint"`
			} `json:"bindings"`
		} `json:"resources"`
	}
	if json.Unmarshal(output, &view) != nil || view.ID != version || view.Resources.Bindings == nil {
		return errors.New("Gateway binding metadata is invalid")
	}
	matches := 0
	for _, binding := range view.Resources.Bindings {
		if binding.Name != "BEHOLDER_SERVICE" {
			continue
		}
		matches++
		if expectedWorker == "" || binding.Type != "service" || binding.Service != expectedWorker ||
			binding.Environment != "" || binding.Entrypoint != "" {
			return errors.New("Gateway Beholder binding does not match the confirmed Worker")
		}
	}
	if (expectedWorker == "" && matches != 0) || (expectedWorker != "" && matches != 1) {
		return errors.New("Gateway Beholder binding is missing or duplicated")
	}
	return nil
}

func inspectBeholderWorkerConfiguration(wrangler, profile, config, version string, selected *operatorBeholderReceipt) error {
	if selected == nil {
		return errors.New("Beholder deployment configuration is missing")
	}
	output, err := runWranglerCapture(wrangler, profile, filepath.Dir(config), []string{
		"versions", "view", version, "--config", config, "--name", selected.Worker, "--json",
	}, nil, workerVersionInspectTimeout)
	defer zeroBytes(output)
	if err != nil {
		return errors.New("inspect Beholder Worker configuration failed")
	}
	var view struct {
		ID        string `json:"id"`
		Resources struct {
			Bindings []struct {
				Name       string `json:"name"`
				Type       string `json:"type"`
				Text       string `json:"text"`
				ClassName  string `json:"class_name"`
				ScriptName string `json:"script_name"`
			} `json:"bindings"`
		} `json:"resources"`
	}
	if json.Unmarshal(output, &view) != nil || view.ID != version || view.Resources.Bindings == nil {
		return errors.New("Beholder Worker version metadata is invalid")
	}
	seen := map[string]bool{}
	for _, binding := range view.Resources.Bindings {
		switch binding.Name {
		case "DECISIONS", "BEHOLDER_PROVIDER_URL", "BEHOLDER_MODEL":
			if seen[binding.Name] {
				return errors.New("Beholder Worker has a duplicate configuration binding")
			}
			seen[binding.Name] = true
			switch binding.Name {
			case "DECISIONS":
				if binding.Type != "durable_object_namespace" || binding.ClassName != "BeholderDecision" || binding.ScriptName != "" {
					return errors.New("Beholder Worker Durable Object binding differs from the confirmed plan")
				}
			case "BEHOLDER_PROVIDER_URL":
				if binding.Type != "plain_text" || binding.Text != selected.ProviderURL {
					return errors.New("Beholder Worker provider differs from the confirmed plan")
				}
			case "BEHOLDER_MODEL":
				if binding.Type != "plain_text" || binding.Text != selected.Model {
					return errors.New("Beholder Worker model differs from the confirmed plan")
				}
			}
		}
	}
	if !seen["DECISIONS"] || !seen["BEHOLDER_PROVIDER_URL"] || !seen["BEHOLDER_MODEL"] {
		return errors.New("Beholder Worker configuration bindings are incomplete")
	}
	return nil
}
