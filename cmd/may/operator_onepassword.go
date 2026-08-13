package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

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

func agentServiceAccountCreateArguments(account, name, agentVaultID string) []string {
	return []string{
		"service-account", "create", name,
		"--vault", agentVaultID + ":read_items,write_items",
		"--raw", "--account", account,
	}
}
