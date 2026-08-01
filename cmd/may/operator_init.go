package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	defaultAgentVaultName         = "Agent"
	defaultExecutorWorkerName     = "onenod-executor"
	defaultGatewayWorkerName      = "onenod"
	defaultRecoveryVaultName      = "OneNod Recovery"
	defaultServiceAccountName     = "onenod-executor"
	productionInitializationTag   = "onenod-production"
	productionInitializationTitle = "OneNod production recovery"
	serviceAccountTokenItemTitle  = "OneNod Executor Service Account"
)

var serviceAccountTokenPattern = regexp.MustCompile(`^ops_[A-Za-z0-9_-]+$`)
var cloudflareAccountIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var onePasswordVaultIDPattern = regexp.MustCompile(`^[a-z0-9]{26}$`)
var onePasswordAccountPattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.1password\.(?:com|ca|eu)$`,
)
var workerNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

type productionInitializationMaterial struct {
	AccountID                      string
	AccountSubdomain               string
	AgentVaultID                   string
	AgentVaultName                 string
	BootstrapToken                 string
	ExecutorAuthToken              string
	ExecutorName                   string
	GatewayMasterKey               string
	GatewayName                    string
	InitializationID               string
	OnePasswordServiceAccountItem  string
	OnePasswordServiceAccountName  string
	OnePasswordServiceAccountToken string
	OnePasswordAccount             string
	Origin                         string
	RecoveryItemID                 string
	RecoveryVault                  string
	ReleaseStage                   string
	RPID                           string
	VAPID                          vapidCredential
}

type onePasswordProvisioning struct {
	Account                 string
	AgentVault              humanRecoveryVault
	RecoveryVault           humanRecoveryVault
	ServiceAccountName      string
	ServiceAccountToken     string
	ServiceAccountTokenItem string
}

type productionTargetIdentity struct {
	AccountID        string
	AccountSubdomain string
	ExecutorName     string
	GatewayName      string
	Origin           string
	RPID             string
}

type operatorConsole struct {
	input  *bufio.Reader
	stdin  io.Reader
	stderr io.Writer
	stdout io.Writer
}

func runProductionInitialization(args []string, deps dependencies) error {
	if len(args) != 0 {
		return errors.New("usage: may operator init")
	}
	console := operatorConsole{
		input:  bufio.NewReader(deps.stdin),
		stdin:  deps.stdin,
		stderr: deps.stderr,
		stdout: deps.stdout,
	}
	return runBinaryFirstProductionDeployment(&console, deps)
}

func newProductionInitializationMaterial(
	provisioning onePasswordProvisioning,
	identity productionTargetIdentity,
) (*productionInitializationMaterial, error) {
	executorAuthToken, err := randomBase64URL(32)
	if err != nil {
		return nil, errors.New("generate executor authentication token failed")
	}
	gatewayMasterKey, err := randomBase64URL(32)
	if err != nil {
		return nil, errors.New("generate gateway master key failed")
	}
	bootstrapToken, err := randomBase64URL(32)
	if err != nil {
		return nil, errors.New("generate bootstrap token failed")
	}
	vapid, err := newVapidCredential()
	if err != nil {
		return nil, errors.New("generate production VAPID keypair failed")
	}
	initializationID, err := newUUIDv4()
	if err != nil {
		return nil, errors.New("generate initialization ID failed")
	}
	material := &productionInitializationMaterial{
		AccountID:                      identity.AccountID,
		AccountSubdomain:               identity.AccountSubdomain,
		AgentVaultID:                   provisioning.AgentVault.ID,
		AgentVaultName:                 provisioning.AgentVault.Name,
		BootstrapToken:                 bootstrapToken,
		ExecutorAuthToken:              executorAuthToken,
		ExecutorName:                   identity.ExecutorName,
		GatewayMasterKey:               gatewayMasterKey,
		GatewayName:                    identity.GatewayName,
		InitializationID:               initializationID,
		OnePasswordServiceAccountItem:  provisioning.ServiceAccountTokenItem,
		OnePasswordServiceAccountName:  provisioning.ServiceAccountName,
		OnePasswordServiceAccountToken: provisioning.ServiceAccountToken,
		OnePasswordAccount:             provisioning.Account,
		Origin:                         identity.Origin,
		RecoveryVault:                  provisioning.RecoveryVault.ID,
		ReleaseStage:                   "production",
		RPID:                           identity.RPID,
		VAPID:                          vapid,
	}
	if err := validateProductionInitializationMaterial(material); err != nil {
		return nil, err
	}
	return material, nil
}

func validateProductionTargetIdentity(
	identity productionTargetIdentity,
) (productionTargetIdentity, error) {
	if !cloudflareAccountIDPattern.MatchString(identity.AccountID) {
		return productionTargetIdentity{}, errors.New("invalid Cloudflare account ID")
	}
	if !dnsLabelPattern.MatchString(identity.AccountSubdomain) {
		return productionTargetIdentity{}, errors.New("invalid Cloudflare account subdomain")
	}
	if err := validateWorkerName(identity.GatewayName, 63); err != nil {
		return productionTargetIdentity{}, errors.New(
			"Gateway Worker name must be a workers.dev DNS label of at most 63 characters",
		)
	}
	if err := validateWorkerName(identity.ExecutorName, 255); err != nil {
		return productionTargetIdentity{}, errors.New("invalid Executor Worker name")
	}
	if identity.GatewayName == identity.ExecutorName {
		return productionTargetIdentity{}, errors.New("Gateway and Executor Worker names must differ")
	}
	expectedOrigin := workersDevOrigin(identity.GatewayName, identity.AccountSubdomain)
	expectedRPID := strings.TrimPrefix(expectedOrigin, "https://")
	if identity.Origin != expectedOrigin || identity.RPID != expectedRPID {
		return productionTargetIdentity{}, errors.New(
			"Gateway Origin and RP ID must be derived from the Worker and account subdomain",
		)
	}
	return identity, nil
}

func validateWorkerName(value string, maximumLength int) error {
	if len(value) == 0 || len(value) > maximumLength ||
		!workerNamePattern.MatchString(value) {
		return errors.New("invalid Worker name")
	}
	return nil
}

func workersDevOrigin(gatewayName string, accountSubdomain string) string {
	return fmt.Sprintf("https://%s.%s.workers.dev", gatewayName, accountSubdomain)
}

func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	defer zeroBytes(value)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func serviceAccountTokenItemTemplate(
	serviceAccountName string,
	agentVault humanRecoveryVault,
	serviceAccountToken string,
) ([]byte, error) {
	template := map[string]any{
		"category": "SECURE_NOTE",
		"title":    serviceAccountTokenItemTitle,
		"tags":     []string{productionInitializationTag},
		"fields": []map[string]any{
			{
				"id":      "notesPlain",
				"label":   "notesPlain",
				"purpose": "NOTES",
				"type":    "STRING",
				"value":   "Human-only copy of the Executor Service Account token. The Service Account can access only the Agent vault and cannot access this Recovery vault.",
			},
			concealedRecoveryField(
				"service_account_token",
				"OP_SERVICE_ACCOUNT_TOKEN",
				serviceAccountToken,
			),
			{
				"id":    "service_account_name",
				"label": "SERVICE_ACCOUNT_NAME",
				"type":  "STRING",
				"value": serviceAccountName,
			},
			{
				"id":    "agent_vault_name",
				"label": "AGENT_VAULT_NAME",
				"type":  "STRING",
				"value": agentVault.Name,
			},
			{
				"id":    "agent_vault_id",
				"label": "AGENT_VAULT_ID",
				"type":  "STRING",
				"value": agentVault.ID,
			},
		},
	}
	return json.Marshal(template)
}

func productionRecoveryItemTemplate(
	material *productionInitializationMaterial,
) ([]byte, error) {
	template := map[string]any{
		"category": "SECURE_NOTE",
		"title":    productionRecoveryItemTitle(material),
		"tags":     []string{productionInitializationTag},
		"fields": []map[string]any{
			{
				"id":      "notesPlain",
				"label":   "notesPlain",
				"purpose": "NOTES",
				"type":    "STRING",
				"value":   "Human-only recovery material. Never grant the Agent Service Account access to this vault.",
			},
			concealedRecoveryField("executor_auth_token", "EXECUTOR_AUTH_TOKEN", material.ExecutorAuthToken),
			concealedRecoveryField("gateway_master_key", "GATEWAY_MASTER_KEY", material.GatewayMasterKey),
			concealedRecoveryField("vapid_private_key", "VAPID_PRIVATE_KEY", material.VAPID.PrivateKey),
			{
				"id":    "vapid_public_key",
				"label": "VAPID_PUBLIC_KEY",
				"type":  "STRING",
				"value": material.VAPID.PublicKey,
			},
			{
				"id":    "origin",
				"label": "ORIGIN",
				"type":  "STRING",
				"value": material.Origin,
			},
			{
				"id":    "onepassword_account",
				"label": "ONEPASSWORD_ACCOUNT",
				"type":  "STRING",
				"value": material.OnePasswordAccount,
			},
			{
				"id":    "cloudflare_account_id",
				"label": "CLOUDFLARE_ACCOUNT_ID",
				"type":  "STRING",
				"value": material.AccountID,
			},
			{
				"id":    "cloudflare_account_subdomain",
				"label": "CLOUDFLARE_ACCOUNT_SUBDOMAIN",
				"type":  "STRING",
				"value": material.AccountSubdomain,
			},
			{
				"id":    "gateway_worker",
				"label": "GATEWAY_WORKER",
				"type":  "STRING",
				"value": material.GatewayName,
			},
			{
				"id":    "executor_worker",
				"label": "EXECUTOR_WORKER",
				"type":  "STRING",
				"value": material.ExecutorName,
			},
			{
				"id":    "agent_vault_name",
				"label": "AGENT_VAULT_NAME",
				"type":  "STRING",
				"value": material.AgentVaultName,
			},
			{
				"id":    "agent_vault_id",
				"label": "AGENT_VAULT_ID",
				"type":  "STRING",
				"value": material.AgentVaultID,
			},
			{
				"id":    "service_account_name",
				"label": "SERVICE_ACCOUNT_NAME",
				"type":  "STRING",
				"value": material.OnePasswordServiceAccountName,
			},
			{
				"id":    "service_account_token_item",
				"label": "SERVICE_ACCOUNT_TOKEN_ITEM_ID",
				"type":  "STRING",
				"value": material.OnePasswordServiceAccountItem,
			},
		},
	}
	return json.Marshal(template)
}

func productionRecoveryItemTitle(
	material *productionInitializationMaterial,
) string {
	return fmt.Sprintf(
		"%s — %s",
		productionInitializationTitle,
		material.InitializationID,
	)
}

func concealedRecoveryField(id string, label string, value string) map[string]any {
	return map[string]any{
		"id":    id,
		"label": label,
		"type":  "CONCEALED",
		"value": value,
	}
}

func validateProductionInitializationMaterial(
	material *productionInitializationMaterial,
) error {
	if material == nil ||
		material.ReleaseStage != "production" ||
		material.InitializationID == "" ||
		material.RecoveryVault == "" ||
		material.AgentVaultName != defaultAgentVaultName ||
		!onePasswordVaultIDPattern.MatchString(material.AgentVaultID) ||
		!onePasswordVaultIDPattern.MatchString(material.RecoveryVault) ||
		material.OnePasswordServiceAccountName == "" ||
		material.OnePasswordServiceAccountItem == "" ||
		!onePasswordAccountPattern.MatchString(material.OnePasswordAccount) ||
		!validServiceAccountToken(material.OnePasswordServiceAccountToken) {
		return errors.New("invalid production initialization material")
	}
	validatedIdentity, err := validateProductionTargetIdentity(productionTargetIdentity{
		AccountID:        material.AccountID,
		AccountSubdomain: material.AccountSubdomain,
		ExecutorName:     material.ExecutorName,
		GatewayName:      material.GatewayName,
		Origin:           material.Origin,
		RPID:             material.RPID,
	})
	if err != nil || validatedIdentity.Origin != material.Origin {
		return errors.New("invalid production target identity")
	}
	for _, value := range []string{
		material.BootstrapToken,
		material.ExecutorAuthToken,
		material.GatewayMasterKey,
	} {
		decoded, err := base64.RawURLEncoding.DecodeString(value)
		if err != nil || len(decoded) != 32 {
			return errors.New("invalid generated production secret")
		}
		zeroBytes(decoded)
	}
	return validateVapidCredential(&material.VAPID)
}

func validServiceAccountToken(value string) bool {
	return len(value) >= 36 &&
		len(value) <= 4096 &&
		serviceAccountTokenPattern.MatchString(value)
}

func destroyProductionInitializationSecrets(
	material *productionInitializationMaterial,
) {
	material.BootstrapToken = ""
	material.ExecutorAuthToken = ""
	material.GatewayMasterKey = ""
	material.OnePasswordServiceAccountToken = ""
	material.VAPID.PrivateKey = ""
}

func (console *operatorConsole) readLine(prompt string) (string, error) {
	fmt.Fprint(console.stderr, prompt)
	value, err := console.input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func (console *operatorConsole) readValue(
	label string,
	fallback string,
) (string, error) {
	value, err := console.readLine(fmt.Sprintf("%s [%s]: ", label, fallback))
	if err != nil {
		return "", err
	}
	if value == "" {
		value = fallback
	}
	return strings.TrimSpace(value), nil
}

func (console *operatorConsole) readRequiredValue(label string) (string, error) {
	value, err := console.readLine(label + ": ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return strings.TrimSpace(value), nil
}

func (console *operatorConsole) confirmDefaultYes(prompt string) (bool, error) {
	value, err := console.readLine(prompt + " [Y/n]: ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, errors.New("enter y or n")
	}
}

func operatorEnvironment(overrides map[string]string) []string {
	blocked := map[string]bool{
		"CURL_CA_BUNDLE":               true,
		"DYLD_FALLBACK_FRAMEWORK_PATH": true,
		"DYLD_FALLBACK_LIBRARY_PATH":   true,
		"DYLD_FRAMEWORK_PATH":          true,
		"DYLD_INSERT_LIBRARIES":        true,
		"DYLD_LIBRARY_PATH":            true,
		"GIT_CONFIG_GLOBAL":            true,
		"GIT_CONFIG_COUNT":             true,
		"GIT_CONFIG_NOSYSTEM":          true,
		"GIT_CONFIG_PARAMETERS":        true,
		"GIT_CONFIG_SYSTEM":            true,
		"LD_LIBRARY_PATH":              true,
		"LD_PRELOAD":                   true,
		"NODE_DEBUG":                   true,
		"NODE_DEBUG_NATIVE":            true,
		"NODE_EXTRA_CA_CERTS":          true,
		"NODE_OPTIONS":                 true,
		"NODE_PATH":                    true,
		"NODE_TLS_REJECT_UNAUTHORIZED": true,
		"REQUESTS_CA_BUNDLE":           true,
		"SSL_CERT_DIR":                 true,
		"SSL_CERT_FILE":                true,
		"SSLKEYLOGFILE":                true,
	}
	for name := range overrides {
		blocked[name] = true
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides)+2)
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		privilegedPrefix := strings.HasPrefix(name, "CF_") ||
			strings.HasPrefix(name, "CLOUDFLARE_") ||
			strings.HasPrefix(name, "DYLD_") ||
			strings.HasPrefix(name, "OP_") ||
			strings.HasPrefix(name, "WRANGLER_") ||
			strings.HasPrefix(name, "GIT_CONFIG_KEY_") ||
			strings.HasPrefix(name, "GIT_CONFIG_VALUE_")
		if !blocked[name] && !privilegedPrefix {
			environment = append(environment, entry)
		}
	}
	environment = append(
		environment,
		"WRANGLER_LOG_SANITIZE=true",
		"WRANGLER_WRITE_LOGS=false",
	)
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	return environment
}
