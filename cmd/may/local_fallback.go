package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const (
	localFallbackConfigFileName = "local-fallback.json"
	localFallbackConfigSchema   = 1
	localFallbackOperationLimit = 2 * time.Minute
	localFallbackSDKSetting     = "Integrate with 1Password SDKs"
	localFallbackVaultTitle     = "Agent"
	localNotesFieldID           = "com.github.vizards.onenod.notes"
	maxLocalFallbackConfigBytes = 4096
	maxLocalSecretBytes         = 16 * 1024
	maxLocalCatalogResults      = 12
	maxLocalCatalogFields       = 64
	maxLocalSSHResults          = 64
)

type localFallbackConfig struct {
	Account       string `json:"account"`
	SchemaVersion int    `json:"schema_version"`
	VaultID       string `json:"vault_id"`
	VaultTitle    string `json:"vault_title"`
}

type localFallbackVault struct {
	ID    string
	Title string
}

type localOnePasswordBackend interface {
	ResolveAgentVault(context.Context) (localFallbackVault, error)
	SearchCatalog(context.Context, string, string) (catalogSearchResponse, error)
	ReadSecret(context.Context, string, string, string, int64) (string, error)
}

type localOnePasswordFactory func(
	context.Context,
	string,
) (localOnePasswordBackend, error)

type localSSHAgent interface {
	List() ([]*sshagent.Key, error)
	SignWithFlags(
		ssh.PublicKey,
		[]byte,
		sshagent.SignatureFlags,
	) (*ssh.Signature, error)
	Close() error
}

type localSSHAgentFactory func(context.Context) (localSSHAgent, error)

type sdkLocalOnePasswordBackend struct {
	client *onepassword.Client
}

type connectedLocalSSHAgent struct {
	net.Conn
	sshagent.ExtendedAgent
}

func runConfigureLocalFallback(args []string, deps dependencies) error {
	if len(args) == 0 {
		return errors.New("usage: may configure local-fallback <status|apply|restore> [--account name-or-uuid]")
	}
	switch args[0] {
	case "status":
		if len(args) != 1 {
			return errors.New("usage: may configure local-fallback status")
		}
		return writeLocalFallbackStatus(deps.stdout)
	case "apply":
		return applyLocalFallbackConfiguration(args[1:], deps)
	case "restore":
		if len(args) != 1 {
			return errors.New("usage: may configure local-fallback restore")
		}
		return restoreLocalFallbackConfiguration(deps.stdout)
	default:
		return errors.New("usage: may configure local-fallback <status|apply|restore> [--account name-or-uuid]")
	}
}

func applyLocalFallbackConfiguration(args []string, deps dependencies) error {
	flags := flag.NewFlagSet("configure local-fallback apply", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	account := flags.String(
		"account",
		"",
		"1Password account name shown in the desktop app, or account UUID",
	)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may configure local-fallback apply [--account name-or-uuid]")
	}
	if runtime.GOOS != "darwin" {
		return errors.New("local 1Password fallback is currently supported only on macOS")
	}
	selectedAccount := strings.TrimSpace(*account)
	if selectedAccount == "" {
		console := operatorConsole{stdin: deps.stdin, stderr: deps.stderr, stdout: deps.stdout}
		var err error
		selectedAccount, err = console.readRequiredValue(
			"1Password account name shown in the desktop app, or account UUID",
		)
		if err != nil {
			return err
		}
	}
	if err := validateLocalAccountReference(selectedAccount); err != nil {
		return err
	}

	fmt.Fprintln(deps.stdout, "Local 1Password quota-fallback plan:")
	fmt.Fprintf(deps.stdout, "  Account: %s\n", selectedAccount)
	fmt.Fprintf(deps.stdout, "  Vault: %s (fixed OneNod Vault; resolved to an ID before saving)\n", localFallbackVaultTitle)
	fmt.Fprintf(deps.stdout, "  1Password prerequisite: Settings > Developer > %s must be enabled\n", localFallbackSDKSetting)
	fmt.Fprintln(deps.stdout, "  Secret reads: official 1Password Desktop SDK, only after the Gateway reports onepassword_rate_limited")
	fmt.Fprintln(deps.stdout, "  SSH/Git signing: local 1Password SSH Agent, only after the same exact Gateway error")
	fmt.Fprintln(deps.stdout, "  Item create, patch, archive, denial, Lock mode, revocation, timeout, network failure, and generic 5xx responses never fall back.")
	fmt.Fprintln(deps.stdout, "  1Password authorizes the SDK process to the selected account for up to ten minutes of inactivity; OneNod restricts its code path to the resolved Agent Vault.")
	configPath, err := onePasswordSSHAgentConfigPath()
	if err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Before continuing, make the Agent Vault available to the 1Password SSH Agent.")
	fmt.Fprintf(deps.stdout, "Add this entry to %s without removing unrelated entries:\n\n", configPath)
	fmt.Fprintln(deps.stdout, "[[ssh-keys]]")
	fmt.Fprintf(deps.stdout, "vault = %s\n", strconv.Quote(localFallbackVaultTitle))
	fmt.Fprintf(deps.stdout, "account = %s\n\n", strconv.Quote(selectedAccount))
	fmt.Fprintf(deps.stdout, "In 1Password Settings > Developer, also enable both the SSH Agent and %s. Lock and unlock 1Password if it does not notice a newly created agent.toml file.\n", localFallbackSDKSetting)
	configured, err := promptYesNo(
		deps.stdin,
		deps.stdout,
		"I saved the agent.toml entry and enabled both 1Password integrations",
		false,
	)
	if err != nil {
		return err
	}
	if !configured {
		return errors.New("1Password local integrations were not confirmed; no OneNod fallback configuration was saved")
	}
	if _, exists, err := readOptionalRegularFile(configPath, 1<<20); err != nil {
		return err
	} else if !exists {
		return fmt.Errorf("1Password SSH Agent config does not exist at %s", configPath)
	}

	confirmed, err := promptYesNo(
		deps.stdin,
		deps.stdout,
		"Request local 1Password authorization and verify the Agent Vault now?",
		false,
	)
	if err != nil {
		return err
	}
	if !confirmed {
		return errors.New("local 1Password fallback was not configured")
	}

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()
	backend, err := localOnePasswordFactoryFor(deps)(clientCtx, selectedAccount)
	if err != nil {
		return fmt.Errorf(
			"open local 1Password Desktop SDK integration failed; verify Settings > Developer > %s is enabled: %w",
			localFallbackSDKSetting,
			err,
		)
	}
	validationCtx, validationCancel := context.WithTimeout(
		context.Background(),
		localFallbackOperationLimit,
	)
	defer validationCancel()
	vault, err := backend.ResolveAgentVault(validationCtx)
	if err != nil {
		if errors.Is(validationCtx.Err(), context.DeadlineExceeded) {
			return errors.New("resolve the local Agent Vault through 1Password timed out")
		}
		return err
	}
	if vault.Title != localFallbackVaultTitle || !onePasswordVaultIDPattern.MatchString(vault.ID) {
		return errors.New("local 1Password integration returned an invalid Agent Vault identity")
	}
	sshCatalog, err := backend.SearchCatalog(validationCtx, vault.ID, "")
	if err != nil {
		if errors.Is(validationCtx.Err(), context.DeadlineExceeded) {
			return errors.New("read Agent SSH inventory through the local 1Password SDK timed out")
		}
		return fmt.Errorf("read Agent SSH inventory through the local 1Password SDK failed: %w", err)
	}
	if err := verifyNativeSSHAgentInventory(validationCtx, deps, sshCatalog.Items); err != nil {
		return err
	}
	config := localFallbackConfig{
		Account: selectedAccount, SchemaVersion: localFallbackConfigSchema,
		VaultID: vault.ID, VaultTitle: vault.Title,
	}
	if err := writeLocalFallbackConfig(config); err != nil {
		return err
	}
	fmt.Fprintln(deps.stdout, "Configured local 1Password fallback for exact Service Account quota exhaustion.")
	fmt.Fprintln(deps.stdout, "Agents must continue to call may; this does not authorize direct op usage.")
	return nil
}

func writeLocalFallbackStatus(output io.Writer) error {
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return err
	}
	if !found {
		_, err = fmt.Fprintln(output, "Local 1Password fallback: not configured")
		return err
	}
	configPath, err := onePasswordSSHAgentConfigPath()
	if err != nil {
		return err
	}
	_, agentConfigPresent, configErr := readOptionalRegularFile(configPath, 1<<20)
	if configErr != nil {
		return configErr
	}
	socketPath, err := onePasswordSSHAgentSocketPath()
	if err != nil {
		return err
	}
	_, socketErr := os.Lstat(socketPath)
	fmt.Fprintln(output, "Local 1Password fallback: configured")
	fmt.Fprintf(output, "  account: %s\n", config.Account)
	fmt.Fprintf(output, "  vault: %s (%s)\n", config.VaultTitle, config.VaultID)
	fmt.Fprintf(output, "  Desktop SDK app: %s\n", localDesktopAppStatus())
	fmt.Fprintf(output, "  1Password SSH Agent socket: %s\n", presentStatus(socketErr == nil))
	fmt.Fprintf(output, "  agent.toml: %s (%s)\n", presentStatus(agentConfigPresent), configPath)
	return nil
}

func restoreLocalFallbackConfiguration(output io.Writer) error {
	path, err := localFallbackConfigPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("remove local 1Password fallback configuration failed")
	}
	fmt.Fprintln(output, "Disabled OneNod local 1Password fallback.")
	fmt.Fprintln(output, "The user-owned 1Password agent.toml file and 1Password app settings were not changed.")
	return nil
}

func searchCatalogWithLocalFallback(
	ctx context.Context,
	client *apiClient,
	query string,
	deps dependencies,
) (catalogSearchResponse, error) {
	response, err := searchCatalog(ctx, client, query)
	if err == nil || !isGatewayErrorCode(err, "onepassword_rate_limited") {
		return response, err
	}
	fmt.Fprintln(deps.stderr, "The remote 1Password Service Account quota is exhausted; requesting local 1Password approval on this Mac.")
	backend, config, localErr := openConfiguredLocalFallback(ctx, deps)
	if localErr != nil {
		return catalogSearchResponse{}, localFallbackUnavailable(err, localErr)
	}
	response, localErr = backend.SearchCatalog(ctx, config.VaultID, query)
	if localErr != nil {
		return catalogSearchResponse{}, localFallbackUnavailable(err, localErr)
	}
	fmt.Fprintln(deps.stderr, "Local 1Password fallback succeeded.")
	return response, nil
}

func readSecretWithLocalFallback(
	ctx context.Context,
	remoteErr error,
	deps dependencies,
	itemID string,
	fieldID string,
	expectedVersion int64,
) (string, error) {
	if !isGatewayErrorCode(remoteErr, "onepassword_rate_limited") {
		return "", remoteErr
	}
	fmt.Fprintln(deps.stderr, "The remote 1Password Service Account quota is exhausted; requesting local 1Password approval on this Mac.")
	backend, config, err := openConfiguredLocalFallback(ctx, deps)
	if err != nil {
		return "", localFallbackUnavailable(remoteErr, err)
	}
	value, err := backend.ReadSecret(
		ctx,
		config.VaultID,
		itemID,
		fieldID,
		expectedVersion,
	)
	if err != nil {
		return "", localFallbackUnavailable(remoteErr, err)
	}
	fmt.Fprintln(deps.stderr, "Local 1Password fallback succeeded. If the remote request had already entered execution, Gateway Activity may still show its Service Account quota failure.")
	return value, nil
}

func openConfiguredLocalFallback(
	ctx context.Context,
	deps dependencies,
) (localOnePasswordBackend, localFallbackConfig, error) {
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return nil, localFallbackConfig{}, err
	}
	if !found {
		return nil, localFallbackConfig{}, errors.New("local fallback is not configured; run `may configure local-fallback apply`")
	}
	backend, err := localOnePasswordFactoryFor(deps)(ctx, config.Account)
	if err != nil {
		return nil, localFallbackConfig{}, fmt.Errorf("open 1Password Desktop SDK integration failed: %w", err)
	}
	vault, err := backend.ResolveAgentVault(ctx)
	if err != nil {
		return nil, localFallbackConfig{}, err
	}
	if vault.ID != config.VaultID || vault.Title != config.VaultTitle {
		return nil, localFallbackConfig{}, errors.New("the configured local Agent Vault no longer matches 1Password")
	}
	return backend, config, nil
}

func localFallbackUnavailable(remoteErr error, localErr error) error {
	return fmt.Errorf("%w; local 1Password fallback is unavailable: %v", remoteErr, localErr)
}

func localOnePasswordFactoryFor(deps dependencies) localOnePasswordFactory {
	if deps.localOnePassword != nil {
		return deps.localOnePassword
	}
	return newSDKLocalOnePasswordBackend
}

func localSSHAgentFactoryFor(deps dependencies) localSSHAgentFactory {
	if deps.localSSHAgent != nil {
		return deps.localSSHAgent
	}
	return openOnePasswordSSHAgent
}

func newSDKLocalOnePasswordBackend(
	ctx context.Context,
	account string,
) (localOnePasswordBackend, error) {
	if err := validateLocalAccountReference(account); err != nil {
		return nil, err
	}
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo("OneNod local fallback", productVersion),
	)
	if err != nil {
		return nil, err
	}
	return &sdkLocalOnePasswordBackend{client: client}, nil
}

func (backend *sdkLocalOnePasswordBackend) ResolveAgentVault(
	ctx context.Context,
) (localFallbackVault, error) {
	defer runtime.KeepAlive(backend.client)
	decryptDetails := true
	vaults, err := backend.client.Vaults().List(
		ctx,
		onepassword.VaultListParams{DecryptDetails: &decryptDetails},
	)
	if err != nil {
		return localFallbackVault{}, fmt.Errorf("list local 1Password Vaults failed: %w", err)
	}
	matches := make([]onepassword.VaultOverview, 0, 1)
	for _, vault := range vaults {
		if vault.Title == localFallbackVaultTitle {
			matches = append(matches, vault)
		}
	}
	if len(matches) != 1 || !onePasswordVaultIDPattern.MatchString(matches[0].ID) {
		return localFallbackVault{}, fmt.Errorf("local 1Password account must contain exactly one %q Vault", localFallbackVaultTitle)
	}
	return localFallbackVault{ID: matches[0].ID, Title: matches[0].Title}, nil
}

func (backend *sdkLocalOnePasswordBackend) SearchCatalog(
	ctx context.Context,
	vaultID string,
	query string,
) (catalogSearchResponse, error) {
	defer runtime.KeepAlive(backend.client)
	if !onePasswordVaultIDPattern.MatchString(vaultID) {
		return catalogSearchResponse{}, errors.New("local Agent Vault ID is invalid")
	}
	filter := onepassword.NewItemListFilterTypeVariantByState(
		&onepassword.ItemListFilterByStateInner{Active: true, Archived: false},
	)
	overviews, err := backend.client.Items().List(ctx, vaultID, filter)
	if err != nil {
		return catalogSearchResponse{}, fmt.Errorf("list local Agent Vault items failed: %w", err)
	}
	normalized := strings.ToLower(strings.TrimSpace(query))
	limit := maxLocalCatalogResults
	matches := make([]onepassword.ItemOverview, 0, limit)
	for _, overview := range overviews {
		if overview.VaultID != vaultID || overview.State != onepassword.ItemStateActive {
			continue
		}
		if normalized == "" {
			limit = maxLocalSSHResults
			if overview.Category != onepassword.ItemCategorySSHKey {
				continue
			}
		} else if overview.ID != strings.TrimSpace(query) &&
			!strings.Contains(strings.ToLower(overview.Title), normalized) {
			continue
		}
		matches = append(matches, overview)
		if len(matches) == limit {
			break
		}
	}
	result := catalogSearchResponse{Items: make([]catalogItemResult, 0, len(matches))}
	for _, overview := range matches {
		item, err := backend.client.Items().Get(ctx, vaultID, overview.ID)
		if err != nil {
			return catalogSearchResponse{}, fmt.Errorf("read local Agent Vault item metadata failed: %w", err)
		}
		projected, err := projectLocalCatalogItem(item, vaultID)
		if err != nil {
			return catalogSearchResponse{}, err
		}
		result.Items = append(result.Items, projected)
	}
	return result, nil
}

func (backend *sdkLocalOnePasswordBackend) ReadSecret(
	ctx context.Context,
	vaultID string,
	itemID string,
	fieldID string,
	expectedVersion int64,
) (string, error) {
	defer runtime.KeepAlive(backend.client)
	if !onePasswordVaultIDPattern.MatchString(vaultID) {
		return "", errors.New("local Agent Vault ID is invalid")
	}
	if err := validateIdentifier(itemID, "item"); err != nil {
		return "", err
	}
	if err := validateIdentifier(fieldID, "field"); err != nil {
		return "", err
	}
	item, err := backend.client.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return "", errors.New("read local Agent Vault item failed")
	}
	if item.ID != itemID || item.VaultID != vaultID || int64(item.Version) != expectedVersion {
		return "", errors.New("local Agent Vault item version does not match the approved request")
	}
	var value string
	var found bool
	if fieldID == localNotesFieldID && item.Notes != "" {
		value, found = item.Notes, true
	} else {
		for _, field := range item.Fields {
			if field.ID == fieldID {
				if found {
					return "", errors.New("local Agent Vault item contains a duplicate field ID")
				}
				value, found = field.Value, true
			}
		}
	}
	if !found {
		return "", errors.New("requested field does not exist in the local Agent Vault item")
	}
	if len(value) > maxLocalSecretBytes {
		return "", errors.New("local 1Password secret exceeded the OneNod size limit")
	}
	return value, nil
}

func projectLocalCatalogItem(
	item onepassword.Item,
	vaultID string,
) (catalogItemResult, error) {
	if item.VaultID != vaultID || item.Version == 0 || item.UpdatedAt.IsZero() ||
		validateIdentifier(item.ID, "item") != nil ||
		validateText(item.Title, 256, "item title") != nil ||
		validateText(string(item.Category), 64, "item category") != nil {
		return catalogItemResult{}, errors.New("local 1Password returned invalid Agent item metadata")
	}
	fieldCount := len(item.Fields)
	if item.Notes != "" {
		fieldCount++
	}
	if fieldCount > maxLocalCatalogFields {
		return catalogItemResult{}, errors.New("local 1Password returned too many Agent item fields")
	}
	fields := make([]catalogFieldResult, 0, len(item.Fields)+1)
	for _, field := range item.Fields {
		if validateIdentifier(field.ID, "field") != nil ||
			validateText(field.Title, 128, "field label") != nil ||
			validateText(string(field.FieldType), 64, "field type") != nil {
			return catalogItemResult{}, errors.New("local 1Password returned invalid Agent field metadata")
		}
		fields = append(fields, catalogFieldResult{
			FieldID: field.ID, FieldType: string(field.FieldType), Label: field.Title,
		})
	}
	if item.Notes != "" {
		fields = append(fields, catalogFieldResult{
			FieldID: localNotesFieldID, FieldType: "Notes", Label: "notes",
		})
	}
	result := catalogItemResult{
		Category: string(item.Category), Fields: fields, ItemID: item.ID,
		Title: item.Title, UpdatedAt: item.UpdatedAt.UTC().Format(time.RFC3339Nano),
		Version: int64(item.Version),
	}
	if item.Category == onepassword.ItemCategorySSHKey {
		metadata, err := localSSHMetadata(item)
		if err != nil {
			return catalogItemResult{}, err
		}
		result.SSH = &metadata
	}
	return result, nil
}

func localSSHMetadata(item onepassword.Item) (catalogSSHMetadata, error) {
	var attributes *onepassword.SSHKeyAttributes
	for _, field := range item.Fields {
		if field.Details == nil ||
			field.Details.Type != onepassword.ItemFieldDetailsTypeVariantSSHKey {
			continue
		}
		candidate := field.Details.SSHKey()
		if candidate == nil || candidate.PublicKey == "" {
			continue
		}
		if attributes != nil {
			return catalogSSHMetadata{}, errors.New("local 1Password SSH item returned multiple public keys")
		}
		attributes = candidate
	}
	if attributes == nil {
		return catalogSSHMetadata{}, errors.New("local 1Password SSH item did not include public-key metadata")
	}
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(attributes.PublicKey))
	if err != nil || len(bytes.TrimSpace(rest)) != 0 || !isSupportedPublicKeyAlgorithm(publicKey.Type()) {
		return catalogSSHMetadata{}, errors.New("local 1Password SSH item returned an unsupported public key")
	}
	fingerprint := ssh.FingerprintSHA256(publicKey)
	if attributes.Fingerprint != "" && attributes.Fingerprint != fingerprint {
		return catalogSSHMetadata{}, errors.New("local 1Password SSH fingerprint did not match its public key")
	}
	blob := publicKey.Marshal()
	return catalogSSHMetadata{
		Algorithm: publicKey.Type(), Fingerprint: fingerprint,
		PublicKey:     strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))),
		PublicKeyBlob: base64.RawURLEncoding.EncodeToString(blob),
	}, nil
}

func verifyNativeSSHAgentInventory(
	ctx context.Context,
	deps dependencies,
	items []catalogItemResult,
) error {
	agent, err := localSSHAgentFactoryFor(deps)(ctx)
	if err != nil {
		return fmt.Errorf("open the local 1Password SSH Agent failed: %w", err)
	}
	defer agent.Close()
	keys, err := agent.List()
	if err != nil {
		return errors.New("list keys from the local 1Password SSH Agent failed")
	}
	offered := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		offered[string(key.Blob)] = struct{}{}
	}
	sshItems := 0
	for _, item := range items {
		if item.SSH == nil {
			continue
		}
		sshItems++
		blob, err := base64.RawURLEncoding.Strict().DecodeString(item.SSH.PublicKeyBlob)
		if err != nil {
			return errors.New("local Agent SSH inventory contained an invalid public key")
		}
		if _, ok := offered[string(blob)]; !ok {
			return fmt.Errorf("1Password SSH Agent does not offer Agent Vault key %s; verify the agent.toml vault and account entry", item.SSH.Fingerprint)
		}
	}
	if sshItems == 0 {
		fmt.Fprintln(deps.stdout, "The Agent Vault currently has no SSH keys; the 1Password SSH Agent socket is reachable, but key membership cannot yet be fingerprint-verified.")
	} else {
		fmt.Fprintf(deps.stdout, "Verified %d Agent Vault SSH key(s) by public fingerprint through the local 1Password SSH Agent.\n", sshItems)
	}
	return nil
}

func signWithConfiguredLocalSSHAgent(
	ctx context.Context,
	deps dependencies,
	identity servedSSHIdentity,
	algorithm string,
	data []byte,
) (sshSignConsumeResponse, error) {
	config, found, err := readLocalFallbackConfig()
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	if !found || config.VaultTitle != localFallbackVaultTitle {
		return sshSignConsumeResponse{}, errors.New("local fallback is not configured; run `may configure local-fallback apply`")
	}
	agent, err := localSSHAgentFactoryFor(deps)(ctx)
	if err != nil {
		return sshSignConsumeResponse{}, fmt.Errorf("open the local 1Password SSH Agent failed: %w", err)
	}
	defer agent.Close()
	keys, err := agent.List()
	if err != nil {
		return sshSignConsumeResponse{}, errors.New("list keys from the local 1Password SSH Agent failed")
	}
	publicKey, err := ssh.ParsePublicKey(identity.keyBlob)
	if err != nil {
		return sshSignConsumeResponse{}, errors.New("configured OneNod SSH public key is invalid")
	}
	found = false
	for _, key := range keys {
		if bytes.Equal(key.Blob, identity.keyBlob) {
			found = true
			break
		}
	}
	if !found {
		return sshSignConsumeResponse{}, errors.New("the requested Agent key is not available from the local 1Password SSH Agent; verify agent.toml")
	}
	flags, err := localSSHSignatureFlags(algorithm)
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	signature, err := agent.SignWithFlags(publicKey, data, flags)
	if err != nil {
		return sshSignConsumeResponse{}, errors.New("local 1Password SSH Agent refused the signing request")
	}
	if signature == nil || signature.Format != algorithm || len(signature.Blob) == 0 ||
		len(signature.Blob) > 16*1024 || publicKey.Verify(data, signature) != nil {
		return sshSignConsumeResponse{}, errors.New("local 1Password SSH Agent returned an invalid signature")
	}
	fmt.Fprintln(deps.stderr, "Local 1Password SSH fallback succeeded. If the remote request had already entered execution, Gateway Activity may still show its Service Account quota failure.")
	return sshSignConsumeResponse{
		Algorithm: algorithm, Fingerprint: identity.catalog.Metadata.Fingerprint,
		ItemID: identity.catalog.ItemID, OK: true,
		PublicKeyBlob: identity.catalog.Metadata.PublicKeyBlob,
		SignatureBlob: base64.RawURLEncoding.EncodeToString(signature.Blob),
		Status:        "consumed", Version: identity.catalog.Version,
	}, nil
}

func localSSHSignatureFlags(algorithm string) (sshagent.SignatureFlags, error) {
	switch algorithm {
	case "ssh-ed25519":
		return 0, nil
	case "rsa-sha2-256":
		return sshagent.SignatureFlagRsaSha256, nil
	case "rsa-sha2-512":
		return sshagent.SignatureFlagRsaSha512, nil
	default:
		return 0, errors.New("local 1Password SSH Agent does not support the requested signature algorithm")
	}
}

func openOnePasswordSSHAgent(ctx context.Context) (localSSHAgent, error) {
	path, err := onePasswordSSHAgentSocketPath()
	if err != nil {
		return nil, err
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("1Password SSH Agent socket is unavailable")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	return &connectedLocalSSHAgent{
		Conn:          connection,
		ExtendedAgent: sshagent.NewClient(connection),
	}, nil
}

func onePasswordSSHAgentSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for the 1Password SSH Agent failed")
	}
	return filepath.Join(
		home,
		"Library",
		"Group Containers",
		"2BUA8C4S2C.com.1password",
		"t",
		"agent.sock",
	), nil
}

func onePasswordSSHAgentConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for the 1Password SSH Agent config failed")
	}
	return filepath.Join(home, ".config", "1Password", "ssh", "agent.toml"), nil
}

func localFallbackConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for local fallback configuration failed")
	}
	return filepath.Join(home, userAgentDirectoryName, localFallbackConfigFileName), nil
}

func readLocalFallbackConfig() (localFallbackConfig, bool, error) {
	path, err := localFallbackConfigPath()
	if err != nil {
		return localFallbackConfig{}, false, err
	}
	encoded, exists, err := readOptionalRegularFile(path, maxLocalFallbackConfigBytes)
	if err != nil || !exists {
		return localFallbackConfig{}, exists, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		return localFallbackConfig{}, false, errors.New("local fallback configuration must be private to the current user")
	}
	var config localFallbackConfig
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || ensureDecoderEOF(decoder) != nil ||
		config.SchemaVersion != localFallbackConfigSchema ||
		config.VaultTitle != localFallbackVaultTitle ||
		!onePasswordVaultIDPattern.MatchString(config.VaultID) ||
		validateLocalAccountReference(config.Account) != nil {
		return localFallbackConfig{}, false, errors.New("local fallback configuration is invalid")
	}
	return config, true, nil
}

func writeLocalFallbackConfig(config localFallbackConfig) error {
	config.SchemaVersion = localFallbackConfigSchema
	if config.VaultTitle != localFallbackVaultTitle ||
		!onePasswordVaultIDPattern.MatchString(config.VaultID) ||
		validateLocalAccountReference(config.Account) != nil {
		return errors.New("refusing to write an invalid local fallback configuration")
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return errors.New("encode local fallback configuration failed")
	}
	encoded = append(encoded, '\n')
	path, err := localFallbackConfigPath()
	if err != nil {
		return err
	}
	return writeAtomicUserConfig(path, encoded, 0o600)
}

func validateLocalAccountReference(value string) error {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) ||
		len([]rune(value)) > 160 {
		return errors.New("1Password account name or UUID is invalid")
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("1Password account name or UUID is invalid")
		}
	}
	return nil
}

func localDesktopAppStatus() string {
	paths := []string{
		"/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(
			paths,
			filepath.Join(
				home,
				"Applications",
				"1Password.app",
				"Contents",
				"Frameworks",
				"libop_sdk_ipc_client.dylib",
			),
		)
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			return "present"
		}
	}
	return "not detected"
}

func presentStatus(present bool) string {
	if present {
		return "present"
	}
	return "not detected"
}
