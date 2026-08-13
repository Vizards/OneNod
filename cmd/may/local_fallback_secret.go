package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"
)

const (
	localNotesFieldID      = "com.github.vizards.onenod.notes"
	maxLocalSecretBytes    = 16 * 1024
	maxLocalCatalogResults = 12
	maxLocalCatalogFields  = 64
	maxLocalSSHResults     = 64
)

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

type sdkLocalOnePasswordBackend struct {
	client *onepassword.Client
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
