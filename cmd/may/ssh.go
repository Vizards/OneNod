package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const sshPublicKeyExportUsage = "usage: may [global flags] ssh public-key export --item <id> --output <path.pub>"

type sshCatalogIdentity struct {
	ItemID   string
	Metadata catalogSSHMetadata
	Title    string
	Version  int64
}

func runSSH(args []string, config cliConfig, deps dependencies) error {
	if len(args) < 2 || args[0] != "public-key" || args[1] != "export" {
		return errors.New("usage: may [global flags] ssh public-key export ...")
	}
	flags := flag.NewFlagSet("ssh public-key export", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	itemID := flags.String("item", "", "1Password SSH Key item ID")
	output := flags.String("output", "", "new public-key file path")
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *itemID == "" || *output == "" {
		return errors.New(sshPublicKeyExportUsage)
	}
	if err := validateIdentifier(*itemID, "item"); err != nil {
		return err
	}
	identity, err := loadSSHIdentity(config, deps, *itemID)
	if err != nil {
		return err
	}
	publicLine, err := verifiedOpenSSHPublicLine(*itemID, identity.Metadata)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("create public-key file: %w", err)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(*output)
		}
	}()
	if _, err := file.WriteString(publicLine); err != nil {
		return errors.New("write public-key file failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("close public-key file failed")
	}
	complete = true
	return writeSafeJSON(deps.stdout, map[string]string{
		"fingerprint": identity.Metadata.Fingerprint,
		"item_id":     *itemID,
		"output":      *output,
		"status":      "exported",
	})
}

func loadSSHIdentity(
	config cliConfig,
	deps dependencies,
	itemID string,
) (sshCatalogIdentity, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return sshCatalogIdentity{}, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return sshCatalogIdentity{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	defer cancel()
	response, err := searchCatalogWithLocalFallback(ctx, client, itemID, deps)
	if err != nil {
		return sshCatalogIdentity{}, err
	}
	var match *catalogItemResult
	for index := range response.Items {
		if response.Items[index].ItemID != itemID {
			continue
		}
		if match != nil {
			return sshCatalogIdentity{}, errors.New("catalog returned duplicate SSH item entries")
		}
		match = &response.Items[index]
	}
	if match == nil || match.SSH == nil {
		return sshCatalogIdentity{}, errors.New("catalog item is not a supported SSH Key item")
	}
	if match.Version <= 0 {
		return sshCatalogIdentity{}, errors.New("catalog returned an invalid SSH item version")
	}
	return sshCatalogIdentity{
		ItemID: itemID, Metadata: *match.SSH, Title: match.Title, Version: match.Version,
	}, nil
}

func verifiedOpenSSHPublicLine(
	itemID string,
	metadata catalogSSHMetadata,
) (string, error) {
	if !isSupportedPublicKeyAlgorithm(metadata.Algorithm) {
		return "", errors.New("catalog returned an unsupported SSH key algorithm")
	}
	blob, err := base64.RawURLEncoding.Strict().DecodeString(metadata.PublicKeyBlob)
	if err != nil || len(blob) == 0 || len(blob) > 8*1024 {
		return "", errors.New("catalog returned an invalid SSH public-key blob")
	}
	digest := sha256.Sum256(blob)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
	if fingerprint != metadata.Fingerprint {
		return "", errors.New("catalog SSH fingerprint did not match the public-key blob")
	}
	parts := strings.Fields(metadata.PublicKey)
	if len(parts) < 2 || parts[0] != metadata.Algorithm {
		return "", errors.New("catalog returned inconsistent SSH public-key text")
	}
	textBlob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil || !bytes.Equal(textBlob, blob) {
		return "", errors.New("catalog SSH public-key text did not match its blob")
	}
	return fmt.Sprintf(
		"%s %s may:%s\n",
		metadata.Algorithm,
		base64.StdEncoding.EncodeToString(blob),
		itemID,
	), nil
}

func isSupportedPublicKeyAlgorithm(value string) bool {
	switch value {
	case "ssh-ed25519", "ssh-rsa":
		return true
	default:
		return false
	}
}
