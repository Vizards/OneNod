package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func operatorReceiptPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for operator receipt failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "operator", "deployment.json"), nil
}

func writeOperatorDeploymentReceipt(receipt operatorDeploymentReceipt) error {
	path, err := operatorReceiptPath()
	if err != nil {
		return err
	}
	if err := ensurePrivateInstallDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	receipt.SchemaVersion = operatorReceiptSchema
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return err
	}
	receipt.Channel = string(channel)
	return writeAtomicPrivateJSON(path, receipt)
}

func readOperatorDeploymentReceipt() (*operatorDeploymentReceipt, error) {
	path, err := operatorReceiptPath()
	if err != nil {
		return nil, err
	}
	var receipt operatorDeploymentReceipt
	if err := readStrictPrivateJSON(path, &receipt); err != nil {
		return nil, err
	}
	if receipt.SchemaVersion != operatorReceiptSchema || !cloudflareAccountIDPattern.MatchString(receipt.AccountID) ||
		!dnsLabelPattern.MatchString(receipt.AccountSubdomain) || !validProductVersion(receipt.ReleaseVersion) ||
		!commitPattern.MatchString(receipt.SourceCommit) || !digestPattern.MatchString(receipt.DeploymentArtifactSHA) ||
		!uuidPattern.MatchString(receipt.ExecutorVersionID) || !uuidPattern.MatchString(receipt.GatewayVersionID) ||
		!onePasswordVaultIDPattern.MatchString(receipt.OnePasswordVaultID) {
		return nil, errors.New("operator deployment receipt is invalid")
	}
	channel, err := normalizedReceiptChannel(receipt.Channel, receipt.ReleaseVersion)
	if err != nil {
		return nil, errors.New("operator deployment receipt has an invalid release channel")
	}
	receipt.Channel = string(channel)
	if _, err := parseGatewayOrigin(receipt.Origin); err != nil || receipt.RPID != strings.TrimPrefix(receipt.Origin, "https://") {
		return nil, errors.New("operator deployment receipt has an invalid immutable Origin")
	}
	return &receipt, nil
}

func writeAtomicPrivateJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("encode private receipt failed")
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	staged, err := os.CreateTemp(directory, ".receipt-")
	if err != nil {
		return errors.New("stage private receipt failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if staged.Chmod(0o600) != nil {
		staged.Close()
		return errors.New("secure private receipt failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write private receipt failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("activate private receipt failed")
	}
	return nil
}

func readStrictPrivateJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return errors.New("private receipt is missing, unsafe, or invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return errors.New("read private receipt failed")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || ensureDecoderEOF(decoder) != nil {
		return errors.New("private receipt JSON is invalid")
	}
	return nil
}
