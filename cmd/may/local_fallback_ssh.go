package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

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

type connectedLocalSSHAgent struct {
	net.Conn
	sshagent.ExtendedAgent
}

func localSSHAgentFactoryFor(deps dependencies) localSSHAgentFactory {
	if deps.localSSHAgent != nil {
		return deps.localSSHAgent
	}
	return openOnePasswordSSHAgent
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
