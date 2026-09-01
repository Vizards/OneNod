package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const (
	sshAgentSuccessResponse = 6
	// Agent extension names are opaque SSH strings. Tie this private protocol
	// identifier to the canonical repository path rather than claiming an
	// unowned DNS namespace.
	versionExtensionName = "version@github.com/Vizards/OneNod"
)

var errReadOnlySSHAgent = errors.New("may SSH agent is read-only")

type sshAgentConnectionState struct {
	beholderBinding string
	binding         *sshSessionBinding
	client          localClientContext
	identities      []servedSSHIdentity
}

type approvalAgentConnection struct {
	agent approvalAgent
	state sshAgentConnectionState
}

type agentRuntimeVersion struct {
	ClientProtocol int    `json:"client_protocol"`
	ReleaseTag     string `json:"release_tag"`
	SourceCommit   string `json:"source_commit"`
	Version        string `json:"version"`
}

type approvalAgent struct {
	config         cliConfig
	context        context.Context
	deps           dependencies
	identities     []servedSSHIdentity
	loadIdentities func() ([]servedSSHIdentity, error)
	resolveClient  func(net.Conn) localClientContext
	sessionKey     ed25519.PrivateKey
}

func defaultAgentSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, userAgentDirectoryName, "agent.sock")
}

func runAgentServe(config cliConfig, deps dependencies) error {
	socketPath := defaultAgentSocket()
	cachePath := sshIdentityCachePath()
	if socketPath == "" || cachePath == "" {
		return errors.New("resolve may agent paths failed")
	}
	listener, err := listenApprovalAgent(socketPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(socketPath)
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate SSH Agent session key failed")
	}
	loadIdentities := newSSHIdentityLoader(cachePath, config, deps)
	agent := approvalAgent{
		config:         config,
		context:        ctx,
		deps:           deps,
		loadIdentities: loadIdentities,
		resolveClient: func(connection net.Conn) localClientContext {
			evidence, evidenceErr := sshPeerApplicationEvidence(connection)
			if evidenceErr != nil {
				return unknownLocalClientContext()
			}
			return resolveObservedApplication(
				deps.applicationResolver,
				config.origin,
				deps.keychain.slot,
				evidence,
			)
		},
		sessionKey: sessionKey,
	}
	go func() {
		if _, err := loadIdentities(); err != nil {
			fmt.Fprintf(deps.stderr, "OneNod SSH inventory startup refresh is unavailable: %v\n", err)
		}
	}()
	fmt.Fprintf(deps.stderr, "Approval SSH agent is listening on %s. SSH Agent instance state remains memory-only, and remembered approvals fail closed on restart.\n", socketPath)
	return agent.serveListener(ctx, listener)
}

func runAgentStatus(deps dependencies) error {
	socketPath := defaultAgentSocket()
	if socketPath == "" {
		return errors.New("resolve may agent socket failed")
	}
	version, err := queryRunningAgentVersion(socketPath)
	if err != nil {
		return err
	}
	identities, cacheErr := readSSHIdentityCache(sshIdentityCachePath())
	result := map[string]any{
		"running": true, "socket": socketPath,
		"version": version.Version, "source_commit": version.SourceCommit,
		"release_tag": version.ReleaseTag, "client_protocol": version.ClientProtocol,
	}
	if cacheErr == nil {
		result["identities"] = len(identities)
		result["inventory_cache"] = "ready"
		result["inventory_refresh"] = "manual"
	} else {
		result["identities"] = 0
		result["inventory_cache"] = "unavailable"
	}
	return writeSafeJSON(deps.stdout, result)
}

func listenApprovalAgent(path string) (net.Listener, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, errors.New("create agent socket directory failed")
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("agent socket directory must be accessible only to the current user")
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket agent path")
		}
		connection, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, errors.New("another approval agent is already listening")
		}
		if err := os.Remove(path); err != nil {
			return nil, errors.New("remove stale agent socket failed")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect agent socket path failed")
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, errors.New("listen on agent socket failed")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, errors.New("secure agent socket permissions failed")
	}
	return listener, nil
}

func (agent approvalAgent) serveListener(ctx context.Context, listener net.Listener) error {
	var connections sync.Map
	var group sync.WaitGroup
	shutdownComplete := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
			connections.Range(func(key, _ any) bool {
				_ = key.(net.Conn).Close()
				return true
			})
		case <-shutdownComplete:
		}
	}()
	defer func() {
		close(shutdownComplete)
		_ = listener.Close()
		connections.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		group.Wait()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("accept SSH agent connection failed")
		}
		connections.Store(connection, struct{}{})
		group.Add(1)
		go func() {
			defer group.Done()
			defer connections.Delete(connection)
			agent.serveConnection(connection)
		}()
	}
}

func (agent approvalAgent) serveConnection(connection net.Conn) {
	defer connection.Close()
	client := unknownLocalClientContext()
	if agent.resolveClient != nil {
		client = agent.resolveClient(connection)
	}
	defer client.Evidence.close()
	_ = sshagent.ServeAgent(&approvalAgentConnection{
		agent: agent,
		state: sshAgentConnectionState{client: client},
	}, connection)
}

func (connection *approvalAgentConnection) List() ([]*sshagent.Key, error) {
	identities, err := connection.agent.currentIdentities()
	if err != nil {
		return nil, err
	}
	connection.state.identities = identities
	keys := make([]*sshagent.Key, 0, len(identities))
	for _, identity := range identities {
		keys = append(keys, &sshagent.Key{
			Format:  identity.catalog.Metadata.Algorithm,
			Blob:    append([]byte(nil), identity.keyBlob...),
			Comment: "may:" + identity.catalog.Metadata.Fingerprint,
		})
	}
	return keys, nil
}

func (connection *approvalAgentConnection) Sign(
	key ssh.PublicKey,
	data []byte,
) (*ssh.Signature, error) {
	return connection.SignWithFlags(key, data, 0)
}

func (connection *approvalAgentConnection) SignWithFlags(
	key ssh.PublicKey,
	data []byte,
	flags sshagent.SignatureFlags,
) (*ssh.Signature, error) {
	if key == nil {
		return nil, errors.New("requested SSH identity is missing")
	}
	return connection.agent.signForConnection(
		&connection.state,
		key.Marshal(),
		data,
		uint32(flags),
	)
}

func (connection *approvalAgentConnection) Add(sshagent.AddedKey) error {
	return errReadOnlySSHAgent
}

func (connection *approvalAgentConnection) Remove(ssh.PublicKey) error {
	return errReadOnlySSHAgent
}

func (connection *approvalAgentConnection) RemoveAll() error {
	return errReadOnlySSHAgent
}

func (connection *approvalAgentConnection) Lock([]byte) error {
	return errReadOnlySSHAgent
}

func (connection *approvalAgentConnection) Unlock([]byte) error {
	return errReadOnlySSHAgent
}

func (connection *approvalAgentConnection) Signers() ([]ssh.Signer, error) {
	return nil, errors.New("may SSH agent signers are available only through the agent protocol")
}

func (connection *approvalAgentConnection) Extension(
	extensionType string,
	contents []byte,
) ([]byte, error) {
	switch extensionType {
	case versionExtensionName:
		if len(contents) != 0 {
			return nil, errors.New("version extension does not accept request data")
		}
		return agentVersionExtensionResponse()
	case sessionBindExtensionName:
		binding, err := parseSessionBindExtension(contents)
		if err != nil {
			return nil, err
		}
		connection.state.binding = &binding
		return []byte{sshAgentSuccessResponse}, nil
	case beholderBindingExtensionName:
		if connection.state.beholderBinding != "" {
			return nil, errors.New("Beholder binding is already set for this Agent connection")
		}
		nonce, err := parseBeholderBindingExtension(contents)
		if err != nil {
			return nil, err
		}
		binding, err := consumeBeholderAgentBinding(connection.agent.deps, nonce)
		clear(nonce)
		if err != nil {
			return nil, err
		}
		connection.state.beholderBinding = binding
		return []byte{sshAgentSuccessResponse}, nil
	default:
		return nil, sshagent.ErrExtensionUnsupported
	}
}

func agentVersionExtensionResponse() ([]byte, error) {
	encoded, err := json.Marshal(agentRuntimeVersion{
		ClientProtocol: mayClientProtocol, ReleaseTag: releaseTag,
		SourceCommit: sourceCommit, Version: productVersion,
	})
	if err != nil {
		return nil, err
	}
	response := []byte{sshAgentSuccessResponse}
	return append(response, ssh.Marshal(struct{ Metadata []byte }{encoded})...), nil
}

func queryRunningAgentVersion(socketPath string) (agentRuntimeVersion, error) {
	connection, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return agentRuntimeVersion{}, errors.New("may SSH Agent is not running")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	response, err := sshagent.NewClient(connection).Extension(versionExtensionName, nil)
	if err != nil || len(response) < 2 || response[0] != sshAgentSuccessResponse {
		return agentRuntimeVersion{}, errors.New("running may SSH Agent does not support the version extension")
	}
	reader := wireReader{value: response[1:]}
	encoded, err := reader.string()
	if err != nil || !reader.done() || len(encoded) > 8*1024 {
		return agentRuntimeVersion{}, errors.New("running may SSH Agent returned invalid version metadata")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var version agentRuntimeVersion
	if decoder.Decode(&version) != nil || ensureDecoderEOF(decoder) != nil ||
		version.ClientProtocol <= 0 || version.Version == "" || version.SourceCommit == "" {
		return agentRuntimeVersion{}, errors.New("running may SSH Agent returned invalid version metadata")
	}
	return version, nil
}

func (agent approvalAgent) currentIdentities() ([]servedSSHIdentity, error) {
	if agent.loadIdentities != nil {
		return agent.loadIdentities()
	}
	return append([]servedSSHIdentity(nil), agent.identities...), nil
}
