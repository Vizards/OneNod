package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/unix"
)

const (
	sshAgentSuccessResponse  = 6
	maximumCachedIdentities  = 64
	sessionBindExtensionName = "session-bind@openssh.com"
	// Agent extension names are opaque SSH strings. Tie this private protocol
	// identifier to the canonical repository path rather than claiming an
	// unowned DNS namespace.
	versionExtensionName             = "version@github.com/Vizards/OneNod"
	sshIdentityCacheVersion          = 2
	sshIdentityCacheLegacyVersion    = 1
	sshIdentityRefreshRequestTimeout = 15 * time.Second
)

var errReadOnlySSHAgent = errors.New("may SSH agent is read-only")

type servedSSHIdentity struct {
	catalog sshCatalogIdentity
	keyBlob []byte
}

type sshSignRequest struct {
	Action               string                   `json:"action"`
	Algorithm            string                   `json:"algorithm"`
	AuthorizationSession *sshAuthorizationSession `json:"authorization_session,omitempty"`
	Client               clientObservation        `json:"client"`
	Data                 string                   `json:"data"`
	ExpectedFingerprint  string                   `json:"expected_fingerprint"`
	ExpectedVersion      int64                    `json:"expected_version"`
	IdempotencyKey       string                   `json:"idempotency_key"`
	ItemID               string                   `json:"item_id"`
	Operation            sshOperation             `json:"operation"`
}

type sshAuthorizationSession struct {
	AgentInstancePublicKey string `json:"agent_instance_public_key"`
	Proof                  string `json:"proof,omitempty"`
	ScopeID                string `json:"scope_id"`
	ScopeKind              string `json:"scope_kind"`
}

type localClientContext struct {
	Observation clientObservation
	ScopeID     string
	ScopeKind   string
}

type sshOperation struct {
	AuthenticationMethod     string `json:"authentication_method,omitempty"`
	Kind                     string `json:"kind"`
	Namespace                string `json:"namespace,omitempty"`
	RemoteUsername           string `json:"remote_username,omitempty"`
	ServerHostKeyFingerprint string `json:"server_host_key_fingerprint,omitempty"`
	Service                  string `json:"service,omitempty"`
	SessionBinding           string `json:"session_binding,omitempty"`
	SessionIDFingerprint     string `json:"session_id_fingerprint,omitempty"`
}

type sshSessionBinding struct {
	hostKeyBlob []byte
	sessionID   []byte
}

type sshAgentConnectionState struct {
	binding    *sshSessionBinding
	client     localClientContext
	identities []servedSSHIdentity
}

type approvalAgentConnection struct {
	agent approvalAgent
	state sshAgentConnectionState
}

type sshUserauthRequest struct {
	authenticationMethod string
	keyBlob              []byte
	remoteUsername       string
	service              string
	sessionID            []byte
	serverHostKeyBlob    []byte
}

type sshSignConsumeResponse struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	ItemID        string `json:"item_id"`
	OK            bool   `json:"ok"`
	PublicKeyBlob string `json:"public_key_blob"`
	RequestID     string `json:"request_id"`
	SignatureBlob string `json:"signature_blob"`
	Status        string `json:"status"`
	Version       int64  `json:"version"`
}

type sshIdentityCache struct {
	Identities []cachedSSHIdentity `json:"identities"`
	Version    int                 `json:"version"`
}

type cachedSSHIdentity struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	ItemID        string `json:"item_id"`
	PublicKey     string `json:"public_key"`
	PublicKeyBlob string `json:"public_key_blob"`
	Version       int64  `json:"version"`
}

type legacySSHIdentityCache struct {
	Identities []sshCatalogIdentity `json:"identities"`
	Version    int                  `json:"version"`
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

func runAgent(args []string, config cliConfig, deps dependencies) error {
	if len(args) != 1 {
		return errors.New("usage: may [global flags] agent <serve|status|refresh>")
	}
	switch args[0] {
	case "serve":
		return runAgentServe(config, deps)
	case "status":
		return runAgentStatus(deps)
	case "refresh":
		identities, err := refreshSSHIdentityCache(config, deps)
		if err != nil {
			return err
		}
		return writeSafeJSON(deps.stdout, map[string]any{
			"identities": len(identities),
			"socket":     defaultAgentSocket(),
			"status":     "refreshed",
		})
	default:
		return errors.New("usage: may [global flags] agent <serve|status|refresh>")
	}
}

func defaultAgentSocket() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, userAgentDirectoryName, "agent.sock")
}

func sshIdentityCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, userAgentDirectoryName, "ssh", "identities.json")
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
		resolveClient:  detectLocalClientContext,
		sessionKey:     sessionKey,
	}
	go func() {
		if _, err := loadIdentities(); err != nil {
			fmt.Fprintf(deps.stderr, "OneNod SSH inventory startup refresh is unavailable: %v\n", err)
		}
	}()
	fmt.Fprintf(deps.stderr, "Approval SSH agent is listening on %s. SSH authorization sessions remain memory-only and fail closed on restart.\n", socketPath)
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

func refreshSSHIdentityCache(
	config cliConfig,
	deps dependencies,
) ([]servedSSHIdentity, error) {
	return refreshSSHIdentityCacheAt(sshIdentityCachePath(), config, deps)
}

func refreshSSHIdentityCacheAt(
	cachePath string,
	config cliConfig,
	deps dependencies,
) ([]servedSSHIdentity, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshIdentityRefreshRequestTimeout)
	defer cancel()
	response, err := searchCatalog(ctx, client, "")
	if err != nil {
		return nil, err
	}
	catalogIdentities := make([]sshCatalogIdentity, 0)
	for _, item := range response.Items {
		if item.SSH == nil {
			continue
		}
		catalogIdentities = append(catalogIdentities, sshCatalogIdentity{
			ItemID: item.ItemID, Metadata: *item.SSH, Title: item.Title, Version: item.Version,
		})
	}
	identities, err := validateServedSSHIdentities(catalogIdentities)
	if err != nil {
		return nil, err
	}
	if err := writeSSHIdentityCache(cachePath, catalogIdentities); err != nil {
		return nil, err
	}
	return identities, nil
}

func newSSHIdentityLoader(
	cachePath string,
	config cliConfig,
	deps dependencies,
) func() ([]servedSSHIdentity, error) {
	var mutex sync.Mutex
	return func() ([]servedSSHIdentity, error) {
		mutex.Lock()
		defer mutex.Unlock()
		identities, err := readSSHIdentityCache(cachePath)
		if errors.Is(err, os.ErrNotExist) {
			return refreshSSHIdentityCacheAt(cachePath, config, deps)
		}
		return identities, err
	}
}

func validateServedSSHIdentities(
	catalogIdentities []sshCatalogIdentity,
) ([]servedSSHIdentity, error) {
	if len(catalogIdentities) > maximumCachedIdentities {
		return nil, fmt.Errorf("Agent vault contains more than %d SSH keys", maximumCachedIdentities)
	}
	seenItems := make(map[string]struct{}, len(catalogIdentities))
	seenKeys := make(map[string]struct{}, len(catalogIdentities))
	identities := make([]servedSSHIdentity, 0, len(catalogIdentities))
	for _, catalog := range catalogIdentities {
		if err := validateIdentifier(catalog.ItemID, "item"); err != nil {
			return nil, err
		}
		if catalog.Version <= 0 {
			return nil, errors.New("catalog returned an invalid SSH item version")
		}
		if _, exists := seenItems[catalog.ItemID]; exists {
			return nil, errors.New("catalog returned a duplicate SSH item")
		}
		seenItems[catalog.ItemID] = struct{}{}
		if _, err := verifiedOpenSSHPublicLine(catalog.ItemID, catalog.Metadata); err != nil {
			return nil, err
		}
		blob, err := base64.RawURLEncoding.Strict().DecodeString(catalog.Metadata.PublicKeyBlob)
		if err != nil {
			return nil, errors.New("catalog returned an invalid SSH key blob")
		}
		keyID := base64.RawStdEncoding.EncodeToString(blob)
		if _, exists := seenKeys[keyID]; exists {
			return nil, errors.New("more than one item contains the same SSH public key")
		}
		seenKeys[keyID] = struct{}{}
		identities = append(identities, servedSSHIdentity{catalog: catalog, keyBlob: blob})
	}
	return identities, nil
}

func writeSSHIdentityCache(path string, identities []sshCatalogIdentity) error {
	if path == "" {
		return errors.New("resolve SSH identity cache path failed")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errors.New("create SSH identity cache directory failed")
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return errors.New("secure SSH identity cache directory failed")
	}
	cached := make([]cachedSSHIdentity, 0, len(identities))
	for _, identity := range identities {
		cached = append(cached, cachedSSHIdentity{
			Algorithm: identity.Metadata.Algorithm, Fingerprint: identity.Metadata.Fingerprint,
			ItemID: identity.ItemID, PublicKey: identity.Metadata.PublicKey,
			PublicKeyBlob: identity.Metadata.PublicKeyBlob, Version: identity.Version,
		})
	}
	encoded, err := json.Marshal(sshIdentityCache{
		Identities: cached,
		Version:    sshIdentityCacheVersion,
	})
	if err != nil {
		return errors.New("encode SSH identity cache failed")
	}
	staged, err := os.CreateTemp(directory, ".identities-stage-*")
	if err != nil {
		return errors.New("create staged SSH identity cache failed")
	}
	stagedPath := staged.Name()
	complete := false
	defer func() {
		_ = staged.Close()
		if !complete {
			_ = os.Remove(stagedPath)
		}
	}()
	if err := staged.Chmod(0o600); err != nil {
		return errors.New("secure staged SSH identity cache failed")
	}
	if _, err := staged.Write(encoded); err != nil {
		return errors.New("write staged SSH identity cache failed")
	}
	if err := staged.Sync(); err != nil {
		return errors.New("sync staged SSH identity cache failed")
	}
	if err := staged.Close(); err != nil {
		return errors.New("close staged SSH identity cache failed")
	}
	if err := os.Rename(stagedPath, path); err != nil {
		return errors.New("install SSH identity cache failed")
	}
	complete = true
	return nil
}

func readSSHIdentityCache(path string) ([]servedSSHIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 512*1024 {
		return nil, errors.New("SSH identity cache must be a bounded mode-0600 regular file")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("read SSH identity cache failed")
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("read SSH identity cache failed")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) ||
		!openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0o600 {
		return nil, errors.New("SSH identity cache changed while opening")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 512*1024+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 512*1024 {
		return nil, errors.New("read SSH identity cache failed")
	}
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(encoded, &header) != nil {
		return nil, errors.New("SSH identity cache is invalid")
	}
	if header.Version == sshIdentityCacheLegacyVersion {
		var legacy legacySSHIdentityCache
		if err := decodeStrictSSHIdentityCache(encoded, &legacy); err != nil || legacy.Version != sshIdentityCacheLegacyVersion {
			return nil, errors.New("SSH identity cache is invalid")
		}
		if _, err := validateServedSSHIdentities(legacy.Identities); err != nil {
			return nil, err
		}
		stripped := make([]sshCatalogIdentity, 0, len(legacy.Identities))
		for _, identity := range legacy.Identities {
			identity.Title = ""
			stripped = append(stripped, identity)
		}
		if err := writeSSHIdentityCache(path, stripped); err != nil {
			return nil, errors.New("migrate legacy SSH identity cache failed")
		}
		return validateServedSSHIdentities(stripped)
	}
	var cache sshIdentityCache
	if err := decodeStrictSSHIdentityCache(encoded, &cache); err != nil || cache.Version != sshIdentityCacheVersion {
		return nil, errors.New("SSH identity cache is invalid")
	}
	catalog := make([]sshCatalogIdentity, 0, len(cache.Identities))
	for _, identity := range cache.Identities {
		catalog = append(catalog, sshCatalogIdentity{
			ItemID: identity.ItemID,
			Metadata: catalogSSHMetadata{
				Algorithm: identity.Algorithm, Fingerprint: identity.Fingerprint,
				PublicKey: identity.PublicKey, PublicKeyBlob: identity.PublicKeyBlob,
			},
			Version: identity.Version,
		})
	}
	return validateServedSSHIdentities(catalog)
}

func decodeStrictSSHIdentityCache(encoded []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing SSH identity cache data")
	}
	return nil
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

func (agent approvalAgent) signForConnection(
	state *sshAgentConnectionState,
	keyBlob []byte,
	data []byte,
	flags uint32,
) (*ssh.Signature, error) {
	if len(keyBlob) == 0 {
		return nil, errors.New("invalid key blob")
	}
	if len(data) == 0 || len(data) > 64*1024 {
		return nil, errors.New("invalid signing payload")
	}
	var err error
	if len(state.identities) == 0 {
		state.identities, err = agent.currentIdentities()
		if err != nil {
			return nil, err
		}
	}
	identity := findIdentity(state.identities, keyBlob)
	if identity == nil {
		return nil, errors.New("requested SSH identity is not configured")
	}
	algorithm, err := signatureAlgorithm(identity.catalog.Metadata.Algorithm, flags)
	if err != nil {
		return nil, err
	}
	operation := sshOperationForPayload(data, keyBlob, state.binding)
	result, err := requestSshSignature(
		agent.context,
		agent.config,
		agent.deps,
		*identity,
		state.client,
		agent.sessionKey,
		operation,
		algorithm,
		data,
	)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(result.SignatureBlob)
	if err != nil || len(signature) == 0 || len(signature) > 16*1024 {
		return nil, errors.New("gateway returned an invalid SSH signature")
	}
	publicKey, err := ssh.ParsePublicKey(identity.keyBlob)
	if err != nil {
		return nil, errors.New("configured SSH public key is invalid")
	}
	if err := publicKey.Verify(data, &ssh.Signature{Format: result.Algorithm, Blob: signature}); err != nil {
		return nil, errors.New("gateway returned an SSH signature that did not verify")
	}
	return &ssh.Signature{Format: result.Algorithm, Blob: signature}, nil
}

func findIdentity(identities []servedSSHIdentity, keyBlob []byte) *servedSSHIdentity {
	for index := range identities {
		if bytes.Equal(identities[index].keyBlob, keyBlob) {
			return &identities[index]
		}
	}
	return nil
}

func sshOperationForPayload(
	data []byte,
	keyBlob []byte,
	binding *sshSessionBinding,
) sshOperation {
	if namespace, ok := parseSSHSIGNamespace(data); ok && namespace == "git" {
		return sshOperation{Kind: "git.ssh-signature", Namespace: "git"}
	}
	request, err := parseSSHUserauthRequest(data)
	if err != nil || !bytes.Equal(request.keyBlob, keyBlob) {
		return sshOperation{Kind: "ssh.opaque-signature"}
	}
	operation := sshOperation{
		AuthenticationMethod: request.authenticationMethod,
		Kind:                 "ssh.authentication",
		RemoteUsername:       request.remoteUsername,
		Service:              request.service,
		SessionBinding:       "unavailable",
		SessionIDFingerprint: byteFingerprint(request.sessionID),
	}
	if binding != nil && verifySSHUserauthBinding(request, *binding, keyBlob) == nil {
		hostKey, err := ssh.ParsePublicKey(binding.hostKeyBlob)
		if err == nil {
			operation.ServerHostKeyFingerprint = ssh.FingerprintSHA256(hostKey)
			operation.SessionBinding = "verified"
		}
	}
	return operation
}

func parseSSHSIGNamespace(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, []byte("SSHSIG")) {
		return "", false
	}
	reader := wireReader{value: data[6:]}
	namespace, err := reader.string()
	if err != nil || len(namespace) == 0 || len(namespace) > 64 {
		return "", false
	}
	if _, err := reader.string(); err != nil {
		return "", false
	}
	hashAlgorithm, err := reader.string()
	if err != nil || (string(hashAlgorithm) != "sha256" && string(hashAlgorithm) != "sha512") {
		return "", false
	}
	digest, err := reader.string()
	if err != nil || len(digest) == 0 || !reader.done() {
		return "", false
	}
	return string(namespace), true
}

func requestSshSignature(
	ctx context.Context,
	config cliConfig,
	deps dependencies,
	identity servedSSHIdentity,
	localClient localClientContext,
	sessionKey ed25519.PrivateKey,
	operation sshOperation,
	algorithm string,
	data []byte,
) (sshSignConsumeResponse, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	request := sshSignRequest{
		Action:              "ssh.sign",
		Algorithm:           algorithm,
		Client:              localClient.Observation,
		Data:                base64.RawURLEncoding.EncodeToString(data),
		ExpectedFingerprint: identity.catalog.Metadata.Fingerprint,
		ExpectedVersion:     identity.catalog.Version,
		IdempotencyKey:      idempotencyKey,
		ItemID:              identity.catalog.ItemID,
		Operation:           operation,
	}
	if err := attachSshAuthorizationSession(&request, localClient, sessionKey); err != nil {
		return sshSignConsumeResponse{}, err
	}
	var created requestStatusResponse
	createContext, cancelCreate := context.WithTimeout(ctx, gatewayRequestTimeout)
	err = client.doJSON(createContext, http.MethodPost, "/v1/requests", request, &created)
	cancelCreate()
	if err != nil {
		return sshSignConsumeResponse{}, fmt.Errorf("create SSH approval request failed: %w", err)
	}
	if created.RequestID == "" || created.ExpiresAt == "" || created.PollToken == "" {
		return sshSignConsumeResponse{}, errors.New("gateway returned an invalid SSH approval response")
	}
	status := normalizeStatus(created.Status)
	if status == "pending" {
		fmt.Fprintf(deps.stderr, "SSH sign request %s submitted; waiting for human approval.\n", created.RequestID)
		pollContext, cancelPoll, contextError := approvalWaitContextFrom(ctx, created.ExpiresAt, config.timeout)
		if contextError != nil {
			return sshSignConsumeResponse{}, fmt.Errorf(
				"prepare SSH request %s approval wait failed: %w",
				created.RequestID,
				contextError,
			)
		}
		status, err = pollStatus(pollContext, config.pollInterval, func() (string, error) {
			var current requestStatusResponse
			path := "/v1/requests/" + url.PathEscape(created.RequestID) + "/status"
			if err := client.doPollingJSON(pollContext, path, created.PollToken, &current); err != nil {
				return "", err
			}
			if current.RequestID != "" && current.RequestID != created.RequestID {
				return "", errors.New("gateway status response changed the request ID")
			}
			return current.Status, nil
		})
		cancelPoll()
		if err != nil {
			return sshSignConsumeResponse{}, fmt.Errorf(
				"poll SSH request %s status failed: %w",
				created.RequestID,
				err,
			)
		}
	}
	if !isAuthorizedStatus(status) {
		return sshSignConsumeResponse{}, fmt.Errorf(
			"SSH request %s reached unexpected status %q",
			created.RequestID,
			status,
		)
	}
	var consumed sshSignConsumeResponse
	consumeContext, cancelConsume := context.WithTimeout(ctx, gatewayRequestTimeout)
	err = client.doJSON(
		consumeContext,
		http.MethodPost,
		"/v1/requests/"+url.PathEscape(created.RequestID)+"/consume",
		consumeRequest{},
		&consumed,
	)
	cancelConsume()
	if err != nil {
		return sshSignConsumeResponse{}, fmt.Errorf(
			"consume SSH request %s failed: %w",
			created.RequestID,
			err,
		)
	}
	if !consumed.OK || consumed.RequestID != created.RequestID ||
		normalizeStatus(consumed.Status) != "consumed" ||
		consumed.ItemID != identity.catalog.ItemID ||
		consumed.Version != identity.catalog.Version ||
		consumed.Fingerprint != identity.catalog.Metadata.Fingerprint ||
		consumed.Algorithm != algorithm ||
		consumed.PublicKeyBlob != identity.catalog.Metadata.PublicKeyBlob {
		return sshSignConsumeResponse{}, fmt.Errorf(
			"gateway returned a mismatched SSH signature response for request %s",
			created.RequestID,
		)
	}
	return consumed, nil
}

func attachSshAuthorizationSession(
	request *sshSignRequest,
	localClient localClientContext,
	sessionKey ed25519.PrivateKey,
) error {
	if len(sessionKey) != ed25519.PrivateKeySize ||
		localClient.ScopeID == "" ||
		(localClient.ScopeKind != "application" && localClient.ScopeKind != "terminal-session") {
		return nil
	}
	request.AuthorizationSession = &sshAuthorizationSession{
		AgentInstancePublicKey: base64.RawURLEncoding.EncodeToString(
			sessionKey.Public().(ed25519.PublicKey),
		),
		ScopeID:   localClient.ScopeID,
		ScopeKind: localClient.ScopeKind,
	}
	proofMaterial, err := canonicalJSON(request)
	if err != nil {
		return errors.New("encode SSH authorization session proof failed")
	}
	request.AuthorizationSession.Proof = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(sessionKey, proofMaterial),
	)
	return nil
}

func signatureAlgorithm(keyAlgorithm string, flags uint32) (string, error) {
	if keyAlgorithm == "ssh-rsa" {
		switch sshagent.SignatureFlags(flags) {
		case sshagent.SignatureFlagRsaSha256:
			return "rsa-sha2-256", nil
		case sshagent.SignatureFlagRsaSha512:
			return "rsa-sha2-512", nil
		default:
			return "", errors.New("RSA-SHA1 and ambiguous RSA signature flags are not supported")
		}
	}
	if flags != 0 {
		return "", errors.New("signature flags do not match the SSH key algorithm")
	}
	if keyAlgorithm == "ssh-ed25519" {
		return keyAlgorithm, nil
	}
	return "", errors.New("SSH key algorithm is not supported")
}

func parseSessionBindExtension(payload []byte) (sshSessionBinding, error) {
	reader := wireReader{value: payload}
	hostKeyBlob, err := reader.string()
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind host key")
	}
	sessionID, err := reader.string()
	if err != nil || len(sessionID) == 0 {
		return sshSessionBinding{}, errors.New("invalid session-bind identifier")
	}
	signatureBlob, err := reader.string()
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind signature")
	}
	forwarded, err := reader.byte()
	if err != nil || forwarded != 0 || !reader.done() {
		return sshSessionBinding{}, errors.New("forwarded or malformed session binding is not allowed")
	}
	hostKey, err := ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind public key")
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(signatureBlob, &signature); err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind signature encoding")
	}
	if err := hostKey.Verify(sessionID, &signature); err != nil {
		return sshSessionBinding{}, errors.New("session-bind signature did not verify")
	}
	return sshSessionBinding{
		hostKeyBlob: append([]byte(nil), hostKeyBlob...),
		sessionID:   append([]byte(nil), sessionID...),
	}, nil
}

func verifySessionBindExtension(payload []byte) bool {
	_, err := parseSessionBindExtension(payload)
	return err == nil
}

func parseSSHUserauthRequest(data []byte) (sshUserauthRequest, error) {
	reader := wireReader{value: data}
	sessionID, err := reader.string()
	if err != nil || len(sessionID) == 0 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth session identifier")
	}
	message, err := reader.byte()
	if err != nil || message != 50 {
		return sshUserauthRequest{}, errors.New("SSH signing payload is not a userauth request")
	}
	username, err := reader.string()
	if err != nil || len(username) == 0 || len(username) > 256 || containsControl(string(username)) {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth username")
	}
	service, err := reader.string()
	if err != nil || string(service) != "ssh-connection" {
		return sshUserauthRequest{}, errors.New("unsupported SSH userauth service")
	}
	method, err := reader.string()
	if err != nil || (string(method) != "publickey" &&
		string(method) != "publickey-hostbound-v00@openssh.com") {
		return sshUserauthRequest{}, errors.New("unsupported SSH userauth method")
	}
	hasSignature, err := reader.byte()
	if err != nil || hasSignature != 1 {
		return sshUserauthRequest{}, errors.New("SSH userauth request did not ask for a signature")
	}
	publicKeyAlgorithm, err := reader.string()
	if err != nil || len(publicKeyAlgorithm) == 0 || len(publicKeyAlgorithm) > 128 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth public-key algorithm")
	}
	keyBlob, err := reader.string()
	if err != nil || len(keyBlob) == 0 || len(keyBlob) > 8*1024 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth public key")
	}
	key, err := ssh.ParsePublicKey(keyBlob)
	if err != nil || !userauthAlgorithmMatchesKey(string(publicKeyAlgorithm), key.Type()) {
		return sshUserauthRequest{}, errors.New("SSH userauth algorithm did not match its public key")
	}
	var serverHostKeyBlob []byte
	if string(method) == "publickey-hostbound-v00@openssh.com" {
		serverHostKeyBlob, err = reader.string()
		if err != nil || len(serverHostKeyBlob) == 0 || len(serverHostKeyBlob) > 8*1024 {
			return sshUserauthRequest{}, errors.New("invalid host-bound SSH server key")
		}
	}
	if !reader.done() {
		return sshUserauthRequest{}, errors.New("SSH userauth request contained trailing data")
	}
	return sshUserauthRequest{
		authenticationMethod: string(method),
		keyBlob:              append([]byte(nil), keyBlob...),
		remoteUsername:       string(username),
		service:              string(service),
		sessionID:            append([]byte(nil), sessionID...),
		serverHostKeyBlob:    append([]byte(nil), serverHostKeyBlob...),
	}, nil
}

func userauthAlgorithmMatchesKey(algorithm, keyType string) bool {
	if keyType == "ssh-rsa" {
		return algorithm == "ssh-rsa" || algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512"
	}
	return algorithm == keyType
}

func verifySSHUserauthBinding(
	request sshUserauthRequest,
	binding sshSessionBinding,
	requestedKeyBlob []byte,
) error {
	if !bytes.Equal(request.sessionID, binding.sessionID) {
		return errors.New("SSH userauth session did not match its verified session binding")
	}
	if !bytes.Equal(request.keyBlob, requestedKeyBlob) {
		return errors.New("SSH userauth payload selected a different key")
	}
	if request.authenticationMethod == "publickey-hostbound-v00@openssh.com" &&
		!bytes.Equal(request.serverHostKeyBlob, binding.hostKeyBlob) {
		return errors.New("host-bound SSH userauth payload selected a different server")
	}
	return nil
}

func byteFingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

type wireReader struct {
	offset int
	value  []byte
}

func (reader *wireReader) byte() (byte, error) {
	if reader.offset >= len(reader.value) {
		return 0, io.ErrUnexpectedEOF
	}
	value := reader.value[reader.offset]
	reader.offset++
	return value, nil
}

func (reader *wireReader) uint32() (uint32, error) {
	if reader.offset+4 > len(reader.value) {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint32(reader.value[reader.offset : reader.offset+4])
	reader.offset += 4
	return value, nil
}

func (reader *wireReader) string() ([]byte, error) {
	length, err := reader.uint32()
	if err != nil || uint64(length) > uint64(len(reader.value)-reader.offset) {
		return nil, io.ErrUnexpectedEOF
	}
	value := reader.value[reader.offset : reader.offset+int(length)]
	reader.offset += int(length)
	return value, nil
}

func (reader *wireReader) done() bool { return reader.offset == len(reader.value) }

func writeWireString(writer io.Writer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write(value)
}
