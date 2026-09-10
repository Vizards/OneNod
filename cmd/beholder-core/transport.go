package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	leasePurposeSSH     = "ssh"
	leasePurposeGitSign = "git-sign"
	outcomeBindingTTL   = 24 * time.Hour
)

type outcomeBinding struct {
	targetSHA256 string
	processRef   string
	requesterUID uint32
	expiresAt    time.Time
}

type transportBinding struct {
	purpose         string
	threadRef       string
	turnRef         string
	toolUseRef      string
	transcriptPath  string
	cwd             string
	envelope        evidenceEnvelope
	requester       processIdentity
	agentProcessRef string
	expiresAt       time.Time
}

type transportCoordinator struct {
	mu               sync.Mutex
	broker           *broker
	proxyRoot        string
	outcomeStateRoot string
	outcomeQueueRoot string
	upstreamPath     string
	bindingTTL       time.Duration
	proxyTimeout     time.Duration
	pending          map[string]transportBinding
	bindings         map[string]transportBinding
	used             map[string]time.Time
	proxies          map[string]*boundAgentProxy
	leaseRoots       map[string]string
	outcomes         map[string]outcomeBinding
	outcomeUsed      map[string]outcomeUsedBinding
	outcomeQueue     map[string]queuedHumanOutcome
	outcomeWake      chan struct{}
	outcomeStop      chan struct{}
	outcomeWorker    sync.WaitGroup
	closed           bool
	agentIdentity    trustedExecutableIdentity
	agentInstanceRef string
	agentUID         uint32
}

func newTransportCoordinator(
	broker *broker,
	proxyRoot, upstreamPath string,
	trustedAgentPath, trustedAgentSHA256 string,
	bindingTTL, proxyTimeout time.Duration,
	outcomeStateRoots ...string,
) (*transportCoordinator, error) {
	if broker == nil || !filepath.IsAbs(proxyRoot) || !filepath.IsAbs(upstreamPath) ||
		bindingTTL <= 0 || bindingTTL > 5*time.Minute ||
		proxyTimeout <= 0 || proxyTimeout > 15*time.Minute {
		return nil, errors.New("invalid transport coordinator configuration")
	}
	if len(outcomeStateRoots) > 2 {
		return nil, errors.New("invalid outcome state configuration")
	}
	outcomeStateRoot := ""
	outcomeQueueRoot := ""
	if len(outcomeStateRoots) == 1 {
		outcomeStateRoot = outcomeStateRoots[0]
		if err := initializeOutcomeStateRoot(outcomeStateRoot); err != nil {
			return nil, err
		}
	} else if len(outcomeStateRoots) == 2 {
		outcomeStateRoot = outcomeStateRoots[0]
		outcomeQueueRoot = outcomeStateRoots[1]
		if err := initializeOutcomeStateRoot(outcomeStateRoot); err != nil {
			return nil, err
		}
		if err := initializeOutcomeQueueRoot(outcomeQueueRoot); err != nil {
			return nil, err
		}
	}
	info, err := os.Stat(proxyRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("transport proxy root is writable")
	}
	coordinator := &transportCoordinator{
		broker: broker, proxyRoot: filepath.Clean(proxyRoot), upstreamPath: filepath.Clean(upstreamPath),
		outcomeStateRoot: outcomeStateRoot, outcomeQueueRoot: outcomeQueueRoot,
		bindingTTL: bindingTTL, proxyTimeout: proxyTimeout,
		pending: map[string]transportBinding{}, bindings: map[string]transportBinding{},
		used: map[string]time.Time{}, proxies: map[string]*boundAgentProxy{},
		leaseRoots: map[string]string{}, outcomes: map[string]outcomeBinding{}, outcomeUsed: map[string]outcomeUsedBinding{},
		outcomeQueue: map[string]queuedHumanOutcome{},
	}
	if err := coordinator.loadOutcomeStates(broker.now().UTC()); err != nil {
		return nil, err
	}
	if err := coordinator.loadOutcomeQueue(broker.now().UTC()); err != nil {
		return nil, err
	}
	if broker.trustMode == "production" {
		identity, err := captureTrustedExecutable(trustedAgentPath, trustedAgentSHA256, false)
		if err != nil {
			return nil, err
		}
		connection, err := net.DialUnix(
			"unix", nil, &net.UnixAddr{Name: upstreamPath, Net: "unix"},
		)
		if err != nil {
			return nil, errors.New("pin trusted OneNod Agent failed")
		}
		peerPID, peerErr := unixPeerPID(connection)
		_ = connection.Close()
		if peerErr != nil {
			return nil, errors.New("pin trusted OneNod Agent failed")
		}
		chain, err := captureProcessChain(peerPID)
		if err != nil || len(chain.Nodes) == 0 || !identity.matches(chain.Nodes[0].Path) {
			return nil, errors.New("trusted OneNod Agent identity mismatch")
		}
		coordinator.agentIdentity = identity
		coordinator.agentInstanceRef = broker.processRef(chain.Nodes[0])
		coordinator.agentUID = chain.Nodes[0].UID
	}
	if coordinator.outcomeQueueRoot != "" {
		coordinator.outcomeWake = make(chan struct{}, 1)
		coordinator.outcomeStop = make(chan struct{})
		coordinator.outcomeWorker.Add(1)
		go coordinator.runOutcomeWorker()
		coordinator.wakeOutcomeWorker()
	}
	return coordinator, nil
}

func (coordinator *transportCoordinator) issueLease(
	threadID, purpose string,
	peer processChain,
) wireResponse {
	if coordinator == nil || !safeJoinKey(threadID) || !validLeasePurpose(purpose) ||
		len(peer.Nodes) == 0 {
		return transportError("task-binding-unverified")
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return transportError("binding-unavailable")
	}
	nonce := hex.EncodeToString(nonceBytes)
	clear(nonceBytes)
	observation := requestObservation{
		ThreadID: threadID, Nonce: nonce, Surface: "ssh-agent-transport",
		Operation: "transport." + purpose, TargetKind: "ssh-agent-lease", TargetID: "purpose-" + purpose,
		ObservedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		EnvironmentPresence: environmentPresence{CodexThreadID: true},
	}
	checked := coordinator.broker.checkRequest(observation, peer)
	defer checked.clearTransient()
	threadID = ""
	if !checked.Accepted || checked.Envelope == nil {
		if checked.ErrorCode != nil {
			return transportError(*checked.ErrorCode)
		}
		return transportError("task-binding-unverified")
	}
	leaseRoot, err := os.MkdirTemp(coordinator.proxyRoot, "l-")
	if err != nil {
		return transportError("binding-unavailable")
	}
	leaseMode := os.FileMode(0o700)
	if os.Geteuid() == 0 {
		leaseMode = 0o711
	}
	if os.Chmod(leaseRoot, leaseMode) != nil {
		_ = os.Remove(leaseRoot)
		return transportError("binding-unavailable")
	}
	proxy, err := startBoundAgentProxy(leaseRoot, coordinator.upstreamPath, []byte(nonce), peer.Nodes[0])
	if err != nil {
		_ = os.Remove(leaseRoot)
		return transportError("binding-unavailable")
	}
	nonceRef := coordinator.broker.keyedRef("transport-nonce", []byte(nonce))
	now := coordinator.broker.now().UTC()
	binding := transportBinding{
		purpose: purpose, threadRef: checked.Envelope.Attribution.ThreadRef,
		turnRef:        checked.contextTurnRef,
		toolUseRef:     checked.contextToolUseRef,
		transcriptPath: checked.decisionTranscriptPath,
		cwd:            checked.decisionCWD,
		envelope:       *checked.Envelope,
		requester:      peer.Nodes[0], expiresAt: now.Add(coordinator.bindingTTL),
	}
	coordinator.mu.Lock()
	coordinator.expireLocked(now)
	if coordinator.closed {
		coordinator.mu.Unlock()
		proxy.close()
		_ = os.Remove(leaseRoot)
		return transportError("binding-unavailable")
	}
	coordinator.pending[nonceRef] = binding
	coordinator.proxies[nonceRef] = proxy
	coordinator.leaseRoots[nonceRef] = leaseRoot
	coordinator.mu.Unlock()
	go coordinator.observeProxy(nonceRef, proxy)
	return wireResponse{
		SchemaVersion: protocolSchemaVersion,
		Accepted:      true,
		AgentSocket:   proxy.socketPath,
	}
}

// issueClientLease gives a trusted OneNod shim a one-use nonce while leaving
// the SSH Agent connection in the requesting user process. That local process
// is an authorized transparent OneNod transport, so application attribution
// continues through the real ssh/git ancestry instead of stopping at this
// root-owned Core daemon.
func (coordinator *transportCoordinator) issueClientLease(
	threadID, purpose string,
	peer processChain,
) wireResponse {
	if coordinator == nil || !safeJoinKey(threadID) || !validLeasePurpose(purpose) || len(peer.Nodes) == 0 {
		return transportError("task-binding-unverified")
	}
	if bound := coordinator.broker.registerLatestExecutionRoot(threadID, purpose, peer); !bound.Accepted {
		if bound.ErrorCode != nil {
			return bound
		}
		return transportError("task-binding-unverified")
	}
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return transportError("binding-unavailable")
	}
	nonce := hex.EncodeToString(nonceBytes)
	checked := coordinator.broker.checkRequest(requestObservation{
		ThreadID: threadID, Nonce: nonce, Surface: "ssh-agent-transport",
		Operation: "transport." + purpose, TargetKind: "ssh-agent-client-lease", TargetID: "purpose-" + purpose,
		ObservedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		EnvironmentPresence: environmentPresence{CodexThreadID: true},
	}, peer)
	threadID = ""
	if !checked.Accepted || checked.Envelope == nil {
		clear(nonceBytes)
		checked.clearTransient()
		if checked.ErrorCode != nil {
			return transportError(*checked.ErrorCode)
		}
		return transportError("task-binding-unverified")
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	nonceRef := coordinator.broker.keyedRef("transport-nonce", nonceBytes)
	clear(nonceBytes)
	now := coordinator.broker.now().UTC()
	binding := transportBinding{
		purpose: purpose, threadRef: checked.Envelope.Attribution.ThreadRef,
		turnRef:        checked.contextTurnRef,
		toolUseRef:     checked.contextToolUseRef,
		transcriptPath: checked.decisionTranscriptPath,
		cwd:            checked.decisionCWD,
		envelope:       *checked.Envelope,
		requester:      peer.Nodes[0], expiresAt: now.Add(coordinator.bindingTTL),
	}
	checked.clearTransient()
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.expireLocked(now)
	if coordinator.closed {
		return transportError("binding-unavailable")
	}
	coordinator.pending[nonceRef] = binding
	return wireResponse{
		SchemaVersion:  protocolSchemaVersion,
		Accepted:       true,
		BindingAttempt: checked.BindingAttempt,
		Binding:        encodedNonce,
	}
}

func (coordinator *transportCoordinator) consumeBinding(
	encodedNonce string,
	peer processChain,
) wireResponse {
	if coordinator == nil || len(peer.Nodes) == 0 {
		return transportError("binding-unavailable")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(encodedNonce)
	encodedNonce = ""
	if err != nil || len(nonce) < 16 || len(nonce) > 128 {
		clear(nonce)
		return transportError("binding-invalid")
	}
	nonceRef := coordinator.broker.keyedRef("transport-nonce", nonce)
	clear(nonce)
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.expireLocked(now)
	if coordinator.closed {
		return transportError("binding-unavailable")
	}
	if _, replayed := coordinator.used[nonceRef]; replayed {
		return transportError("binding-replay")
	}
	binding, found := coordinator.pending[nonceRef]
	if !found {
		return transportError("binding-missing")
	}
	if !coordinator.validAgentPeer(peer, binding.requester.UID) {
		return transportError("agent-identity-mismatch")
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return transportError("binding-unavailable")
	}
	token := hex.EncodeToString(tokenBytes)
	clear(tokenBytes)
	bindingRef := coordinator.broker.keyedRef("transport-binding", []byte(token))
	delete(coordinator.pending, nonceRef)
	coordinator.used[nonceRef] = now.Add(coordinator.bindingTTL)
	binding.agentProcessRef = coordinator.broker.processRef(peer.Nodes[0])
	binding.expiresAt = now.Add(coordinator.bindingTTL)
	coordinator.bindings[bindingRef] = binding
	return wireResponse{
		SchemaVersion: protocolSchemaVersion,
		Accepted:      true,
		Binding:       token,
	}
}

func (coordinator *transportCoordinator) observeAgentOperation(
	bindingToken string,
	target operationTarget,
	peer processChain,
	requesterDeviceIDs ...string,
) wireResponse {
	if coordinator == nil || !safeBindingToken(bindingToken) || !validOperationTarget(target) ||
		len(peer.Nodes) == 0 {
		return transportError("operation-binding-invalid")
	}
	bindingRef := coordinator.broker.keyedRef("transport-binding", []byte(bindingToken))
	bindingToken = ""
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	coordinator.expireLocked(now)
	if _, replayed := coordinator.used[bindingRef]; replayed {
		coordinator.mu.Unlock()
		return transportError("operation-replay")
	}
	binding, found := coordinator.bindings[bindingRef]
	if !found {
		coordinator.mu.Unlock()
		return transportError("operation-binding-missing")
	}
	delete(coordinator.bindings, bindingRef)
	coordinator.used[bindingRef] = now.Add(coordinator.bindingTTL)
	coordinator.mu.Unlock()
	if !coordinator.validAgentPeer(peer, binding.requester.UID) ||
		coordinator.broker.processRef(peer.Nodes[0]) != binding.agentProcessRef {
		return transportError("agent-instance-mismatch")
	}
	if !operationMatchesPurpose(binding.purpose, target) {
		return transportError("operation-target-mismatch")
	}
	context, result := coordinator.broker.acquireDecisionContext(binding.turnRef, binding.toolUseRef)
	if !result.Accepted {
		return transportError(result.ErrorCode)
	}
	checked := wireResponse{
		SchemaVersion: protocolSchemaVersion, Accepted: true, Envelope: &binding.envelope,
		contextTurnRef: binding.turnRef, contextToolUseRef: binding.toolUseRef,
		decisionContext: &context, decisionTranscriptPath: binding.transcriptPath, decisionCWD: binding.cwd,
	}
	requesterDeviceID := ""
	if len(requesterDeviceIDs) == 1 {
		requesterDeviceID = requesterDeviceIDs[0]
	}
	disposition, evidenceID, authorization := coordinator.broker.runGatekeeperWithEvidence(
		&checked, target, requesterDeviceID,
	)
	coordinator.registerOutcome(evidenceID, target, peer.Nodes[0])
	return wireResponse{
		SchemaVersion:     protocolSchemaVersion,
		Accepted:          true,
		Disposition:       disposition,
		EvidenceID:        evidenceID,
		Authorization:     authorization,
		Envelope:          checked.Envelope,
		ModelCalled:       checked.ModelCalled,
		DecisionErrorCode: checked.DecisionErrorCode,
	}
}

func (coordinator *transportCoordinator) checkDirectOperation(
	threadID, nonce string,
	target operationTarget,
	peer processChain,
	requesterDeviceIDs ...string,
) wireResponse {
	if coordinator == nil || !safeJoinKey(threadID) || !safeJoinKey(nonce) ||
		!validOperationTarget(target) || len(peer.Nodes) == 0 {
		return transportError("direct-operation-invalid")
	}
	bound := coordinator.broker.registerLatestExecutionRoot(threadID, "direct", peer)
	encodedTarget, err := json.Marshal(target)
	if err != nil {
		return transportError("direct-operation-invalid")
	}
	targetDigest := sha256.Sum256(encodedTarget)
	clear(encodedTarget)
	observation := requestObservation{
		ThreadID: threadID, Nonce: nonce, Surface: target.Surface,
		Operation: target.Operation, TargetKind: target.TargetKind,
		TargetID:            hex.EncodeToString(targetDigest[:]),
		ObservedAt:          time.Now().UTC().Format(time.RFC3339Nano),
		EnvironmentPresence: environmentPresence{CodexThreadID: true},
	}
	var checked wireResponse
	if bound.Accepted {
		checked = coordinator.broker.checkRequest(observation, peer)
	} else {
		envelope := coordinator.broker.baseEnvelope(observation, peer)
		envelope.Attribution.BindingAttempt = bound.BindingAttempt
		if bound.BindingAttempt != nil {
			envelope.Attribution.LateBindingCandidateCount = bound.BindingAttempt.EligibleCount
		}
		code := "task-binding-unverified"
		if bound.ErrorCode != nil {
			code = *bound.ErrorCode
		}
		checked = coordinator.broker.escalateResponse(wireResponse{
			SchemaVersion: protocolSchemaVersion, Envelope: &envelope, BindingAttempt: bound.BindingAttempt,
		}, code)
	}
	threadID, nonce = "", ""
	if !checked.Accepted {
		evidenceID := coordinator.broker.recordShadowEscalationWithEvidence(&checked, target)
		coordinator.registerOutcome(evidenceID, target, peer.Nodes[0])
		if checked.ErrorCode != nil {
			response := transportError(*checked.ErrorCode)
			response.EvidenceID = evidenceID
			response.BindingAttempt = checked.BindingAttempt
			return response
		}
		response := transportError("task-binding-unverified")
		response.EvidenceID = evidenceID
		return response
	}
	requesterDeviceID := ""
	if len(requesterDeviceIDs) == 1 {
		requesterDeviceID = requesterDeviceIDs[0]
	}
	checked.Disposition, checked.EvidenceID, checked.Authorization =
		coordinator.broker.runGatekeeperWithEvidence(&checked, target, requesterDeviceID)
	coordinator.registerOutcome(checked.EvidenceID, target, peer.Nodes[0])
	return checked
}

func (coordinator *transportCoordinator) registerOutcome(
	evidenceID string,
	target operationTarget,
	requester processIdentity,
) {
	if coordinator == nil || evidenceID == "" || !validOperationTarget(target) {
		return
	}
	targetSHA256, ok := operationTargetSHA256(target)
	if !ok {
		return
	}
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	coordinator.expireLocked(now)
	if coordinator.closed || coordinator.outcomes[evidenceID].targetSHA256 != "" ||
		coordinator.outcomeUsed[evidenceID].expiresAt.After(now) {
		return
	}
	binding := outcomeBinding{
		targetSHA256: targetSHA256, processRef: rawProcessRef(requester), requesterUID: requester.UID,
		expiresAt: now.Add(outcomeBindingTTL),
	}
	coordinator.outcomes[evidenceID] = binding
	// Keep the same-process retry path even if the durable observation state is
	// temporarily unwritable. The evidence auditor will still expose a restart
	// gap; shadow observability must not alter the authorization result.
	_ = coordinator.persistPendingOutcome(evidenceID, binding)
}

func (coordinator *transportCoordinator) recordHumanOutcome(
	evidenceID string,
	target operationTarget,
	outcome humanOutcome,
	peer processChain,
) wireResponse {
	if coordinator == nil || coordinator.broker == nil ||
		(coordinator.broker.gatekeeper == nil && coordinator.outcomeQueueRoot == "") ||
		len(peer.Nodes) == 0 || evidenceID == "" || evidenceID != outcome.EvidenceID ||
		!validOperationTarget(target) || !validHumanOutcome(outcome) {
		return transportError("human-outcome-invalid")
	}
	targetSHA256, ok := operationTargetSHA256(target)
	if !ok {
		return transportError("human-outcome-invalid")
	}
	if outcome.OperationTargetSHA256 != targetSHA256 {
		return transportError("human-outcome-binding-mismatch")
	}
	outcomeDigest, ok := outcomeSHA256(outcome)
	if !ok {
		return transportError("human-outcome-invalid")
	}
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	coordinator.expireLocked(now)
	if used, found := coordinator.outcomeUsed[evidenceID]; found {
		matched := used.targetSHA256 == targetSHA256 && used.outcomeSHA256 == outcomeDigest
		coordinator.mu.Unlock()
		if matched {
			return wireResponse{SchemaVersion: protocolSchemaVersion, Accepted: true, EvidenceID: evidenceID}
		}
		return transportError("human-outcome-binding-mismatch")
	}
	binding, found := coordinator.outcomes[evidenceID]
	if !found {
		coordinator.mu.Unlock()
		return transportError("human-outcome-binding-missing")
	}
	if binding.targetSHA256 != targetSHA256 {
		coordinator.mu.Unlock()
		return transportError("human-outcome-target-mismatch")
	}
	if !coordinator.validOutcomePeer(binding, peer) {
		coordinator.mu.Unlock()
		return transportError("human-outcome-peer-mismatch")
	}
	if coordinator.outcomeQueueRoot != "" {
		if queued, exists := coordinator.outcomeQueue[evidenceID]; exists {
			matched := queued.binding.targetSHA256 == targetSHA256 && queued.outcomeSHA256 == outcomeDigest
			coordinator.mu.Unlock()
			if matched {
				coordinator.wakeOutcomeWorker()
				return wireResponse{SchemaVersion: protocolSchemaVersion, Accepted: true, EvidenceID: evidenceID}
			}
			return transportError("human-outcome-binding-mismatch")
		}
		queued := queuedHumanOutcome{
			binding: binding, outcomeSHA256: outcomeDigest, outcome: outcome,
		}
		if err := coordinator.persistQueuedHumanOutcome(evidenceID, queued); err != nil {
			coordinator.mu.Unlock()
			return transportError("human-outcome-queue-write-failed")
		}
		coordinator.outcomeQueue[evidenceID] = queued
		coordinator.mu.Unlock()
		coordinator.wakeOutcomeWorker()
		return wireResponse{SchemaVersion: protocolSchemaVersion, Accepted: true, EvidenceID: evidenceID}
	}
	coordinator.mu.Unlock()
	if err := coordinator.broker.gatekeeper.recordOutcome(outcome); err != nil {
		return transportError(gatekeeperOutcomeFailureCode(err))
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if current, exists := coordinator.outcomes[evidenceID]; exists &&
		current.targetSHA256 == binding.targetSHA256 && current.processRef == binding.processRef {
		if coordinator.persistRecordedOutcome(evidenceID, binding, outcomeDigest) != nil {
			return transportError("human-outcome-state-write-failed")
		}
		delete(coordinator.outcomes, evidenceID)
		coordinator.outcomeUsed[evidenceID] = outcomeUsedBinding{
			targetSHA256: targetSHA256, outcomeSHA256: outcomeDigest, expiresAt: binding.expiresAt,
		}
	}
	return wireResponse{
		SchemaVersion: protocolSchemaVersion, Accepted: true, EvidenceID: evidenceID,
	}
}

func (coordinator *transportCoordinator) validOutcomePeer(binding outcomeBinding, peer processChain) bool {
	if coordinator == nil || len(peer.Nodes) == 0 || peer.Nodes[0].UID != binding.requesterUID ||
		peer.Nodes[0].RealUID != binding.requesterUID {
		return false
	}
	if coordinator.broker.trustMode == "production" {
		return peer.Nodes[0].UID == coordinator.agentUID && coordinator.agentIdentity.matches(peer.Nodes[0].Path)
	}
	return binding.processRef == rawProcessRef(peer.Nodes[0])
}

func operationTargetSHA256(target operationTarget) (string, bool) {
	encoded, err := json.Marshal(target)
	if err != nil {
		return "", false
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func (coordinator *transportCoordinator) validAgentPeer(peer processChain, expectedUID uint32) bool {
	if len(peer.Nodes) == 0 || len(peer.Roles) != len(peer.Nodes) ||
		peer.Nodes[0].UID != expectedUID || peer.Nodes[0].RealUID != expectedUID {
		return false
	}
	if coordinator.broker.trustMode == "production" {
		return peer.Nodes[0].UID == coordinator.agentUID &&
			coordinator.agentIdentity.matches(peer.Nodes[0].Path) &&
			coordinator.broker.processRef(peer.Nodes[0]) == coordinator.agentInstanceRef
	}
	base := strings.ToLower(filepath.Base(peer.Nodes[0].Path))
	return base == "may" || strings.HasPrefix(base, "may-") ||
		peer.Roles[0] == "onenod-requester"
}

func (coordinator *transportCoordinator) observeProxy(nonceRef string, proxy *boundAgentProxy) {
	_ = proxy.wait(coordinator.proxyTimeout)
	proxy.close()
	coordinator.mu.Lock()
	root := coordinator.leaseRoots[nonceRef]
	delete(coordinator.pending, nonceRef)
	delete(coordinator.proxies, nonceRef)
	delete(coordinator.leaseRoots, nonceRef)
	coordinator.mu.Unlock()
	if root != "" {
		_ = os.Remove(root)
	}
}

func (coordinator *transportCoordinator) expireLocked(now time.Time) {
	for ref, binding := range coordinator.pending {
		if !binding.expiresAt.After(now) {
			delete(coordinator.pending, ref)
		}
	}
	for ref, binding := range coordinator.bindings {
		if !binding.expiresAt.After(now) {
			delete(coordinator.bindings, ref)
		}
	}
	for ref, expiresAt := range coordinator.used {
		if !expiresAt.After(now) {
			delete(coordinator.used, ref)
		}
	}
	for evidenceID, binding := range coordinator.outcomes {
		if !binding.expiresAt.After(now) {
			delete(coordinator.outcomes, evidenceID)
			delete(coordinator.outcomeQueue, evidenceID)
			coordinator.removeOutcomeState(evidenceID)
			coordinator.removeQueuedHumanOutcome(evidenceID)
		}
	}
	for evidenceID, binding := range coordinator.outcomeUsed {
		if !binding.expiresAt.After(now) {
			delete(coordinator.outcomeUsed, evidenceID)
			coordinator.removeOutcomeState(evidenceID)
		}
	}
}

func (coordinator *transportCoordinator) close() {
	if coordinator == nil {
		return
	}
	coordinator.mu.Lock()
	if coordinator.closed {
		coordinator.mu.Unlock()
		return
	}
	coordinator.closed = true
	outcomeStop := coordinator.outcomeStop
	proxies := make([]*boundAgentProxy, 0, len(coordinator.proxies))
	roots := make([]string, 0, len(coordinator.leaseRoots))
	for _, proxy := range coordinator.proxies {
		proxies = append(proxies, proxy)
	}
	for _, root := range coordinator.leaseRoots {
		roots = append(roots, root)
	}
	coordinator.mu.Unlock()
	if outcomeStop != nil {
		close(outcomeStop)
		coordinator.outcomeWorker.Wait()
	}
	coordinator.mu.Lock()
	clear(coordinator.pending)
	clear(coordinator.bindings)
	clear(coordinator.used)
	clear(coordinator.proxies)
	clear(coordinator.leaseRoots)
	clear(coordinator.outcomes)
	clear(coordinator.outcomeUsed)
	clear(coordinator.outcomeQueue)
	coordinator.mu.Unlock()
	for _, proxy := range proxies {
		proxy.close()
	}
	for _, root := range roots {
		_ = os.Remove(root)
	}
}

func validLeasePurpose(purpose string) bool {
	return purpose == leasePurposeSSH || purpose == leasePurposeGitSign
}

func operationMatchesPurpose(purpose string, target operationTarget) bool {
	if target.Surface != "ssh-agent" || target.TargetKind != "ssh-key" {
		return false
	}
	switch purpose {
	case leasePurposeGitSign:
		return target.Operation == "git.ssh-signature"
	case leasePurposeSSH:
		return target.Operation == "ssh.authentication" || target.Operation == "ssh.opaque-signature"
	default:
		return false
	}
}

func safeBindingToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func transportError(code string) wireResponse {
	called := false
	return wireResponse{
		ModelCalled:   &called,
		SchemaVersion: protocolSchemaVersion,
		Disposition:   "escalate",
		ErrorCode:     stringPointer(code),
	}
}
