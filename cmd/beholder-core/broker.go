package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type broker struct {
	transportLog          *transportLog
	promptLedger          *promptLedger
	mu                    sync.Mutex
	key                   []byte
	epochRef              string
	sessionRoot           string
	trustMode             string
	trustedHookPath       string
	trustedHook           trustedExecutableIdentity
	allowedUID            uint32
	socketOwnerUID        int
	claimTTL              time.Duration
	now                   func() time.Time
	processAlive          func(processIdentity) bool
	contexts              *transientContextStore
	gatekeeper            *shadowGatekeeperClient
	authority             *beholderAuthority
	claimsByToolRef       map[string]*hostClaim
	claimRefByTool        map[string]string
	claimRefByExecution   map[string]string
	nonces                map[string]string
	executionContextBytes int
	executionSequence     uint64
}

const maximumHostObservations = 2048

func newBroker(
	sessionRoot, trustMode, trustedHookPath, trustedHookSHA256 string,
	claimTTL time.Duration,
) (*broker, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return newBrokerWithKey(
		sessionRoot, trustMode, trustedHookPath, trustedHookSHA256,
		claimTTL, key, time.Now,
	)
}

func newBrokerWithKey(
	sessionRoot, trustMode, trustedHookPath, trustedHookSHA256 string,
	claimTTL time.Duration,
	key []byte,
	now func() time.Time,
) (*broker, error) {
	if !filepath.IsAbs(sessionRoot) || (trustMode != "fixture" && trustMode != "production") ||
		claimTTL <= 0 || claimTTL > 5*time.Minute || len(key) < 32 || now == nil {
		return nil, errors.New("invalid broker configuration")
	}
	if trustMode == "production" && (!filepath.IsAbs(trustedHookPath) || trustedHookSHA256 == "") {
		return nil, errors.New("trusted hook path required")
	}
	var trustedHook trustedExecutableIdentity
	if trustMode == "production" {
		var err error
		trustedHook, err = captureTrustedExecutable(trustedHookPath, trustedHookSHA256, true)
		if err != nil {
			return nil, err
		}
	}
	keyCopy := append([]byte(nil), key...)
	contexts, err := newTransientContextStoreWithKey(30*time.Minute, claimTTL, keyCopy, now)
	if err != nil {
		return nil, err
	}
	broker := &broker{
		key: keyCopy, sessionRoot: filepath.Clean(sessionRoot), trustMode: trustMode,
		trustedHookPath: filepath.Clean(trustedHookPath), trustedHook: trustedHook,
		claimTTL: claimTTL, now: now, processAlive: kernelProcessAlive,
		contexts: contexts, claimsByToolRef: map[string]*hostClaim{}, claimRefByTool: map[string]string{},
		claimRefByExecution: map[string]string{},
		nonces:              map[string]string{},
		allowedUID:          uint32(os.Getuid()), socketOwnerUID: -1,
	}
	broker.epochRef = broker.keyedRef("broker-epoch", keyCopy)
	return broker, nil
}

func (broker *broker) configureProductionUser(uid int) error {
	if broker == nil || broker.trustMode != "production" || uid <= 0 || uint64(uid) > uint64(^uint32(0)) {
		return errors.New("invalid production user")
	}
	broker.allowedUID = uint32(uid)
	broker.socketOwnerUID = uid
	return nil
}

func (broker *broker) close() {
	if broker == nil {
		return
	}
	broker.contexts.close()
	if broker.authority != nil {
		broker.authority.close()
		broker.authority = nil
	}
	broker.mu.Lock()
	defer broker.mu.Unlock()
	clear(broker.key)
	for _, claim := range broker.claimsByToolRef {
		if claim.executionContext != nil {
			claim.executionContext.clear()
		}
	}
	clear(broker.claimsByToolRef)
	clear(broker.claimRefByTool)
	clear(broker.claimRefByExecution)
	clear(broker.nonces)
}

func (broker *broker) registerPrompt(observation promptObservation, peer processChain) wireResponse {
	response := wireResponse{SchemaVersion: protocolSchemaVersion}
	if code := validatePromptObservation(observation); code != "" {
		return responseWithError(response, code)
	}
	_, _, code := broker.validateHookPeer(peer)
	if code != "" {
		return responseWithError(response, code)
	}
	if !pathWithin(broker.sessionRoot, observation.TranscriptPath) {
		return responseWithError(response, "transcript-outside-session-root")
	}
	metadataID, _, err := readSessionMetadata(observation.TranscriptPath)
	if err != nil {
		return responseWithError(response, "session-metadata-unavailable")
	}
	if metadataID != observation.SessionID {
		return responseWithError(response, "hook-evidence-conflict")
	}
	result := broker.contexts.registerPrompt(observation.SessionID, observation.TurnID, observation.Prompt)
	if !result.Accepted {
		return responseWithError(response, result.ErrorCode)
	}
	if err := broker.promptLedger.remember(observation); err != nil {
		broker.contexts.completeTurn(observation.SessionID, observation.TurnID)
		return responseWithError(response, "prompt-proof-persistence-failed")
	}
	response.Accepted = true
	return response
}

func (broker *broker) registerHost(observation hostObservation, peer processChain) wireResponse {
	response := wireResponse{SchemaVersion: protocolSchemaVersion}
	if code := validateHostObservation(observation); code != "" {
		return responseWithError(response, code)
	}
	ownerClass, userWritable, code := broker.validateHookPeer(peer)
	if code != "" {
		return responseWithError(response, code)
	}
	runtimeIndex := firstRoleIndex(peer, "codex-runtime")
	metadataMatched, cwdMatch, recentOps, transcriptError := validateTranscript(
		broker.sessionRoot, observation.TranscriptPath, observation.SessionID, observation.TurnID, observation.CWD,
	)
	if transcriptError != "" {
		return responseWithError(response, transcriptError)
	}
	transcriptInfo, statErr := os.Stat(observation.TranscriptPath)
	if statErr != nil || !transcriptInfo.Mode().IsRegular() {
		return responseWithError(response, "session-metadata-unavailable")
	}
	contextResult := broker.contexts.registerToolInput(
		observation.SessionID,
		observation.TurnID,
		observation.ToolUseID,
		observation.ToolInput,
	)
	if !contextResult.Accepted && contextResult.ErrorCode == "prompt-binding-missing" {
		if code := broker.restorePrompt(observation); code != "" {
			return responseWithError(response, code)
		}
		contextResult = broker.contexts.registerToolInput(observation.SessionID, observation.TurnID, observation.ToolUseID, observation.ToolInput)
	}
	if !contextResult.Accepted {
		if contextResult.ErrorCode == "tool-input-observation-conflict" {
			broker.mu.Lock()
			if source := broker.claimsByToolRef[broker.keyedRef("tool-selector", []byte(observation.ToolUseID))]; source != nil {
				source.conflictCode = contextResult.ErrorCode
				broker.invalidateExecutionCandidatesLocked(source, contextResult.ErrorCode)
			}
			broker.mu.Unlock()
		}
		return responseWithError(response, contextResult.ErrorCode)
	}
	registeredAt := broker.now().UTC()
	hookAnchorRef := broker.processRef(peer.Nodes[1])
	runtimeBindingRef := broker.processRef(peer.Nodes[runtimeIndex])
	toolRef := broker.keyedRef("tool-selector", []byte(observation.ToolUseID))
	claim := &hostClaim{
		threadRef:     broker.keyedRef("thread", []byte(observation.SessionID)),
		turnRef:       broker.keyedRef("turn", []byte(observation.TurnID)),
		toolUseRef:    broker.keyedRef("tool-use", []byte(observation.ToolUseID)),
		hookAnchorRef: hookAnchorRef, runtimeBindingRef: runtimeBindingRef,
		registeredAt:          registeredAt,
		sessionCandidateCount: 1, metadataMatched: metadataMatched,
		transcriptInfo: transcriptInfo, runtimeIdentity: peer.Nodes[runtimeIndex],
		hostCWD: observation.CWD, transcriptPath: observation.TranscriptPath,
		recentOps:      append([]string(nil), recentOps...),
		contextTurnRef: contextResult.turnRef, contextToolUseRef: contextResult.toolRef,
		host: hostEvidence{
			HookEventName: observation.HookEventName, ToolName: observation.ToolName,
			Model: observation.Model, PermissionMode: observation.PermissionMode,
			CWDRelation: cwdMatch, PeerAncestryDepth: len(peer.Nodes),
			PeerAncestryRoles:    append([]string(nil), peer.Roles...),
			ExecutableOwnerClass: ownerClass, ExecutableUserWritable: userWritable,
			CodeIdentityVerified: broker.trustMode == "production",
			ToolInputFeatures:    observation.ToolInputFeatures,
		},
		toolRef: toolRef,
	}

	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.expireLocked(broker.now().UTC())
	if existingToolRef, found := broker.claimRefByTool[claim.contextToolUseRef]; found {
		existing, exists := broker.claimsByToolRef[existingToolRef]
		if !exists || !sameHostRegistration(existing, claim) {
			if exists {
				existing.conflictCode = "tool-registration-conflict"
				broker.invalidateExecutionCandidatesLocked(existing, existing.conflictCode)
			}
			return responseWithError(response, "tool-registration-conflict")
		}
		// Idempotent delivery must not move the causal observation timestamp.
		response.Accepted = true
		response.ToolRef = existing.toolRef
		return response
	}
	if _, collision := broker.claimsByToolRef[toolRef]; collision {
		return responseWithError(response, "tool-ref-unavailable")
	}
	if len(broker.claimsByToolRef) >= maximumHostObservations {
		return responseWithError(response, "observation-capacity-exceeded")
	}
	if !broker.contexts.pinRefs(claim.contextTurnRef, claim.contextToolUseRef) {
		return responseWithError(response, "context-binding-missing")
	}
	broker.claimsByToolRef[toolRef] = claim
	broker.claimRefByTool[claim.contextToolUseRef] = toolRef
	response.Accepted = true
	response.ToolRef = toolRef
	return response
}

// registerExecutionRoot retains compatibility with the earlier selector-based
// transport. New managed hooks are observation-only and use
// registerLatestExecutionRoot instead, so Codex can display the original Bash
// command without a registrar prefix. The selector is correlation data, not a
// bearer credential: later requesters never send it back. They must instead be
// live descendants of this kernel-observed PID/start-time root.
func (broker *broker) registerExecutionRoot(toolRef, threadID string, peer processChain) wireResponse {
	response := wireResponse{SchemaVersion: protocolSchemaVersion}
	if !safeToolRef(toolRef) || !safeJoinKey(threadID) || len(peer.Nodes) < 3 ||
		len(peer.Roles) != len(peer.Nodes) || peer.Roles[1] != "shell" {
		return responseWithError(response, "execution-root-unverified")
	}
	_, _, code := broker.validateHookPeer(peer)
	if code != "" {
		return responseWithError(response, code)
	}
	runtimeIndex := firstRoleIndex(peer, "codex-runtime")
	if runtimeIndex < 0 {
		return responseWithError(response, "runtime-binding-mismatch")
	}
	executionRootRef := broker.processRef(peer.Nodes[1])
	runtimeBindingRef := broker.processRef(peer.Nodes[runtimeIndex])
	threadRef := broker.keyedRef("thread", []byte(threadID))
	now := broker.now().UTC()

	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.expireLocked(now)
	claim, found := broker.claimsByToolRef[toolRef]
	if !found {
		return responseWithError(response, "tool-ref-unverified")
	}
	if !hmac.Equal([]byte(threadRef), []byte(claim.threadRef)) {
		return responseWithError(response, "task-binding-mismatch")
	}
	if claim.runtimeBindingRef != runtimeBindingRef {
		return responseWithError(response, "runtime-binding-mismatch")
	}
	if claim.executionRootRef != "" {
		if claim.executionRootRef != executionRootRef {
			return responseWithError(response, "tool-ref-already-claimed")
		}
		response.Accepted = true
		return response
	}
	if existingToolRef, exists := broker.claimRefByExecution[executionRootRef]; exists && existingToolRef != toolRef {
		return responseWithError(response, "execution-root-conflict")
	}
	claim.executionRootRef = executionRootRef
	claim.executionIdentity = peer.Nodes[1]
	claim.bindingMethod = "hook-selector"
	claim.lateBindingCandidates = 0
	broker.claimRefByExecution[executionRootRef] = toolRef
	response.Accepted = true
	return response
}

func validLateBindingRole(role, purpose string) bool {
	switch purpose {
	case leasePurposeSSH:
		return role == "ssh-client"
	case leasePurposeGitSign:
		return role == "onenod-sign-adapter"
	case "direct":
		return role == "onenod-requester"
	default:
		return false
	}
}

func (broker *broker) checkRequest(
	observation requestObservation,
	peer processChain,
) wireResponse {
	envelope := broker.baseEnvelope(observation, peer)
	response := wireResponse{SchemaVersion: protocolSchemaVersion, Envelope: &envelope}
	if code := validateRequestObservation(observation); code != "" {
		return broker.escalateResponse(response, code)
	}
	if len(peer.Nodes) == 0 || len(peer.Roles) != len(peer.Nodes) {
		return broker.escalateResponse(response, "request-process-unavailable")
	}
	now := broker.now().UTC()
	threadRef := broker.keyedRef("thread", []byte(observation.ThreadID))
	nonceRef := broker.keyedRef("nonce", []byte(observation.Nonce))
	requestProcessRefs := make([]string, 0, len(peer.Nodes))
	for _, identity := range peer.Nodes {
		requestProcessRefs = append(requestProcessRefs, broker.processRef(identity))
	}

	broker.mu.Lock()
	broker.expireLocked(now)
	matchingToolRefs := map[string]bool{}
	executionRootIndex := -1
	for index, processRef := range requestProcessRefs {
		if toolRef, found := broker.claimRefByExecution[processRef]; found {
			matchingToolRefs[toolRef] = true
			if executionRootIndex < 0 {
				executionRootIndex = index
			}
		}
	}
	if len(matchingToolRefs) == 0 {
		broker.mu.Unlock()
		return broker.escalateResponse(response, "execution-root-unverified")
	}
	if len(matchingToolRefs) > 1 {
		broker.mu.Unlock()
		return broker.escalateResponse(response, "execution-root-ambiguous")
	}
	toolRef := ""
	for candidate := range matchingToolRefs {
		toolRef = candidate
	}
	claim, found := broker.claimsByToolRef[toolRef]
	if !found || executionRootIndex < 0 || claim.executionRootRef != requestProcessRefs[executionRootIndex] {
		broker.mu.Unlock()
		return broker.escalateResponse(response, "execution-root-unverified")
	}
	contextTurnRef := claim.contextTurnRef
	contextToolUseRef := claim.contextToolUseRef
	broker.mu.Unlock()

	context, contextResult := broker.acquireDecisionContext(contextTurnRef, contextToolUseRef)
	if !contextResult.Accepted {
		return broker.escalateResponse(response, contextResult.ErrorCode)
	}
	failWithContext := func(code string) wireResponse {
		context.clear()
		return broker.escalateResponse(response, code)
	}

	broker.mu.Lock()
	defer broker.mu.Unlock()
	now = broker.now().UTC()
	broker.expireLocked(now)
	claim, found = broker.claimsByToolRef[toolRef]
	if !found || claim.contextTurnRef != contextTurnRef || claim.contextToolUseRef != contextToolUseRef ||
		claim.executionRootRef == "" || broker.claimRefByExecution[claim.executionRootRef] != toolRef {
		return failWithContext("execution-root-unverified")
	}
	executionRootIndex = indexOf(requestProcessRefs, claim.executionRootRef)
	if executionRootIndex < 0 {
		return failWithContext("execution-root-unverified")
	}
	if indexOf(requestProcessRefs, claim.runtimeBindingRef) < 0 {
		return failWithContext("runtime-binding-mismatch")
	}
	response.contextTurnRef = contextTurnRef
	response.contextToolUseRef = contextToolUseRef
	response.Envelope.Host = claim.host
	response.Envelope.RecentOpKinds = append([]string(nil), claim.recentOps...)
	response.Envelope.Attribution.ThreadRef = claim.threadRef
	response.Envelope.Attribution.TurnRef = claim.turnRef
	response.Envelope.Attribution.ToolUseRef = claim.toolUseRef
	response.Envelope.Attribution.SessionCandidateCount = claim.sessionCandidateCount
	response.Envelope.Attribution.SessionMetadataMatched = claim.metadataMatched
	response.Envelope.Attribution.ToolRefMatched = len(claim.executionCandidates) <= 1
	response.Envelope.Attribution.ExecutionRootMatched = true
	response.Envelope.Attribution.BindingMethod = claim.bindingMethod
	response.Envelope.Attribution.LateBindingCandidateCount = claim.lateBindingCandidates
	response.Envelope.Attribution.BindingAttempt = claim.bindingAttempt
	response.BindingAttempt = claim.bindingAttempt
	response.Envelope.Attribution.ExecutionRootRequestIndex = executionRootIndex
	response.Envelope.Attribution.RequestThreadMatched = hmac.Equal([]byte(threadRef), []byte(claim.threadRef))
	response.Envelope.Temporal.HostObservationAgeMS = maxInt64(0, now.Sub(claim.registeredAt).Milliseconds())
	response.Envelope.Temporal.AgeBucket = durationBucket(time.Duration(response.Envelope.Temporal.HostObservationAgeMS) * time.Millisecond)
	response.Envelope.Workspace.CWDRelation = cwdRelation(claim.hostCWD, peer.Nodes[0].CWD)

	runtimeBindings := map[string]bool{}
	pendingInvocations := 0
	for _, candidate := range broker.claimsByToolRef {
		if candidate.threadRef == claim.threadRef {
			if candidate.executionContext == nil {
				pendingInvocations++
			}
			if candidate.executionRootRef != "" {
				runtimeBindings[candidate.runtimeBindingRef] = true
			}
		}
	}
	response.Envelope.Attribution.PendingInvocationCount = pendingInvocations
	response.Envelope.Attribution.RuntimeBindingCount = len(runtimeBindings)

	switch {
	case claim.conflictCode != "":
		return failWithContext(claim.conflictCode)
	case !claim.metadataMatched:
		return failWithContext("hook-evidence-conflict")
	case !response.Envelope.Attribution.RequestThreadMatched:
		return failWithContext("task-binding-mismatch")
	case broker.nonces[nonceRef] != "":
		return failWithContext("request-replay")
	}
	// Bind the selected active file, not the contents of unrelated rollouts.
	currentInfo, statErr := os.Stat(claim.transcriptPath)
	if statErr != nil || claim.transcriptInfo == nil || !os.SameFile(claim.transcriptInfo, currentInfo) {
		return failWithContext("transcript-identity-changed")
	}
	if len(broker.nonces) >= 16384 {
		return failWithContext("observation-capacity-exceeded")
	}
	broker.nonces[nonceRef] = toolRef
	response.Envelope.Attribution.RequestNonceFresh = true
	response.Envelope.Attribution.Result = "unique"
	if len(claim.executionCandidates) > 1 {
		response.Envelope.Attribution.Result = "task-bound-tool-candidates"
	}
	response.Envelope.Attribution.EvidenceKinds = []string{
		"broker-memory", "cwd", "execution-root", "host-process-anchor", "pid-start", "process-ancestry",
		"request-nonce", "session-meta", "thread-join-key", "tool-ref", "tool-use", "turn",
	}
	if claim.bindingMethod == "process-birth-candidate-set" {
		response.Envelope.Attribution.EvidenceKinds = append(
			response.Envelope.Attribution.EvidenceKinds, "late-process-binding",
		)
	}
	response.Envelope.Collection.Status = "ready"
	response.Envelope.Collection.ErrorCode = nil
	response.Envelope.Features = buildFeatureManifest(*response.Envelope)
	response.Accepted = true
	response.decisionContext = &context
	response.decisionTranscriptPath = claim.transcriptPath
	response.decisionCWD = peer.Nodes[0].CWD
	return response
}

func (broker *broker) validateHookPeer(peer processChain) (string, bool, string) {
	if len(peer.Nodes) < 2 || len(peer.Roles) != len(peer.Nodes) {
		return "unknown", false, "hook-process-unavailable"
	}
	ownerClass, userWritable := executableOwnership(peer.Nodes[0].Path)
	if broker.trustMode == "production" {
		if peer.Roles[0] != "managed-hook" || firstRoleIndex(peer, "codex-runtime") < 0 ||
			firstRoleIndex(peer, "codex-desktop-host") < 0 ||
			!broker.trustedHook.matches(peer.Nodes[0].Path) {
			return ownerClass, userWritable, "managed-hook-identity-mismatch"
		}
		return "root", false, ""
	}
	if firstRoleIndex(peer, "codex-runtime") < 0 || firstRoleIndex(peer, "codex-desktop-host") < 0 {
		return ownerClass, userWritable, "codex-host-ancestry-unverified"
	}
	return ownerClass, userWritable, ""
}

func (broker *broker) baseEnvelope(observation requestObservation, peer processChain) evidenceEnvelope {
	envelope := evidenceEnvelope{
		SchemaVersion: protocolSchemaVersion, FeatureSchemaVersion: featureSchemaVersion,
		Collector: "Beholder Core", DecisionComponent: "Gatekeeper",
		Collection: collectionEvidence{
			Status: "incomplete", BrokerEpochRef: broker.epochRef, StateStorage: "memory-only",
		},
		Gatekeeper: gatekeeperEvidence{
			Disposition: "escalate", ErrorCode: stringPointer("gatekeeper-not-run"), Executed: false,
			ProductionAuthoritative: false, ModelUsed: false,
		},
		Attribution: attributionEvidence{
			Result: "unattributed", ExecutionRootRequestIndex: -1,
			EvidenceKinds: []string{}, Conflicts: []string{},
		},
		Host:                hostEvidence{PeerAncestryRoles: []string{}},
		RequestProcess:      requestProcessEvidence{AncestryRoles: []string{}},
		Request:             classifyRequest(observation, broker.keyedRef),
		Workspace:           workspaceEvidence{RepositoryKind: "none", HeadState: "unknown", RawPathsStored: false},
		Temporal:            temporalEvidence{AgeBucket: "unknown", ObservationLifetime: "kernel-process-lifetime", ReplayRetention: "execution-binding-lifetime"},
		EnvironmentPresence: observation.EnvironmentPresence,
		RecentOpKinds:       []string{},
		Privacy:             envelopePrivacy{},
	}
	if len(peer.Nodes) > 0 {
		ownerClass, writable := executableOwnership(peer.Nodes[0].Path)
		envelope.RequestProcess = requestProcessEvidence{
			PIDStartObserved: true,
			UIDMatchedBroker: peer.Nodes[0].UID == broker.allowedUID && peer.Nodes[0].RealUID == broker.allowedUID,
			AncestryDepth:    len(peer.Nodes), AncestryRoles: append([]string(nil), peer.Roles...),
			ExecutableOwnerClass: ownerClass, ExecutableUserWritable: writable,
			CodexRuntimeObserved: firstRoleIndex(peer, "codex-runtime") >= 0,
			DesktopHostObserved:  firstRoleIndex(peer, "codex-desktop-host") >= 0,
			RawPIDsStored:        false, ExecutablePathsStored: false,
		}
		envelope.Workspace = collectWorkspaceEvidence(peer.Nodes[0].CWD, broker.keyedRef)
	}
	envelope.Features = buildFeatureManifest(envelope)
	return envelope
}

func (broker *broker) escalateResponse(response wireResponse, code string) wireResponse {
	response.Accepted = false
	response.ErrorCode = stringPointer(code)
	if response.Envelope != nil {
		response.Envelope.Collection.Status = "incomplete"
		response.Envelope.Collection.ErrorCode = stringPointer(code)
		response.Envelope.Gatekeeper.Disposition = "escalate"
		response.Envelope.Gatekeeper.ErrorCode = stringPointer(code)
		response.Envelope.Attribution.Conflicts = append(response.Envelope.Attribution.Conflicts, code)
		response.Envelope.Features = buildFeatureManifest(*response.Envelope)
	}
	return response
}

func (broker *broker) expireLocked(now time.Time) {
	for _, claim := range broker.claimsByToolRef {
		// Observation ownership follows the kernel process lifetime. The short
		// claimTTL below remains the independent nonce/transport lifetime.
		alive := broker.processAlive(claim.runtimeIdentity)
		if claim.executionRootRef != "" {
			alive = alive && broker.processAlive(claim.executionIdentity)
		}
		if !alive {
			broker.removeClaimLocked(claim)
		}
	}
	for nonce, toolRef := range broker.nonces {
		if broker.claimsByToolRef[toolRef] == nil {
			delete(broker.nonces, nonce)
		}
	}
}

func sameHostRegistration(existing, candidate *hostClaim) bool {
	if existing == nil || candidate == nil {
		return false
	}
	return existing.threadRef == candidate.threadRef &&
		existing.turnRef == candidate.turnRef &&
		existing.toolUseRef == candidate.toolUseRef &&
		existing.hookAnchorRef == candidate.hookAnchorRef &&
		existing.runtimeBindingRef == candidate.runtimeBindingRef &&
		existing.contextTurnRef == candidate.contextTurnRef &&
		existing.contextToolUseRef == candidate.contextToolUseRef &&
		existing.transcriptPath == candidate.transcriptPath &&
		existing.host.Model == candidate.host.Model &&
		existing.host.PermissionMode == candidate.host.PermissionMode
}

func (broker *broker) processRef(identity processIdentity) string {
	return broker.keyedRef("process", []byte(rawProcessRef(identity)))
}

func (broker *broker) keyedRef(kind string, value []byte) string {
	digest := hmac.New(sha256.New, broker.key)
	_, _ = digest.Write([]byte(kind))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	return kind + "-" + hex.EncodeToString(digest.Sum(nil))
}

func classifyRequest(observation requestObservation, ref func(string, []byte) string) requestEvidence {
	evidence := requestEvidence{
		Surface: observation.Surface, Operation: observation.Operation, TargetKind: observation.TargetKind,
		RequesterReasonAccepted: false,
	}
	if observation.TargetID != "" {
		evidence.TargetRef = ref("target", []byte(observation.TargetID))
	}
	lower := strings.ToLower(observation.Operation + " " + observation.Surface)
	evidence.ReadLike = strings.Contains(lower, "read") || strings.Contains(lower, "list") || strings.Contains(lower, "observe")
	evidence.MutationLike = strings.Contains(lower, "create") || strings.Contains(lower, "patch") ||
		strings.Contains(lower, "write") || strings.Contains(lower, "archive") || strings.Contains(lower, "delete")
	evidence.SignatureLike = strings.Contains(lower, "sign") || strings.Contains(lower, "ssh")
	evidence.NetworkLike = evidence.SignatureLike || strings.Contains(lower, "network") || strings.Contains(lower, "git")
	return evidence
}

func buildFeatureManifest(envelope evidenceEnvelope) []featureDescriptor {
	features := []featureDescriptor{
		{Name: "host-binding", Source: "codex-managed-hook", TrustClass: "host-attested", PrivacyClass: "keyed-references", Observed: envelope.Host.HookEventName != ""},
		{Name: "process-provenance", Source: "macos-kernel", TrustClass: "os-observed", PrivacyClass: "roles-and-keyed-references", Observed: envelope.RequestProcess.PIDStartObserved},
		{Name: "session-metadata", Source: "codex-session-store", TrustClass: "cross-checked", PrivacyClass: "counts-and-keyed-references", Observed: envelope.Attribution.SessionCandidateCount > 0},
		{Name: "event-context", Source: "codex-session-store", TrustClass: "structured-derived", PrivacyClass: "operation-kinds-only", Observed: len(envelope.RecentOpKinds) > 0},
		{Name: "tool-semantics", Source: "pretool-input", TrustClass: "derived-not-authority", PrivacyClass: "coarse-features-only", Observed: envelope.Host.ToolInputFeatures.Observed},
		{Name: "request-semantics", Source: "onenod-entry-adapter", TrustClass: "adapter-structured", PrivacyClass: "operation-and-keyed-target", Observed: envelope.Request.Operation != ""},
		{Name: "workspace", Source: "local-filesystem", TrustClass: "os-observed", PrivacyClass: "keyed-paths", Observed: envelope.Workspace.CWDRelation != ""},
		{Name: "runtime-policy", Source: "codex-managed-hook", TrustClass: "host-attested", PrivacyClass: "enum-only", Observed: envelope.Host.PermissionMode != ""},
		{Name: "temporal", Source: "beholder-core-clock", TrustClass: "broker-derived", PrivacyClass: "bucketed", Observed: envelope.Temporal.AgeBucket != "unknown"},
		{Name: "environment-presence", Source: "request-process", TrustClass: "request-self-report", PrivacyClass: "presence-booleans-only", Observed: envelope.EnvironmentPresence.CodexThreadID},
		{Name: "integrity-replay", Source: "beholder-core-memory", TrustClass: "broker-authoritative-in-process", PrivacyClass: "keyed-nonce", Observed: envelope.Attribution.RequestNonceFresh},
	}
	return features
}

func validateHostObservation(observation hostObservation) string {
	if !safeJoinKey(observation.SessionID) || !safeJoinKey(observation.TurnID) || !safeJoinKey(observation.ToolUseID) ||
		!filepath.IsAbs(observation.TranscriptPath) || !filepath.IsAbs(observation.CWD) ||
		observation.HookEventName != "PreToolUse" ||
		(observation.ToolName != "Bash" && observation.ToolName != "functions.exec") ||
		!safeLabel(observation.Model) || !safePermissionMode(observation.PermissionMode) ||
		len(observation.ToolInput) == 0 || len(observation.ToolInput) > maximumTransientContextSize ||
		!json.Valid(observation.ToolInput) ||
		observation.ToolInputFeatures.SchemaVersion != featureSchemaVersion ||
		observation.ToolInputFeatures.RawCommandStored || observation.ToolInputFeatures.RawTokensStored {
		return "invalid-host-observation"
	}
	return ""
}

func validatePromptObservation(observation promptObservation) string {
	if !safeJoinKey(observation.SessionID) || !safeJoinKey(observation.TurnID) ||
		!filepath.IsAbs(observation.TranscriptPath) || !filepath.IsAbs(observation.CWD) ||
		observation.HookEventName != "UserPromptSubmit" || !safeLabel(observation.Model) ||
		!safePermissionMode(observation.PermissionMode) || len(observation.Prompt) == 0 ||
		len(observation.Prompt) > maximumTransientContextSize {
		return "invalid-prompt-observation"
	}
	return ""
}

func validateRequestObservation(observation requestObservation) string {
	if !safeJoinKey(observation.ThreadID) || !safeJoinKey(observation.Nonce) ||
		!safeLabel(observation.Surface) || !safeLabel(observation.Operation) || !safeLabel(observation.TargetKind) ||
		(observation.TargetID != "" && !safeJoinKey(observation.TargetID)) {
		return "invalid-request-observation"
	}
	return ""
}

func safeJoinKey(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func safeToolRef(value string) bool {
	const prefix = "tool-selector-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func safeLabel(value string) bool {
	return value != "" && len(value) <= 96 && safeJoinKey(strings.Repeat("x", 8)+value)
}

func safePermissionMode(value string) bool {
	switch value {
	case "default", "acceptEdits", "plan", "dontAsk", "bypassPermissions":
		return true
	default:
		return false
	}
}

func responseWithError(response wireResponse, code string) wireResponse {
	response.Accepted = false
	response.ErrorCode = stringPointer(code)
	return response
}

func stringPointer(value string) *string { return &value }

func sameRegularFile(left, right string) bool {
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && leftInfo.Mode().IsRegular() && rightInfo.Mode().IsRegular() && os.SameFile(leftInfo, rightInfo)
}

func indexOf(values []string, target string) int {
	for index, value := range values {
		if hmac.Equal([]byte(value), []byte(target)) {
			return index
		}
	}
	return -1
}

func durationBucket(duration time.Duration) string {
	switch {
	case duration < 0:
		return "invalid"
	case duration < 10*time.Millisecond:
		return "lt-10ms"
	case duration < 50*time.Millisecond:
		return "10-49ms"
	case duration < 250*time.Millisecond:
		return "50-249ms"
	case duration < time.Second:
		return "250-999ms"
	case duration < 5*time.Second:
		return "1-4s"
	case duration < 30*time.Second:
		return "5-29s"
	default:
		return "30s-plus"
	}
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

func sortedStrings(values []string) []string {
	copyValues := append([]string(nil), values...)
	sort.Strings(copyValues)
	return copyValues
}

func formatBrokerState(broker *broker) string {
	return fmt.Sprintf("claims=%d executions=%d nonces=%d", len(broker.claimsByToolRef), len(broker.claimRefByExecution), len(broker.nonces))
}
