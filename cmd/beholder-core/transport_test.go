package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIntegratedSSHLeaseConsumesBindingAndObservesExactAgentOperation(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeSSH, true)
	defer fixture.close()
	lease := fixture.transport.issueLease(fixture.threadID, leasePurposeSSH, fixture.requesterPeer)
	if !lease.Accepted || lease.AgentSocket == "" || lease.ErrorCode != nil {
		t.Fatalf("lease was not issued: %+v", lease)
	}

	connection, err := net.Dial("unix", lease.AgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	response, err := readAgentFrame(connection)
	_ = connection.Close()
	if err != nil || !bytes.Equal(response, []byte{12, 0, 0, 0, 0}) {
		t.Fatalf("standard Agent request was not forwarded: %x, %v", response, err)
	}

	binding := <-fixture.binding
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion,
		Surface:       "ssh-agent",
		Operation:     "ssh.authentication",
		TargetKind:    "ssh-key",
		TargetID:      "item-ssh-1",
		RemoteUser:    "git",
		PayloadDigest: strings.Repeat("a", 64),
	}
	observed := fixture.transport.observeAgentOperation(binding, target, fixture.agentPeer)
	if !observed.Accepted || observed.Disposition != "escalate" || observed.ErrorCode != nil {
		code := ""
		if observed.ErrorCode != nil {
			code = *observed.ErrorCode
		}
		t.Fatalf("actual Agent operation was not bound (%s): %+v", code, observed)
	}
	replayed := fixture.transport.observeAgentOperation(binding, target, fixture.agentPeer)
	if replayed.Accepted || replayed.ErrorCode == nil || *replayed.ErrorCode != "operation-replay" {
		t.Fatalf("operation binding replay was accepted: %+v", replayed)
	}
}

func TestClientHostedSSHLeaseConsumesWithoutACoreOwnedProxy(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeSSH, false)
	defer fixture.close()
	requester := processIdentity{
		PID: 8801, ParentPID: 8802, StartSeconds: 88,
		UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/Library/Application Support/Beholder/bin/ssh", CWD: fixture.root,
	}
	runtime := processIdentity{
		PID: 8802, ParentPID: 8803, StartSeconds: 80,
		UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/Applications/ChatGPT.app/codex", CWD: fixture.root,
	}
	desktop := processIdentity{
		PID: 8803, ParentPID: 1, StartSeconds: 79,
		UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/Applications/ChatGPT.app/ChatGPT", CWD: fixture.root,
	}
	shell := processIdentity{PID: 8804, ParentPID: runtime.PID, StartSeconds: uint64(time.Now().Unix()), StartMicroseconds: uint64(time.Now().Nanosecond() / 1000), UID: requester.UID, RealUID: requester.RealUID, Path: "/bin/zsh", CWD: fixture.root}
	requester.ParentPID = shell.PID
	fixture.requesterPeer = processChain{Nodes: []processIdentity{requester, shell, runtime, desktop}, Roles: []string{"ssh-client", "shell", "codex-runtime", "codex-desktop-host"}}
	fixture.transport.broker.mu.Lock()
	for toolRef, claim := range fixture.transport.broker.claimsByToolRef {
		delete(fixture.transport.broker.claimRefByExecution, claim.executionRootRef)
		claim.executionRootRef = ""
		claim.runtimeBindingRef = fixture.transport.broker.processRef(runtime)
		claim.host.ToolInputFeatures = deriveToolInputFeatures("ssh example.invalid")
		fixture.transport.broker.claimsByToolRef[toolRef] = claim
	}
	fixture.transport.broker.mu.Unlock()
	lease := fixture.transport.issueClientLease(
		fixture.threadID, leasePurposeSSH, fixture.requesterPeer,
	)
	if !lease.Accepted || lease.Binding == "" || lease.AgentSocket != "" || lease.ErrorCode != nil {
		t.Fatalf("client-hosted lease was not issued: %+v", lease)
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(lease.Binding)
	if err != nil || len(nonce) != 32 {
		t.Fatalf("client-hosted lease nonce is invalid: %v", err)
	}
	consumed := fixture.transport.consumeBinding(
		base64.RawURLEncoding.EncodeToString(nonce), fixture.agentPeer,
	)
	clear(nonce)
	if !consumed.Accepted || consumed.Binding == "" || consumed.ErrorCode != nil {
		t.Fatalf("client-hosted binding was not consumed: %+v", consumed)
	}
	fixture.transport.mu.Lock()
	proxyCount := len(fixture.transport.proxies)
	leaseRootCount := len(fixture.transport.leaseRoots)
	fixture.transport.mu.Unlock()
	if proxyCount != 0 || leaseRootCount != 0 {
		t.Fatalf("Core unexpectedly owned a client proxy: proxies=%d roots=%d", proxyCount, leaseRootCount)
	}
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion,
		Surface:       "ssh-agent",
		Operation:     "ssh.authentication",
		TargetKind:    "ssh-key",
		PayloadDigest: strings.Repeat("a", 64),
	}
	observed := fixture.transport.observeAgentOperation(consumed.Binding, target, fixture.agentPeer)
	if !observed.Accepted || observed.ErrorCode != nil {
		t.Fatalf("client-hosted operation was not observed: %+v", observed)
	}
}

func TestOptionCFallsBackToExistingAgentWhenBindingExtensionIsUnsupported(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeSSH, false)
	defer fixture.close()
	lease := fixture.transport.issueLease(fixture.threadID, leasePurposeSSH, fixture.requesterPeer)
	if !lease.Accepted {
		t.Fatalf("lease was not issued: %+v", lease)
	}
	connection, err := net.Dial("unix", lease.AgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	response, err := readAgentFrame(connection)
	_ = connection.Close()
	if err != nil || !bytes.Equal(response, []byte{12, 0, 0, 0, 0}) {
		t.Fatalf("fallback did not preserve the existing Agent path: %x, %v", response, err)
	}
	select {
	case binding := <-fixture.binding:
		t.Fatalf("unsupported Agent unexpectedly consumed a binding: %q", binding)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDirectMayOperationUsesTheSameCurrentHookClaimAndReplayGate(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeSSH, false)
	defer fixture.close()
	coreFixture := newBrokerFixture(t)
	fixture.transport.broker.close()
	fixture.transport.broker = coreFixture.core
	fixture.threadID, fixture.requesterPeer = coreFixture.sessionID, coreFixture.requestPeer
	if registered := coreFixture.registerPrimaryHost(); !registered.Accepted {
		t.Fatal("host registration failed")
	}
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion,
		Surface:       "direct-may",
		Operation:     "credential.use",
		TargetKind:    "onepassword-item",
		TargetID:      `{"item_id":"item-1","field_ids":["username"]}`,
		PayloadDigest: strings.Repeat("b", 64),
	}
	first := fixture.transport.checkDirectOperation(
		fixture.threadID, "0123456789abcdef0123456789abcdef", target, fixture.requesterPeer,
	)
	if !first.Accepted || first.Disposition != "escalate" || first.Envelope == nil ||
		first.Envelope.Gatekeeper.Executed || first.Envelope.Gatekeeper.ModelUsed {
		t.Fatalf("direct may operation did not reach collection-ready/escalate: %+v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(target.TargetID)) || bytes.Contains(encoded, []byte(target.PayloadDigest)) {
		t.Fatal("direct operation response leaked its raw target contract")
	}
	replayed := fixture.transport.checkDirectOperation(
		fixture.threadID, "0123456789abcdef0123456789abcdef", target, fixture.requesterPeer,
	)
	if replayed.Accepted || replayed.ErrorCode == nil || *replayed.ErrorCode != "request-replay" {
		t.Fatalf("direct request replay was accepted: %+v", replayed)
	}
}

func TestHumanOutcomeRequiresExactTargetAndProcessAndAcceptsExactRetry(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-outcome-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	coreSHA256, err := currentCoreExecutableSHA256()
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := captureTrustedExecutable(executable, coreSHA256, false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: coreSHA256,
	}
	core := &broker{gatekeeper: client, now: time.Now}
	coordinator := &transportCoordinator{
		broker: core, outcomes: map[string]outcomeBinding{}, outcomeUsed: map[string]outcomeUsedBinding{},
		pending: map[string]transportBinding{}, bindings: map[string]transportBinding{},
		used: map[string]time.Time{},
	}
	peer, err := captureProcessChain(os.Getpid())
	if err != nil || len(peer.Nodes) == 0 {
		t.Fatalf("capture peer: %v", err)
	}
	target := operationTarget{
		SchemaVersion: 1, Surface: "direct-may", Operation: "secret.read",
		TargetKind: "onepassword-item-fields", TargetID: `{"item_id":"fixture-a","field_ids":["credential"]}`,
		RequestContext: `{"client":{"application":"Codex"}}`, PayloadDigest: strings.Repeat("a", 64),
	}
	const evidenceID = "shadow-0123456789abcdef0123456789abcdef"
	coordinator.registerOutcome(evidenceID, target, peer.Nodes[0])
	now := time.Now().UTC()
	outcome := humanOutcome{
		SchemaVersion: 1, RecordType: "beholder_human_outcome", EvidenceID: evidenceID,
		OperationTargetSHA256: mustOperationTargetSHA256(t, target),
		AuthorizationSource:   "pwa-interactive", Decision: "approved",
		StatusTimeline:     []outcomeStatus{{Status: "approved", ObservedAt: now}},
		OperationCompleted: true, CredentialDelivered: true, ObservedAt: now,
	}
	mismatchedTarget := target
	mismatchedTarget.TargetID = `{"item_id":"fixture-b","field_ids":["credential"]}`
	if result := coordinator.recordHumanOutcome(evidenceID, mismatchedTarget, outcome, peer); result.Accepted ||
		result.ErrorCode == nil || *result.ErrorCode != "human-outcome-binding-mismatch" {
		t.Fatalf("mismatched outcome target was accepted: %+v", result)
	}
	mismatchedPeer := peer
	mismatchedPeer.Nodes = append([]processIdentity(nil), peer.Nodes...)
	mismatchedPeer.Nodes[0].PID++
	if result := coordinator.recordHumanOutcome(evidenceID, target, outcome, mismatchedPeer); result.Accepted ||
		result.ErrorCode == nil || *result.ErrorCode != "human-outcome-peer-mismatch" {
		t.Fatalf("mismatched outcome process was accepted: %+v", result)
	}
	received := make(chan gatekeeperLocalRequest, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		received <- request
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: 1, RequestID: evidenceID, Decision: "escalate",
			Reason: "The human outcome was recorded.", EvidenceID: evidenceID, OutcomeRecorded: true,
		})
	}()
	result := coordinator.recordHumanOutcome(evidenceID, target, outcome, peer)
	if !result.Accepted || result.EvidenceID != evidenceID || result.ErrorCode != nil {
		t.Fatalf("valid human outcome was rejected: %+v", result)
	}
	request := <-received
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	if request.Mode != "outcome" || request.RequestID != evidenceID || request.HumanOutcome == nil ||
		request.HumanOutcome.EvidenceID != evidenceID || request.CoreBinarySHA256 != coreSHA256 {
		t.Fatalf("Gatekeeper outcome request was invalid: %+v", request)
	}
	if replay := coordinator.recordHumanOutcome(evidenceID, target, outcome, peer); !replay.Accepted ||
		replay.ErrorCode != nil || replay.EvidenceID != evidenceID {
		t.Fatalf("identical human outcome retry was not idempotent: %+v", replay)
	}
}

func TestProductionHumanOutcomePeerUsesPinnedExecutableAndUID(t *testing.T) {
	peer, err := captureProcessChain(os.Getpid())
	if err != nil || len(peer.Nodes) == 0 {
		t.Fatalf("capture peer: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := &transportCoordinator{
		broker: &broker{trustMode: "production"}, agentUID: peer.Nodes[0].UID,
		agentIdentity: identity,
	}
	binding := outcomeBinding{
		targetSHA256: strings.Repeat("a", 64), requesterUID: peer.Nodes[0].UID,
		processRef: rawProcessRef(peer.Nodes[0]), expiresAt: time.Now().Add(time.Hour),
	}
	if !coordinator.validOutcomePeer(binding, peer) {
		t.Fatal("exact pinned production Agent peer was rejected")
	}
	wrongUID := peer
	wrongUID.Nodes = append([]processIdentity(nil), peer.Nodes...)
	wrongUID.Nodes[0].UID++
	if coordinator.validOutcomePeer(binding, wrongUID) {
		t.Fatal("production Agent peer with the wrong UID was accepted")
	}
	wrongPath := peer
	wrongPath.Nodes = append([]processIdentity(nil), peer.Nodes...)
	wrongPath.Nodes[0].Path = "/bin/echo"
	if coordinator.validOutcomePeer(binding, wrongPath) {
		t.Fatal("production Agent peer with an unpinned executable was accepted")
	}
}

func TestHumanOutcomeCorrelationSurvivesCoreRestartAndWriteRetry(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-outcome-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "outcome-state")
	socketPath := filepath.Join(root, "gatekeeper.sock")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: time.Second, allowedUID: uint32(os.Geteuid()),
		trustedProcess: identity, coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	core := &broker{gatekeeper: client, now: time.Now, trustMode: "fixture"}
	newCoordinator := func() *transportCoordinator {
		coordinator, createErr := newTransportCoordinator(
			core, root, filepath.Join(root, "unused-agent.sock"), "", "",
			time.Minute, time.Minute, stateRoot,
		)
		if createErr != nil {
			t.Fatal(createErr)
		}
		return coordinator
	}
	peer, err := captureProcessChain(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	target := operationTarget{
		SchemaVersion: 1, Surface: "direct-may", Operation: "secret.read",
		TargetKind: "onepassword-item-fields", PayloadDigest: strings.Repeat("d", 64),
	}
	const evidenceID = "shadow-durable-correlation-000000000001"
	now := time.Now().UTC()
	outcome := humanOutcome{
		SchemaVersion: 1, RecordType: "beholder_human_outcome", EvidenceID: evidenceID,
		OperationTargetSHA256: mustOperationTargetSHA256(t, target),
		AuthorizationSource:   "pwa-interactive", Decision: "approved",
		StatusTimeline:     []outcomeStatus{{Status: "approved", ObservedAt: now}},
		OperationCompleted: true, CredentialDelivered: true, ObservedAt: now,
	}

	first := newCoordinator()
	first.registerOutcome(evidenceID, target, peer.Nodes[0])
	first.close()
	second := newCoordinator()
	if result := second.recordHumanOutcome(evidenceID, target, outcome, peer); result.Accepted ||
		result.ErrorCode == nil || *result.ErrorCode != "human-outcome-gatekeeper-unavailable" {
		t.Fatalf("unavailable Gatekeeper did not preserve a retryable outcome: %+v", result)
	}
	if _, found := second.outcomes[evidenceID]; !found {
		t.Fatal("failed Gatekeeper write consumed the durable correlation")
	}

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: 1, RequestID: evidenceID, Decision: "escalate",
			Reason: "The human outcome was recorded.", EvidenceID: evidenceID, OutcomeRecorded: true,
		})
	}()
	if result := second.recordHumanOutcome(evidenceID, target, outcome, peer); !result.Accepted || result.ErrorCode != nil {
		t.Fatalf("retryable human outcome was not recorded: %+v", result)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	second.close()

	third := newCoordinator()
	defer third.close()
	if result := third.recordHumanOutcome(evidenceID, target, outcome, peer); !result.Accepted ||
		result.ErrorCode != nil || result.EvidenceID != evidenceID {
		t.Fatalf("recorded outcome was not idempotent after Core restart: %+v", result)
	}
}

func TestHumanOutcomeDurableQueueAcknowledgesThenDeliversAfterCoreRestart(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-outcome-queue-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(root, "outcome-state")
	queueRoot := filepath.Join(root, "outcome-delivery")
	socketPath := filepath.Join(root, "gatekeeper.sock")
	peer, err := captureProcessChain(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	target := operationTarget{
		SchemaVersion: 1, Surface: "ssh-agent", Operation: "ssh.authentication",
		TargetKind: "ssh-key", PayloadDigest: strings.Repeat("e", 64),
	}
	const evidenceID = "shadow-durable-queue-0000000000000001"
	now := time.Now().UTC()
	requestID := "22222222-2222-4222-8222-222222222222"
	outcome := humanOutcome{
		SchemaVersion: 1, RecordType: "beholder_human_outcome", EvidenceID: evidenceID,
		OperationTargetSHA256: mustOperationTargetSHA256(t, target), OneNodRequestID: &requestID,
		AuthorizationSource: "pwa-interactive", Decision: "approved",
		StatusTimeline: []outcomeStatus{
			{Status: "pending", ObservedAt: now.Add(-2 * time.Second)},
			{Status: "approved", ObservedAt: now.Add(-time.Second)},
			{Status: "consumed", ObservedAt: now},
		},
		OperationCompleted: true, CredentialDelivered: false, ObservedAt: now,
	}
	firstBroker := &broker{now: time.Now, trustMode: "fixture"}
	first, err := newTransportCoordinator(
		firstBroker, root, filepath.Join(root, "unused-agent.sock"), "", "",
		time.Minute, time.Minute, stateRoot, queueRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	first.registerOutcome(evidenceID, target, peer.Nodes[0])
	started := time.Now()
	queued := first.recordHumanOutcome(evidenceID, target, outcome, peer)
	if !queued.Accepted || queued.ErrorCode != nil || queued.EvidenceID != evidenceID ||
		time.Since(started) >= time.Second {
		code := ""
		if queued.ErrorCode != nil {
			code = *queued.ErrorCode
		}
		t.Fatalf("human outcome was not durably acknowledged before delivery: %+v code=%s", queued, code)
	}
	queuePath := outcomeQueuePath(queueRoot, evidenceID)
	if _, err := os.Stat(queuePath); err != nil {
		t.Fatalf("durable outcome delivery was not queued: %v", err)
	}
	first.close()

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(digest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: time.Second, allowedUID: uint32(os.Geteuid()),
		trustedProcess: identity, coreBinarySHA256: hex.EncodeToString(digest[:]),
	}
	delivered := make(chan gatekeeperLocalRequest, 1)
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		delivered <- request
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: 1, RequestID: evidenceID, Decision: "escalate",
			Reason: "The human outcome was recorded.", EvidenceID: evidenceID, OutcomeRecorded: true,
		})
	}()
	secondBroker := &broker{gatekeeper: client, now: time.Now, trustMode: "fixture"}
	second, err := newTransportCoordinator(
		secondBroker, root, filepath.Join(root, "unused-agent.sock"), "", "",
		time.Minute, time.Minute, stateRoot, queueRoot,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer second.close()
	select {
	case request := <-delivered:
		if request.Mode != "outcome" || request.HumanOutcome == nil ||
			request.HumanOutcome.EvidenceID != evidenceID || request.HumanOutcome.CredentialDelivered {
			t.Fatalf("queued human outcome changed during delivery: %+v", request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued human outcome was not retried after Core restart")
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(queuePath); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("delivered human outcome remained in the durable queue")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if replay := second.recordHumanOutcome(evidenceID, target, outcome, peer); !replay.Accepted ||
		replay.ErrorCode != nil || replay.EvidenceID != evidenceID {
		t.Fatalf("delivered queued outcome was not idempotent: %+v", replay)
	}
}

func mustOperationTargetSHA256(t *testing.T, target operationTarget) string {
	t.Helper()
	digest, ok := operationTargetSHA256(target)
	if !ok {
		t.Fatal("operation target digest failed")
	}
	return digest
}

func TestGitLeaseRejectsAnSSHAuthenticationOperation(t *testing.T) {
	fixture := newTransportFixture(t, leasePurposeGitSign, true)
	defer fixture.close()
	lease := fixture.transport.issueLease(fixture.threadID, leasePurposeGitSign, fixture.requesterPeer)
	if !lease.Accepted {
		t.Fatalf("Git lease was not issued: %+v", lease)
	}
	connection, err := net.Dial("unix", lease.AgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAgentFrame(connection, []byte{11}); err != nil {
		t.Fatal(err)
	}
	_, _ = readAgentFrame(connection)
	_ = connection.Close()
	binding := <-fixture.binding
	wrong := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion,
		Surface:       "ssh-agent",
		Operation:     "ssh.authentication",
		TargetKind:    "ssh-key",
		PayloadDigest: strings.Repeat("c", 64),
	}
	result := fixture.transport.observeAgentOperation(binding, wrong, fixture.agentPeer)
	if result.Accepted || result.ErrorCode == nil || *result.ErrorCode != "operation-target-mismatch" {
		t.Fatalf("Git transport accepted a different operation: %+v", result)
	}
}

func TestIntegratedTransportKeepsConcurrentSessionsAndPurposesIsolated(t *testing.T) {
	const sessions = 32
	root, err := os.MkdirTemp("/tmp", "bh-core-concurrent-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerWithKey(
		root, "fixture", "", "", time.Minute, bytes.Repeat([]byte{9}, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	transport, err := newTransportCoordinator(
		core, root, filepath.Join(root, "unused-upstream.sock"), "", "", time.Minute, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.close()

	type sessionFixture struct {
		threadID string
		purpose  string
		peer     processChain
	}
	fixtures := make([]sessionFixture, sessions)
	now := time.Now().UTC()
	sharedRuntime := processIdentity{
		PID: 3000, ParentPID: 1,
		StartSeconds: 200, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/fixture/shared-codex-runtime", CWD: root,
	}
	for index := range fixtures {
		threadID := fmt.Sprintf("session-concurrent-%02d", index)
		turnID := fmt.Sprintf("turn-concurrent-%02d", index)
		toolUseID := fmt.Sprintf("tool-use-concurrent-%02d", index)
		if result := core.contexts.registerPrompt(threadID, turnID, []byte("use ordinary git or ssh")); !result.Accepted {
			t.Fatalf("register prompt %d: %+v", index, result)
		}
		contextResult := core.contexts.registerToolInput(
			threadID, turnID, toolUseID, json.RawMessage(`{"command":"git commit or ssh"}`),
		)
		if !contextResult.Accepted {
			t.Fatalf("register tool input %d: %+v", index, contextResult)
		}
		executionRoot := processIdentity{
			PID: 4000 + index, ParentPID: sharedRuntime.PID,
			StartSeconds: uint64(300 + index), UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
			Path: "/bin/zsh", CWD: root,
		}
		leaf := processIdentity{
			PID: 2000 + index, ParentPID: executionRoot.PID,
			StartSeconds: uint64(100 + index), UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
			Path: "/fixture/ssh", CWD: root,
		}
		peer := processChain{
			Nodes: []processIdentity{leaf, executionRoot, sharedRuntime},
			Roles: []string{"tool-child", "shell", "codex-runtime"},
		}
		executionRootRef := core.processRef(executionRoot)
		runtimeRef := core.processRef(sharedRuntime)
		claim := &hostClaim{
			threadRef:     core.keyedRef("thread", []byte(threadID)),
			turnRef:       core.keyedRef("turn", []byte(turnID)),
			toolUseRef:    core.keyedRef("tool-use", []byte(toolUseID)),
			hookAnchorRef: runtimeRef, executionRootRef: executionRootRef, runtimeBindingRef: runtimeRef,
			registeredAt:          now,
			sessionCandidateCount: 1, metadataMatched: true,
			hostCWD: root, contextTurnRef: contextResult.turnRef,
			contextToolUseRef: contextResult.toolRef,
		}
		installTestHostClaim(core, claim, byte(index+1))
		purpose := leasePurposeSSH
		if index%2 == 1 {
			purpose = leasePurposeGitSign
		}
		fixtures[index] = sessionFixture{
			threadID: threadID, purpose: purpose, peer: peer,
		}
	}

	type leaseResult struct {
		index    int
		response wireResponse
	}
	leases := make(chan leaseResult, sessions)
	var issueGroup sync.WaitGroup
	for index, fixture := range fixtures {
		issueGroup.Add(1)
		go func(index int, fixture sessionFixture) {
			defer issueGroup.Done()
			leases <- leaseResult{
				index:    index,
				response: transport.issueLease(fixture.threadID, fixture.purpose, fixture.peer),
			}
		}(index, fixture)
	}
	issueGroup.Wait()
	close(leases)
	sockets := map[string]bool{}
	for result := range leases {
		if !result.response.Accepted || result.response.AgentSocket == "" || result.response.ErrorCode != nil {
			t.Fatalf("lease %d failed: %+v", result.index, result.response)
		}
		if sockets[result.response.AgentSocket] {
			t.Fatalf("sessions shared Agent socket %q", result.response.AgentSocket)
		}
		sockets[result.response.AgentSocket] = true
	}

	type pendingFixture struct {
		index int
		nonce []byte
	}
	pendingByRequester := make(map[string]pendingFixture, sessions)
	transport.mu.Lock()
	if len(transport.pending) != sessions || len(transport.proxies) != sessions {
		transport.mu.Unlock()
		t.Fatalf("unexpected pending state: pending=%d proxies=%d", len(transport.pending), len(transport.proxies))
	}
	for nonceRef, binding := range transport.pending {
		proxy := transport.proxies[nonceRef]
		if proxy == nil {
			transport.mu.Unlock()
			t.Fatalf("pending binding %s has no proxy", nonceRef)
		}
		index := int(binding.requester.PID) - 2000
		pendingByRequester[rawProcessRef(binding.requester)] = pendingFixture{
			index: index,
			nonce: append([]byte(nil), proxy.bindingNonce...),
		}
	}
	transport.mu.Unlock()

	agentIdentity := processIdentity{
		PID: 991, ParentPID: 1, StartSeconds: 42,
		UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/fixture/may", CWD: root,
	}
	agentPeer := processChain{Nodes: []processIdentity{agentIdentity}, Roles: []string{"onenod-requester"}}
	tokens := make([]string, sessions)
	type consumeResult struct {
		index    int
		response wireResponse
	}
	consumed := make(chan consumeResult, sessions)
	var consumeGroup sync.WaitGroup
	for index, fixture := range fixtures {
		pending, found := pendingByRequester[rawProcessRef(fixture.peer.Nodes[0])]
		if !found || pending.index != index {
			t.Fatalf("session %d lost its pending nonce", index)
		}
		consumeGroup.Add(1)
		go func(index int, nonce []byte) {
			defer consumeGroup.Done()
			defer clear(nonce)
			consumed <- consumeResult{
				index:    index,
				response: transport.consumeBinding(base64.RawURLEncoding.EncodeToString(nonce), agentPeer),
			}
		}(index, pending.nonce)
	}
	consumeGroup.Wait()
	close(consumed)
	for result := range consumed {
		if !result.response.Accepted || result.response.Binding == "" || result.response.ErrorCode != nil {
			t.Fatalf("consume %d failed: %+v", result.index, result.response)
		}
		tokens[result.index] = result.response.Binding
	}

	type operationResult struct {
		index    int
		response wireResponse
	}
	operations := make(chan operationResult, sessions)
	var operationGroup sync.WaitGroup
	for index, fixture := range fixtures {
		target := operationTarget{
			SchemaVersion: decisionBindingSchemaVersion,
			Surface:       "ssh-agent", TargetKind: "ssh-key",
			TargetID: fmt.Sprintf("item-%02d", index), PayloadDigest: strings.Repeat("d", 64),
		}
		if fixture.purpose == leasePurposeGitSign {
			target.Operation = "git.ssh-signature"
		} else {
			target.Operation = "ssh.authentication"
		}
		operationGroup.Add(1)
		go func(index int, token string, target operationTarget) {
			defer operationGroup.Done()
			operations <- operationResult{
				index:    index,
				response: transport.observeAgentOperation(token, target, agentPeer),
			}
		}(index, tokens[index], target)
	}
	operationGroup.Wait()
	close(operations)
	for result := range operations {
		if !result.response.Accepted || result.response.Disposition != "escalate" || result.response.ErrorCode != nil {
			t.Fatalf("operation %d crossed or lost its binding: %+v", result.index, result.response)
		}
	}
}

type transportFixture struct {
	threadID      string
	root          string
	upstream      net.Listener
	transport     *transportCoordinator
	requesterPeer processChain
	agentPeer     processChain
	binding       chan string
	serverResult  chan error
}

func newTransportFixture(t *testing.T, purpose string, supportsBinding bool) *transportFixture {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "bh-core-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	upstreamPath := filepath.Join(root, "upstream.sock")
	upstream, err := net.Listen("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	core, err := newBrokerWithKey(
		root, "fixture", "", "", time.Minute, bytes.Repeat([]byte{7}, 32), time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	threadID := "session-transport-alpha"
	turnID := "turn-transport-alpha"
	toolUseID := "tool-use-transport-alpha"
	if result := core.contexts.registerPrompt(threadID, turnID, []byte("use ordinary ssh or git")); !result.Accepted {
		t.Fatal(result)
	}
	contextResult := core.contexts.registerToolInput(
		threadID, turnID, toolUseID, json.RawMessage(`{"command":"ssh example.invalid"}`),
	)
	if !contextResult.Accepted {
		t.Fatal(contextResult)
	}
	requesterPeer, err := captureProcessChain(os.Getpid())
	if err != nil || len(requesterPeer.Nodes) == 0 {
		t.Fatalf("capture requester peer: %v", err)
	}
	requesterPeer.Nodes[0].CWD = root
	executionRoot := core.processRef(requesterPeer.Nodes[0])
	now := time.Now().UTC()
	claim := &hostClaim{
		threadRef:     core.keyedRef("thread", []byte(threadID)),
		turnRef:       core.keyedRef("turn", []byte(turnID)),
		toolUseRef:    core.keyedRef("tool-use", []byte(toolUseID)),
		hookAnchorRef: executionRoot, executionRootRef: executionRoot, runtimeBindingRef: executionRoot,
		registeredAt:          now,
		sessionCandidateCount: 1, metadataMatched: true,
		hostCWD: root, contextTurnRef: contextResult.turnRef,
		contextToolUseRef: contextResult.toolRef,
	}
	installTestHostClaim(core, claim, 0x42)
	agentIdentity := processIdentity{
		PID: 991, ParentPID: 1, StartSeconds: 42,
		UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()),
		Path: "/fixture/may", CWD: root,
	}
	agentPeer := processChain{Nodes: []processIdentity{agentIdentity}, Roles: []string{"onenod-requester"}}
	transport, err := newTransportCoordinator(
		core, root, upstreamPath, "", "", time.Minute, 2*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &transportFixture{
		threadID: threadID, root: root, upstream: upstream, transport: transport,
		requesterPeer: requesterPeer, agentPeer: agentPeer,
		binding: make(chan string, 1), serverResult: make(chan error, 1),
	}
	go fixture.serveFakeAgent(supportsBinding)
	_ = purpose
	return fixture
}

func installTestHostClaim(core *broker, claim *hostClaim, seed byte) {
	core.processAlive = func(processIdentity) bool { return true }
	if claim.transcriptPath == "" {
		claim.transcriptPath = filepath.Join(core.sessionRoot, fmt.Sprintf("transport-%d.jsonl", seed))
		_ = os.WriteFile(claim.transcriptPath, []byte("fixture transport evidence\n"), 0600)
	}
	claim.transcriptInfo, _ = os.Stat(claim.transcriptPath)
	core.contexts.pinRefs(claim.contextTurnRef, claim.contextToolUseRef)
	toolRef := core.keyedRef("tool-selector", []byte{seed})
	claim.toolRef = toolRef
	core.claimsByToolRef[toolRef] = claim
	core.claimRefByTool[claim.contextToolUseRef] = toolRef
	core.claimRefByExecution[claim.executionRootRef] = toolRef
}

func (fixture *transportFixture) serveFakeAgent(supportsBinding bool) {
	connection, err := fixture.upstream.Accept()
	if err != nil {
		fixture.serverResult <- err
		return
	}
	defer connection.Close()
	extension, err := readAgentFrame(connection)
	if err != nil {
		fixture.serverResult <- err
		return
	}
	nonce, err := parseBindingExtensionFrame(extension)
	if err != nil {
		fixture.serverResult <- err
		return
	}
	if supportsBinding {
		consumed := fixture.transport.consumeBinding(
			base64.RawURLEncoding.EncodeToString(nonce), fixture.agentPeer,
		)
		if !consumed.Accepted || consumed.Binding == "" {
			fixture.serverResult <- errors.New("binding consume failed")
			return
		}
		fixture.binding <- consumed.Binding
		if err := writeAgentFrame(connection, []byte{beholderAgentSuccessResponse}); err != nil {
			fixture.serverResult <- err
			return
		}
	} else if err := writeAgentFrame(connection, []byte{5}); err != nil {
		fixture.serverResult <- err
		return
	}
	standard, err := readAgentFrame(connection)
	if err != nil || !bytes.Equal(standard, []byte{11}) {
		fixture.serverResult <- errors.New("standard Agent request missing")
		return
	}
	if err := writeAgentFrame(connection, []byte{12, 0, 0, 0, 0}); err != nil {
		fixture.serverResult <- err
		return
	}
	fixture.serverResult <- nil
}

func (fixture *transportFixture) close() {
	fixture.transport.close()
	_ = fixture.upstream.Close()
	select {
	case <-fixture.serverResult:
	case <-time.After(100 * time.Millisecond):
	}
	_ = os.RemoveAll(fixture.root)
}

func parseBindingExtensionFrame(frame []byte) ([]byte, error) {
	if len(frame) < 1 || frame[0] != beholderAgentExtensionRequest {
		return nil, errors.New("binding extension type missing")
	}
	offset := 1
	readString := func() ([]byte, bool) {
		if offset+4 > len(frame) {
			return nil, false
		}
		length := int(binary.BigEndian.Uint32(frame[offset : offset+4]))
		offset += 4
		if length < 0 || offset+length > len(frame) {
			return nil, false
		}
		value := frame[offset : offset+length]
		offset += length
		return value, true
	}
	name, ok := readString()
	if !ok || string(name) != beholderBindingExtensionName || offset+4 > len(frame) ||
		binary.BigEndian.Uint32(frame[offset:offset+4]) != beholderBindingExtensionVersion {
		return nil, errors.New("invalid binding extension header")
	}
	offset += 4
	nonce, ok := readString()
	if !ok || offset != len(frame) || len(nonce) < 16 || len(nonce) > 128 {
		return nil, errors.New("invalid binding extension nonce")
	}
	return append([]byte(nil), nonce...), nil
}
