package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBrokerBuildsWidePrivacySafeEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.registerPrimaryHost()
	if !registered.Accepted || registered.ErrorCode != nil {
		t.Fatalf("host registration failed: %+v", registered)
	}
	checked := fixture.checkPrimaryRequest()
	if !checked.Accepted || checked.Envelope == nil || checked.Envelope.Collection.Status != "ready" ||
		checked.Envelope.Attribution.Result != "unique" {
		t.Fatalf("request evidence was not ready: %+v", checked)
	}
	if checked.Envelope.Gatekeeper.Disposition != "escalate" || checked.Envelope.Gatekeeper.ErrorCode == nil ||
		*checked.Envelope.Gatekeeper.ErrorCode != "gatekeeper-not-run" || checked.Envelope.Gatekeeper.Executed ||
		checked.Envelope.Gatekeeper.ProductionAuthoritative || checked.Envelope.Gatekeeper.ModelUsed ||
		checked.Envelope.Collection.StateStorage != "memory-only" {
		t.Fatalf("fixture overstated authority: collection=%+v gatekeeper=%+v", checked.Envelope.Collection, checked.Envelope.Gatekeeper)
	}
	if !checked.Envelope.Attribution.ToolRefMatched || !checked.Envelope.Attribution.ExecutionRootMatched ||
		!checked.Envelope.Attribution.RequestThreadMatched ||
		checked.Envelope.Attribution.SessionCandidateCount != 1 || !checked.Envelope.Attribution.RequestNonceFresh {
		t.Fatalf("missing attribution evidence: %+v", checked.Envelope.Attribution)
	}
	if len(checked.Envelope.Features) < 10 {
		t.Fatalf("feature envelope is too narrow: %+v", checked.Envelope.Features)
	}
	for _, expected := range []string{"host-binding", "process-provenance", "session-metadata", "tool-semantics", "request-semantics", "workspace", "integrity-replay"} {
		if !featureNamed(checked.Envelope.Features, expected) {
			t.Fatalf("missing feature group %q", expected)
		}
	}
	encoded, err := json.Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		fixture.sessionID, fixture.turnID, fixture.toolUseID, fixture.targetID,
		fixture.transcriptPath, fixture.root, fixture.sentinel, registered.ToolRef,
	} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("envelope leaked raw value %q", forbidden)
		}
	}
	privacy := checked.Envelope.Privacy
	if privacy.RawPromptStored || privacy.RawToolInputStored || privacy.RawToolOutputStored ||
		privacy.RawTranscriptStored || privacy.RawEnvironmentStored || privacy.RawIDsStored || privacy.CredentialMaterialSeen {
		t.Fatalf("privacy flags must remain false: %+v", privacy)
	}
}

func TestEnvelopeMatchesTheConfiguredRequestUIDWhenCoreRunsAsRoot(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	fixture.core.allowedUID = 4242
	peer := cloneProcessChain(fixture.requestPeer)
	peer.Nodes[0].UID = 4242
	peer.Nodes[0].RealUID = 4242
	envelope := fixture.core.baseEnvelope(fixture.request, peer)
	if !envelope.RequestProcess.UIDMatchedBroker {
		t.Fatal("configured production request UID was reported as mismatched")
	}
	peer.Nodes[0].RealUID = 4243
	envelope = fixture.core.baseEnvelope(fixture.request, peer)
	if envelope.RequestProcess.UIDMatchedBroker {
		t.Fatal("different real UID was reported as matching")
	}
}

func TestBrokerRequiresCurrentPromptBeforePreToolUse(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if result := fixture.core.contexts.completeTurn(fixture.sessionID, fixture.turnID); !result.Accepted {
		t.Fatal(result)
	}
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if registered.Accepted || registered.ErrorCode == nil || *registered.ErrorCode != "prompt-binding-missing" {
		t.Fatalf("PreToolUse without current prompt was accepted: %+v", registered)
	}
}

func TestBrokerRegistersPromptAndKeepsExactContextOutOfEnvelope(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if result := fixture.core.contexts.completeTurn(fixture.sessionID, fixture.turnID); !result.Accepted {
		t.Fatal(result)
	}
	promptSentinel := "E1_CURRENT_PROMPT_MEMORY_ONLY_SENTINEL"
	registeredPrompt := fixture.core.registerPrompt(promptObservation{
		SessionID: fixture.sessionID, TurnID: fixture.turnID,
		TranscriptPath: fixture.transcriptPath, CWD: fixture.root,
		HookEventName: "UserPromptSubmit", Model: "gpt-5.6-luna",
		PermissionMode: "dontAsk", ObservedAt: fixture.current.Format(time.RFC3339Nano),
		Prompt: []byte(promptSentinel),
	}, fixture.hookPeer)
	if !registeredPrompt.Accepted || registeredPrompt.ErrorCode != nil {
		t.Fatalf("prompt registration failed: %+v", registeredPrompt)
	}
	toolSentinel := "E1_EXACT_TOOL_INPUT_MEMORY_ONLY_SENTINEL"
	fixture.host.ToolInput = json.RawMessage(`{"command":"` + toolSentinel + `"}`)
	if registered := fixture.registerPrimaryHost(); !registered.Accepted {
		t.Fatalf("PreToolUse registration failed: %+v", registered)
	}
	checked := fixture.checkPrimaryRequest()
	if !checked.Accepted {
		t.Fatalf("bound request failed: %+v", checked)
	}
	encoded, err := json.Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(promptSentinel)) || bytes.Contains(encoded, []byte(toolSentinel)) {
		t.Fatalf("decision context leaked into the evidence envelope: %s", encoded)
	}
}

func TestBrokerRejectsThreadReplayFromAnotherTask(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("host registration failed")
	}
	fixture.request.ThreadID = "session-other-task"
	checked := fixture.checkPrimaryRequest()
	assertEscalated(t, checked, "task-binding-mismatch")
}

func TestBrokerRejectsRequestNonceReplay(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("host registration failed")
	}
	if first := fixture.checkPrimaryRequest(); !first.Accepted {
		t.Fatalf("first request failed: %+v", first)
	}
	second := fixture.checkPrimaryRequest()
	assertEscalated(t, second, "request-replay")
}

func TestBrokerIgnoresUnrelatedDuplicateSessionMetadata(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	writeSessionFixture(t, filepath.Join(fixture.root, "duplicate.jsonl"), fixture.sessionID, fixture.turnID, fixture.root)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("host observation should be retained for a diagnostic envelope")
	}
	checked := fixture.checkPrimaryRequest()
	if !checked.Accepted {
		t.Fatalf("bound active transcript rejected because of a copy: %+v", checked)
	}
}

func TestBrokerBindsDifferentTasksToDistinctExecutionRootsUnderSharedHost(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	first := fixture.registerPrimaryHost()
	if !first.Accepted {
		t.Fatal("first host registration failed")
	}
	otherPath := filepath.Join(fixture.root, "other.jsonl")
	writeSessionFixture(t, otherPath, "session-other-task", "turn-other-task", fixture.root)
	conflict := fixture.host
	conflict.SessionID = "session-other-task"
	conflict.TurnID = "turn-other-task"
	conflict.ToolUseID = "tool-use-other-task"
	conflict.TranscriptPath = otherPath
	if result := fixture.core.contexts.registerPrompt(
		conflict.SessionID,
		conflict.TurnID,
		[]byte("other task prompt"),
	); !result.Accepted {
		t.Fatal(result)
	}
	second := fixture.core.registerHost(conflict, fixture.hookPeer)
	if !second.Accepted || second.ErrorCode != nil || second.ToolRef == "" || second.ToolRef == first.ToolRef {
		t.Fatalf("shared-anchor registrations were not isolated: first=%+v second=%+v", first, second)
	}
	secondExecutionPeer := cloneProcessChain(fixture.executionPeer)
	secondExecutionPeer.Nodes[0].PID += 100
	secondExecutionPeer.Nodes[0].StartMicroseconds += 1
	secondExecutionPeer.Nodes[1].PID += 100
	secondExecutionPeer.Nodes[1].StartMicroseconds += 1
	if entered := fixture.core.registerExecutionRoot(second.ToolRef, conflict.SessionID, secondExecutionPeer); !entered.Accepted {
		t.Fatalf("second execution root failed: %+v", entered)
	}
	if checked := fixture.checkPrimaryRequest(); !checked.Accepted {
		t.Fatalf("first task lost its execution root: %+v", checked)
	}
	otherRequest := fixture.request
	otherRequest.ThreadID = conflict.SessionID
	otherRequest.Nonce = "request-nonce-other-task"
	secondRequestPeer := cloneProcessChain(fixture.requestPeer)
	secondRequestPeer.Nodes[0].PID += 100
	secondRequestPeer.Nodes[0].StartMicroseconds += 1
	secondRequestPeer.Nodes[1] = secondExecutionPeer.Nodes[1]
	if checked := fixture.core.checkRequest(otherRequest, secondRequestPeer); !checked.Accepted {
		t.Fatalf("second task lost its execution root: %+v", checked)
	}
	otherRequest.Nonce = "request-nonce-cross-task"
	if checked := fixture.core.checkRequest(otherRequest, fixture.requestPeer); checked.Accepted ||
		checked.ErrorCode == nil || *checked.ErrorCode != "task-binding-mismatch" {
		t.Fatalf("cross-task binding was not rejected: %+v", checked)
	}
}

func TestBrokerAllowsConcurrentInvocationsForSameThreadAndRuntime(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("first host registration failed")
	}
	secondHost := fixture.host
	secondHost.ToolUseID = "tool-use-test-bravo"
	second := fixture.core.registerHost(secondHost, fixture.hookPeer)
	if !second.Accepted || second.ToolRef == fixture.toolRef {
		t.Fatal("second same-runtime invocation failed")
	}
	secondExecutionPeer := cloneProcessChain(fixture.executionPeer)
	secondExecutionPeer.Nodes[0].PID += 100
	secondExecutionPeer.Nodes[1].PID += 100
	if entered := fixture.core.registerExecutionRoot(second.ToolRef, fixture.sessionID, secondExecutionPeer); !entered.Accepted {
		t.Fatalf("second same-runtime execution root failed: %+v", entered)
	}
	checked := fixture.checkPrimaryRequest()
	if !checked.Accepted || checked.Envelope.Attribution.PendingInvocationCount != 2 ||
		checked.Envelope.Attribution.RuntimeBindingCount != 1 {
		t.Fatalf("legitimate same-task concurrency was rejected: %+v", checked)
	}
}

func TestBrokerRepeatedHostObservationReturnsTheSamePublicToolRef(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	first := fixture.registerPrimaryHost()
	second := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !first.Accepted || !second.Accepted || first.ToolRef == "" || second.ToolRef != first.ToolRef {
		t.Fatalf("idempotent host observation changed its tool ref: first=%+v second=%+v", first, second)
	}
	if len(fixture.core.claimsByToolRef) != 1 || len(fixture.core.claimRefByTool) != 1 ||
		len(fixture.core.claimRefByExecution) != 1 {
		t.Fatalf("idempotent registration duplicated state: %s", formatBrokerState(fixture.core))
	}
}

func TestBrokerRejectsRequestWithoutRegisteredExecutionRoot(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted {
		t.Fatal("host registration failed")
	}
	checked := fixture.core.checkRequest(fixture.request, fixture.requestPeer)
	assertEscalated(t, checked, "execution-root-unverified")
	unknown := fixture.core.registerExecutionRoot(
		"tool-selector-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		fixture.sessionID,
		fixture.executionPeer,
	)
	if unknown.Accepted || unknown.ErrorCode == nil || *unknown.ErrorCode != "tool-ref-unverified" {
		t.Fatalf("unknown tool ref was accepted: %+v", unknown)
	}
}

func TestBrokerLateBindsTheUnmodifiedSSHProcessToTheLatestHookObservation(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	fixture.host.ToolInput = json.RawMessage(`{"command":"ssh example.invalid"}`)
	fixture.host.ToolInputFeatures = deriveToolInputFeatures("ssh example.invalid")
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted {
		t.Fatalf("host registration failed: %+v", registered)
	}
	peer := cloneProcessChain(fixture.requestPeer)
	peer.Nodes[0].Path = "/Library/Application Support/Beholder/bin/ssh"
	peer.Roles[0] = "ssh-client"
	bound := fixture.core.registerLatestExecutionRoot(fixture.sessionID, leasePurposeSSH, peer)
	if !bound.Accepted || bound.ErrorCode != nil {
		t.Fatalf("late binding failed: %+v", bound)
	}
	checked := fixture.core.checkRequest(fixture.request, peer)
	if !checked.Accepted || checked.Envelope == nil ||
		checked.Envelope.Attribution.BindingMethod != "process-birth-unique-candidate" ||
		checked.Envelope.Attribution.LateBindingCandidateCount != 1 ||
		!slices.Contains(checked.Envelope.Attribution.EvidenceKinds, "late-process-binding") {
		t.Fatalf("late-bound request lost causal evidence: %+v", checked)
	}
}

func TestBrokerLateBindingDoesNotTreatCommandKeywordsAsIdentity(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted {
		t.Fatalf("host registration failed: %+v", registered)
	}
	peer := cloneProcessChain(fixture.requestPeer)
	peer.Nodes[0].Path = "/Library/Application Support/Beholder/bin/ssh"
	peer.Roles[0] = "ssh-client"
	bound := fixture.core.registerLatestExecutionRoot(fixture.sessionID, leasePurposeSSH, peer)
	if !bound.Accepted {
		t.Fatalf("neutral tool observation was rejected by a purpose heuristic: %+v", bound)
	}
}

func TestBrokerLateBindingExcludesObservationsAfterProcessBirth(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	sshHost := fixture.host
	sshHost.ToolInput = json.RawMessage(`{"command":"ssh example.invalid"}`)
	sshHost.ToolInputFeatures = deriveToolInputFeatures("ssh example.invalid")
	sshRegistration := fixture.core.registerHost(sshHost, fixture.hookPeer)
	if !sshRegistration.Accepted {
		t.Fatalf("SSH host registration failed: %+v", sshRegistration)
	}
	fixture.advance(time.Millisecond)
	mayHost := fixture.host
	mayHost.ToolUseID = "tool-use-test-newer-may"
	mayHost.ToolInput = json.RawMessage(`{"command":"may read fixture"}`)
	mayHost.ToolInputFeatures = deriveToolInputFeatures("may read fixture")
	if registered := fixture.core.registerHost(mayHost, fixture.hookPeer); !registered.Accepted {
		t.Fatalf("newer may registration failed: %+v", registered)
	}
	peer := cloneProcessChain(fixture.requestPeer)
	peer.Nodes[0].Path = "/Library/Application Support/Beholder/bin/ssh"
	peer.Roles[0] = "ssh-client"
	if bound := fixture.core.registerLatestExecutionRoot(fixture.sessionID, leasePurposeSSH, peer); !bound.Accepted {
		t.Fatalf("process birth association failed: %+v", bound)
	}
	claim := fixture.core.claimsByToolRef[sshRegistration.ToolRef]
	if claim == nil || claim.executionRootRef == "" {
		t.Fatal("process birth did not select its only earlier observation")
	}
}

func TestBrokerLateBindingFailsClosedOnAnExactTemporalTie(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	first := fixture.host
	first.ToolInput = json.RawMessage(`{"command":"ssh first.invalid"}`)
	first.ToolInputFeatures = deriveToolInputFeatures("ssh first.invalid")
	if registered := fixture.core.registerHost(first, fixture.hookPeer); !registered.Accepted {
		t.Fatal("first host registration failed")
	}
	second := first
	second.ToolUseID = "tool-use-test-tied-ssh"
	second.ToolInput = json.RawMessage(`{"command":"ssh second.invalid"}`)
	if registered := fixture.core.registerHost(second, fixture.hookPeer); !registered.Accepted {
		t.Fatal("second host registration failed")
	}
	peer := cloneProcessChain(fixture.requestPeer)
	peer.Nodes[0].Path = "/Library/Application Support/Beholder/bin/ssh"
	peer.Roles[0] = "ssh-client"
	result := fixture.core.registerLatestExecutionRoot(fixture.sessionID, leasePurposeSSH, peer)
	if result.Accepted || result.ErrorCode == nil || *result.ErrorCode != "late-binding-ambiguous" {
		t.Fatalf("tied observations were guessed instead of escalated: %+v", result)
	}
}

func TestBrokerConcurrentLateBindingHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	fixture.host.ToolInput = json.RawMessage(`{"command":"ssh example.invalid"}`)
	fixture.host.ToolInputFeatures = deriveToolInputFeatures("ssh example.invalid")
	if registered := fixture.core.registerHost(fixture.host, fixture.hookPeer); !registered.Accepted {
		t.Fatal("host registration failed")
	}
	const contenders = 32
	results := make(chan wireResponse, contenders)
	var group sync.WaitGroup
	for index := 0; index < contenders; index++ {
		peer := cloneProcessChain(fixture.requestPeer)
		peer.Nodes[0].PID += 1000 + index
		peer.Nodes[1].PID += 1000 + index
		peer.Nodes[0].ParentPID = peer.Nodes[1].PID
		peer.Nodes[0].StartMicroseconds += uint64(index + 1)
		peer.Nodes[0].Path = "/Library/Application Support/Beholder/bin/ssh"
		peer.Roles[0] = "ssh-client"
		group.Add(1)
		go func(peer processChain) {
			defer group.Done()
			results <- fixture.core.registerLatestExecutionRoot(fixture.sessionID, leasePurposeSSH, peer)
		}(peer)
	}
	group.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.Accepted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent late bind winners=%d, want 1", winners)
	}
}

func TestPublicToolRefCanBindOnlyOneExecutionRoot(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted || !safeToolRef(registered.ToolRef) ||
		strings.Contains(registered.ToolRef, fixture.toolUseID) {
		t.Fatalf("host did not return a privacy-safe public tool ref: %+v", registered)
	}
	firstRoot := cloneProcessChain(fixture.executionPeer)
	firstRoot.Nodes[0].PID += 100
	firstRoot.Nodes[1].PID += 100
	if first := fixture.core.registerExecutionRoot(registered.ToolRef, fixture.sessionID, firstRoot); !first.Accepted {
		t.Fatalf("first execution root was rejected: %+v", first)
	}
	second := fixture.core.registerExecutionRoot(registered.ToolRef, fixture.sessionID, fixture.executionPeer)
	if second.Accepted || second.ErrorCode == nil || *second.ErrorCode != "tool-ref-already-claimed" {
		t.Fatalf("public tool ref was claimed by two roots: %+v", second)
	}
}

func TestPublicToolRefConcurrentClaimHasExactlyOneWinner(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted {
		t.Fatal("host registration failed")
	}
	const contenders = 32
	results := make(chan wireResponse, contenders)
	var group sync.WaitGroup
	for index := 0; index < contenders; index++ {
		peer := cloneProcessChain(fixture.executionPeer)
		peer.Nodes[0].PID += 1000 + index
		peer.Nodes[1].PID += 1000 + index
		peer.Nodes[0].ParentPID = peer.Nodes[1].PID
		peer.Nodes[0].StartMicroseconds += uint64(index + 1)
		peer.Nodes[1].PID += 1000 + index
		peer.Nodes[1].StartMicroseconds += uint64(index + 1)
		group.Add(1)
		go func(peer processChain) {
			defer group.Done()
			results <- fixture.core.registerExecutionRoot(registered.ToolRef, fixture.sessionID, peer)
		}(peer)
	}
	group.Wait()
	close(results)
	winners := 0
	losers := 0
	for result := range results {
		if result.Accepted {
			winners++
			continue
		}
		if result.ErrorCode == nil || *result.ErrorCode != "tool-ref-already-claimed" {
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
		losers++
	}
	if winners != 1 || losers != contenders-1 {
		t.Fatalf("concurrent claims winners=%d losers=%d", winners, losers)
	}
}

func TestExecutionRegistrarRejectsWrongThreadAndNonCodexAncestry(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	registered := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if !registered.Accepted {
		t.Fatal("host registration failed")
	}
	wrongThread := fixture.core.registerExecutionRoot(
		registered.ToolRef, "session-other-task", fixture.executionPeer,
	)
	if wrongThread.Accepted || wrongThread.ErrorCode == nil || *wrongThread.ErrorCode != "task-binding-mismatch" {
		t.Fatalf("wrong thread claimed the tool ref: %+v", wrongThread)
	}
	terminalPeer := cloneProcessChain(fixture.executionPeer)
	terminalPeer.Nodes = terminalPeer.Nodes[:3]
	terminalPeer.Roles = terminalPeer.Roles[:3]
	terminalResult := fixture.core.registerExecutionRoot(registered.ToolRef, fixture.sessionID, terminalPeer)
	if terminalResult.Accepted || terminalResult.ErrorCode == nil ||
		*terminalResult.ErrorCode != "codex-host-ancestry-unverified" {
		t.Fatalf("non-Codex registrar ancestry was accepted: %+v", terminalResult)
	}
	if legitimate := fixture.core.registerExecutionRoot(
		registered.ToolRef, fixture.sessionID, fixture.executionPeer,
	); !legitimate.Accepted {
		t.Fatalf("failed attempts burned the legitimate tool ref: %+v", legitimate)
	}
}

func TestDetachedBackgroundChildLosesExecutionRootAttribution(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("host registration failed")
	}
	detached := cloneProcessChain(fixture.requestPeer)
	detached.Nodes = append(detached.Nodes[:1], detached.Nodes[2:]...)
	detached.Roles = append(detached.Roles[:1], detached.Roles[2:]...)
	checked := fixture.core.checkRequest(fixture.request, detached)
	assertEscalated(t, checked, "execution-root-unverified")
}

func TestBrokerAllowsSameThreadAcrossDifferentRuntimeBindingsWhenRootsAreExact(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("first host registration failed")
	}
	secondHost := fixture.host
	secondHost.ToolUseID = "tool-use-test-bravo"
	secondHookPeer := cloneProcessChain(fixture.hookPeer)
	secondHookPeer.Nodes[1].PID += 100
	secondHookPeer.Nodes[1].StartMicroseconds += 1
	second := fixture.core.registerHost(secondHost, secondHookPeer)
	if !second.Accepted {
		t.Fatal("second host registration failed")
	}
	secondExecutionPeer := cloneProcessChain(fixture.executionPeer)
	secondExecutionPeer.Nodes[0].PID += 100
	secondExecutionPeer.Nodes[1].PID += 100
	secondExecutionPeer.Nodes[2] = secondHookPeer.Nodes[1]
	if entered := fixture.core.registerExecutionRoot(second.ToolRef, fixture.sessionID, secondExecutionPeer); !entered.Accepted {
		t.Fatalf("second runtime root registration failed: %+v", entered)
	}
	checked := fixture.checkPrimaryRequest()
	if !checked.Accepted || checked.Envelope.Attribution.RuntimeBindingCount != 2 {
		t.Fatalf("exact execution root was rejected by unrelated live runtime: %+v", checked)
	}
}

func TestBrokerLiveObservationSurvivesLeaseExpiryAndRestartFailsClosed(t *testing.T) {
	t.Parallel()
	fixture := newBrokerFixture(t)
	if !fixture.registerPrimaryHost().Accepted {
		t.Fatal("host registration failed")
	}
	fixture.advance(31 * time.Second)
	expired := fixture.checkPrimaryRequest()
	if !expired.Accepted {
		t.Fatalf("live root expired with nonce TTL: %+v", expired)
	}

	restarted, err := newBrokerWithKey(fixture.root, "fixture", "", "", 30*time.Second, bytes.Repeat([]byte{9}, 32), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	restartResult := restarted.checkRequest(fixture.request, fixture.requestPeer)
	assertEscalated(t, restartResult, "execution-root-unverified")
}

func TestDerivedToolFeaturesNeverRetainRawCommand(t *testing.T) {
	t.Parallel()
	secret := "TOKEN=E1_BROKER_FEATURE_SENTINEL"
	features := deriveToolInputFeatures(secret + " ~/.onenod/bin/may preflight | ssh -G example.invalid")
	if !features.HasPipe ||
		!slices.Contains(features.Families, "onenod") || !slices.Contains(features.Families, "ssh") {
		t.Fatalf("coarse features missing: %+v", features)
	}
	encoded, err := json.Marshal(features)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(secret)) || bytes.Contains(encoded, []byte("example.invalid")) {
		t.Fatalf("feature record retained raw input: %s", encoded)
	}
}

func TestDerivedToolFeaturesRecognizeMacPeerInsideExecSource(t *testing.T) {
	t.Parallel()
	source := "const result = await tools.exec_command({cmd: `mac-peer macbook true`});"
	features := deriveToolInputFeatures(source)
	if !slices.Contains(features.Families, "ssh") || !slices.Contains(features.Families, "network") {
		t.Fatalf("freeform exec source lost peer-Mac purpose evidence: %+v", features)
	}
}

type brokerFixture struct {
	t              *testing.T
	root           string
	transcriptPath string
	sessionID      string
	turnID         string
	toolUseID      string
	targetID       string
	sentinel       string
	current        time.Time
	core           *broker
	host           hostObservation
	request        requestObservation
	hookPeer       processChain
	executionPeer  processChain
	requestPeer    processChain
	toolRef        string
}

func newBrokerFixture(t *testing.T) *brokerFixture {
	t.Helper()
	fixture := &brokerFixture{
		t: t, root: t.TempDir(), sessionID: "session-test-alpha", turnID: "turn-test-alpha",
		toolUseID: "tool-use-test-alpha", targetID: "fixture-target-alpha",
		sentinel: "E1_BROKER_RAW_SENTINEL_DO_NOT_STORE",
		current:  time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC),
	}
	fixture.transcriptPath = filepath.Join(fixture.root, "session.jsonl")
	writeSessionFixture(t, fixture.transcriptPath, fixture.sessionID, fixture.turnID, fixture.root)
	core, err := newBrokerWithKey(
		fixture.root, "fixture", "", "", 30*time.Second, bytes.Repeat([]byte{7}, 32), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.core = core
	core.processAlive = func(processIdentity) bool { return true }
	if result := fixture.core.contexts.registerPrompt(
		fixture.sessionID,
		fixture.turnID,
		[]byte("fixture current human prompt"),
	); !result.Accepted {
		t.Fatal(result)
	}
	fixture.host = hostObservation{
		SessionID: fixture.sessionID, TurnID: fixture.turnID, ToolUseID: fixture.toolUseID,
		TranscriptPath: fixture.transcriptPath, CWD: fixture.root,
		HookEventName: "PreToolUse", ToolName: "Bash", Model: "gpt-5.6-luna",
		PermissionMode: "dontAsk", ObservedAt: fixture.current.Format(time.RFC3339Nano),
		ToolInput:         json.RawMessage(`{"command":"~/.onenod/bin/may preflight"}`),
		ToolInputFeatures: deriveToolInputFeatures(fixture.sentinel + " ~/.onenod/bin/may preflight"),
	}
	fixture.request = requestObservation{
		ThreadID: fixture.sessionID, Nonce: "request-nonce-alpha", Surface: "tool-child",
		Operation: "probe.observe", TargetKind: "fixture", TargetID: fixture.targetID,
		ObservedAt:          fixture.current.Format(time.RFC3339Nano),
		EnvironmentPresence: environmentPresence{CodexThreadID: true, CodexSessionID: true, ThreadSessionEqual: true},
	}
	fixture.hookPeer = syntheticHookPeer(fixture.root)
	fixture.executionPeer = syntheticExecutionPeer(fixture.root)
	fixture.requestPeer = syntheticRequestPeer(fixture.root)
	// Put synthetic process births in the same wall-clock domain as registration.
	for _, chain := range []*processChain{&fixture.hookPeer, &fixture.executionPeer, &fixture.requestPeer} {
		for i := range chain.Nodes {
			if chain.Roles[i] == "shell" {
				chain.Nodes[i].StartSeconds = uint64(fixture.current.Unix())
			}
		}
	}
	return fixture
}

func (fixture *brokerFixture) now() time.Time { return fixture.current }

func (fixture *brokerFixture) advance(duration time.Duration) {
	fixture.current = fixture.current.Add(duration)
}

func (fixture *brokerFixture) registerPrimaryHost() wireResponse {
	response := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if response.Accepted {
		fixture.toolRef = response.ToolRef
		entered := fixture.core.registerExecutionRoot(response.ToolRef, fixture.sessionID, fixture.executionPeer)
		if !entered.Accepted {
			fixture.t.Fatalf("execution root registration failed: %+v", entered)
		}
	}
	return response
}

func (fixture *brokerFixture) checkPrimaryRequest() wireResponse {
	return fixture.core.checkRequest(fixture.request, fixture.requestPeer)
}

func syntheticHookPeer(cwd string) processChain {
	nodes := []processIdentity{
		{PID: 110, ParentPID: 140, StartSeconds: 10, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/fixture/beholder-e1-context", CWD: cwd},
		{PID: 140, ParentPID: 150, StartSeconds: 7, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/codex", CWD: cwd},
		{PID: 150, ParentPID: 1, StartSeconds: 6, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/ChatGPT", CWD: cwd},
	}
	return processChain{Nodes: nodes, Roles: []string{"managed-hook", "codex-runtime", "codex-desktop-host"}}
}

func syntheticExecutionPeer(cwd string) processChain {
	nodes := []processIdentity{
		{PID: 160, ParentPID: 120, StartSeconds: 11, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/fixture/beholder-e1-context", CWD: cwd},
		{PID: 120, ParentPID: 140, StartSeconds: 9, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/bin/zsh", CWD: cwd},
		{PID: 140, ParentPID: 150, StartSeconds: 7, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/codex", CWD: cwd},
		{PID: 150, ParentPID: 1, StartSeconds: 6, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/ChatGPT", CWD: cwd},
	}
	return processChain{Nodes: nodes, Roles: []string{"managed-hook", "shell", "codex-runtime", "codex-desktop-host"}}
}

func syntheticRequestPeer(cwd string) processChain {
	nodes := []processIdentity{
		{PID: 210, ParentPID: 120, StartSeconds: 11, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/fixture/e1-beholder-core", CWD: cwd},
		{PID: 120, ParentPID: 140, StartSeconds: 9, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/bin/zsh", CWD: cwd},
		{PID: 140, ParentPID: 150, StartSeconds: 7, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/codex", CWD: cwd},
		{PID: 150, ParentPID: 1, StartSeconds: 6, UID: uint32(os.Geteuid()), RealUID: uint32(os.Getuid()), Path: "/Applications/ChatGPT.app/ChatGPT", CWD: cwd},
	}
	return processChain{Nodes: nodes, Roles: []string{"beholder-core-client", "shell", "codex-runtime", "codex-desktop-host"}}
}

func cloneProcessChain(chain processChain) processChain {
	return processChain{Nodes: append([]processIdentity(nil), chain.Nodes...), Roles: append([]string(nil), chain.Roles...)}
}

func writeSessionFixture(t *testing.T, path, sessionID, turnID, cwd string) {
	t.Helper()
	entries := []map[string]any{
		{"type": "session_meta", "payload": map[string]any{"id": sessionID, "cwd": cwd}},
		{"type": "turn_context", "payload": map[string]any{"turn_id": turnID, "cwd": cwd}},
		{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": turnID}},
		{"type": "response_item", "payload": map[string]any{"type": "custom_tool_call", "name": "functions.exec"}},
	}
	var encoded bytes.Buffer
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		encoded.Write(line)
		encoded.WriteByte('\n')
	}
	if err := os.WriteFile(path, encoded.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func featureNamed(features []featureDescriptor, name string) bool {
	for _, feature := range features {
		if feature.Name == name {
			return true
		}
	}
	return false
}

func assertEscalated(t *testing.T, response wireResponse, code string) {
	t.Helper()
	if response.Accepted || response.ErrorCode == nil || *response.ErrorCode != code || response.Envelope == nil ||
		response.Envelope.Collection.Status != "incomplete" || response.Envelope.Gatekeeper.Disposition != "escalate" {
		t.Fatalf("expected escalate/%s, got %+v", code, response)
	}
}

func TestBrokerConnectionErrorCodeIsPrivacySafe(t *testing.T) {
	if got := brokerConnectionErrorCode(brokerConnectionFailure{code: "invalid-wire-request"}); got != "invalid-wire-request" {
		t.Fatalf("brokerConnectionErrorCode() = %q", got)
	}
	if got := brokerConnectionErrorCode(assertionError("sensitive detail")); got != "broker-handler-failed" {
		t.Fatalf("unexpected fallback code: %q", got)
	}
}

type assertionError string

func (err assertionError) Error() string { return string(err) }
