package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func concurrentPeer(f *brokerFixture, offset int) processChain {
	peer := cloneProcessChain(f.requestPeer)
	peer.Nodes[0].PID += offset
	peer.Nodes[1].PID += offset
	peer.Nodes[0].ParentPID = peer.Nodes[1].PID
	peer.Nodes[0].Path, peer.Roles[0] = "/fixture/may", "onenod-requester"
	return peer
}

func TestConcurrentExecutionSnapshotsSurviveOtherProcessExitAndToolCompletion(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if result := f.core.registerHost(f.host, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	first, second := concurrentPeer(f, 100), concurrentPeer(f, 200)
	for _, peer := range []processChain{first, second} {
		if result := f.core.registerLatestExecutionRoot(f.sessionID, "direct", peer); !result.Accepted {
			t.Fatal(result)
		}
	}
	event := lifecycleObservation{SessionID: f.sessionID, TurnID: f.turnID, ToolUseID: f.toolUseID,
		TranscriptPath: f.transcriptPath, Event: "PostToolUse", Terminal: true}
	if result := f.core.observeLifecycle(event, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	if len(f.core.contexts.tools) != 0 || len(f.core.claimRefByExecution) != 2 {
		t.Fatal("source observation completion consumed a live execution")
	}
	f.core.processAlive = func(p processIdentity) bool { return p.PID != first.Nodes[1].PID }
	f.advance(15 * time.Minute)
	checked := f.core.checkRequest(f.request, second)
	defer checked.clearTransient()
	if !checked.Accepted || string(checked.decisionContext.ToolInput) != string(f.host.ToolInput) ||
		len(f.core.claimRefByExecution) != 1 || f.core.executionContextBytes == 0 {
		t.Fatal("one process exit invalidated another live execution or its delayed request")
	}
	// Returned copies must not mutate the immutable snapshot used by a lease.
	checked.decisionContext.ToolInput[0] = '!'
	context, result := f.core.acquireDecisionContext(checked.contextTurnRef, checked.contextToolUseRef)
	if !result.Accepted || string(context.ToolInput) != string(f.host.ToolInput) {
		t.Fatal("a request mutated the shared execution snapshot")
	}
	context.clear()
	event.Event, event.ToolUseID = "Interrupt", ""
	f.core.observeLifecycle(event, f.hookPeer)
	if _, result := f.core.acquireDecisionContext(checked.contextTurnRef, checked.contextToolUseRef); result.Accepted || f.core.executionContextBytes != 0 {
		t.Fatal("cancelled snapshot survived or its memory was not released")
	}
}

func TestConcurrentCandidateSetKeepsTaskAndRuntimeSeparationAndReplay(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if result := f.core.registerHost(f.host, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	other := f.host
	other.SessionID, other.ToolUseID = "different-task-session", "different-task-tool-use"
	other.TranscriptPath = filepath.Join(f.root, "different-task.jsonl")
	other.ToolInput = json.RawMessage(`{"command":"OTHER_TASK_MUST_NOT_ENTER_MODEL"}`)
	writeSessionFixture(t, other.TranscriptPath, other.SessionID, other.TurnID, f.root)
	f.core.contexts.registerPrompt(other.SessionID, other.TurnID, []byte("other task"))
	if result := f.core.registerHost(other, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	peer := concurrentPeer(f, 100)
	bound := f.core.registerLatestExecutionRoot(f.sessionID, "direct", peer)
	if !bound.Accepted || bound.BindingAttempt.EligibleCount != 1 || bound.BindingAttempt.Excluded["different-task"] != 1 {
		t.Fatal("other task observation was mixed into the candidate set")
	}
	checked := f.core.checkRequest(f.request, peer)
	defer checked.clearTransient()
	if !checked.Accepted || bytes.Contains(checked.decisionContext.ToolInput, []byte("OTHER_TASK")) {
		t.Fatal("other task input crossed the binding")
	}
	assertEscalated(t, f.core.checkRequest(f.request, peer), "request-replay")
	if result := f.core.registerLatestExecutionRoot(other.SessionID, "direct", peer); result.Accepted || *result.ErrorCode != "late-binding-conflict" {
		t.Fatal("bound process changed task")
	}
	wrongRuntime := concurrentPeer(f, 200)
	wrongRuntime.Nodes[2].PID++
	wrongRuntime.Nodes[1].ParentPID = wrongRuntime.Nodes[2].PID
	if result := f.core.registerLatestExecutionRoot(f.sessionID, "direct", wrongRuntime); result.Accepted || *result.ErrorCode != "late-binding-missing" {
		t.Fatal("unobserved runtime obtained a binding")
	}
}

func TestConcurrentCandidateSetRejectsConflictingActiveTranscriptFiles(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	f.core.registerHost(f.host, f.hookPeer)
	other := f.host
	other.ToolUseID = "same-task-another-rollout-tool"
	other.TranscriptPath = filepath.Join(f.root, "duplicate-rollout.jsonl")
	writeSessionFixture(t, other.TranscriptPath, other.SessionID, other.TurnID, f.root)
	if result := f.core.registerHost(other, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	result := f.core.registerLatestExecutionRoot(f.sessionID, "direct", concurrentPeer(f, 100))
	if result.Accepted || *result.ErrorCode != "late-binding-session-conflict" || result.BindingAttempt.EligibleCount != 2 {
		t.Fatal("different active transcript identities were arbitrarily selected")
	}
}

func TestConcurrentCandidatesAcrossTurnsUseChronologyAnchorWithoutSelectingATool(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	f.core.registerHost(f.host, f.hookPeer)
	f.advance(time.Second)
	other := f.host
	other.ToolUseID, other.TurnID = "second-turn-tool-use", "second-turn-identifier"
	other.ToolInput = json.RawMessage(`{"command":"second operation"}`)
	file, err := os.OpenFile(f.transcriptPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(file).Encode(map[string]any{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": other.TurnID}}); err != nil {
		t.Fatal(err)
	}
	file.Close()
	f.core.contexts.registerPrompt(f.sessionID, other.TurnID, []byte("second direction"))
	if result := f.core.registerHost(other, f.hookPeer); !result.Accepted {
		t.Fatal(result)
	}
	peer := concurrentPeer(f, 100)
	peer.Nodes[1].StartSeconds = uint64(f.current.Unix())
	if result := f.core.registerLatestExecutionRoot(f.sessionID, "direct", peer); !result.Accepted {
		t.Fatal(result)
	}
	checked := f.core.checkRequest(f.request, peer)
	defer checked.clearTransient()
	if !checked.Accepted || checked.Envelope.Attribution.TurnRef != "" ||
		checked.Envelope.Attribution.ToolUseRef != "" ||
		!bytes.Contains(checked.decisionContext.ToolInput, []byte("chronology-only")) {
		t.Fatal("chronology anchor was presented as a uniquely identified causal tool")
	}
	// Cancellation of either contributing turn invalidates the whole snapshot.
	f.core.observeLifecycle(lifecycleObservation{SessionID: f.sessionID, TurnID: other.TurnID,
		TranscriptPath: f.transcriptPath, Event: "Interrupt"}, f.hookPeer)
	if _, result := f.core.acquireDecisionContext(checked.contextTurnRef, checked.contextToolUseRef); result.Accepted {
		t.Fatal("a cancelled candidate remained available to a pending transport")
	}
}

func TestCandidateDiagnosticLimitDoesNotTruncateModelContext(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	for i := 0; i < 35; i++ {
		host := f.host
		host.ToolUseID = fmt.Sprintf("concurrent-tool-%02d", i)
		host.ToolInput = json.RawMessage(fmt.Sprintf(`{"command":"candidate-%02d"}`, i))
		if result := f.core.registerHost(host, f.hookPeer); !result.Accepted {
			t.Fatal(result)
		}
	}
	peer := concurrentPeer(f, 100)
	bound := f.core.registerLatestExecutionRoot(f.sessionID, "direct", peer)
	if !bound.Accepted || !bound.BindingAttempt.CandidatesTruncated || len(bound.BindingAttempt.Candidates) != 32 {
		t.Fatal("diagnostic candidate summary was not bounded")
	}
	checked := f.core.checkRequest(f.request, peer)
	defer checked.clearTransient()
	var captured struct {
		Candidates []capturedExecutionCandidate `json:"candidates"`
	}
	if !checked.Accepted || json.Unmarshal(checked.decisionContext.ToolInput, &captured) != nil || len(captured.Candidates) != 35 {
		t.Fatal("model input silently lost candidates beyond the diagnostic limit")
	}
}

func TestDirectBindingFailurePreservesOriginalErrorAndCandidateDiagnostics(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	transport, err := newTransportCoordinator(f.core, f.root, filepath.Join(f.root, "unused.sock"), "", "", time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.close()
	target := operationTarget{SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may", Operation: "secret.read",
		TargetKind: "onepassword-item", TargetID: "dummy-item", PayloadDigest: strings.Repeat("a", 64)}
	result := transport.checkDirectOperation(f.sessionID, "direct-failure-nonce", target, concurrentPeer(f, 100))
	if result.Accepted || result.ErrorCode == nil || *result.ErrorCode != "late-binding-missing" ||
		result.BindingAttempt == nil || result.BindingAttempt.EligibleCount != 0 {
		t.Fatalf("initial binding failure was replaced by a generic execution-root error: %+v", result)
	}
}

func TestConcurrentSnapshotRejectsSubsequentConflictingHookInput(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	f.core.registerHost(f.host, f.hookPeer)
	peer := concurrentPeer(f, 100)
	f.core.registerLatestExecutionRoot(f.sessionID, "direct", peer)
	checked := f.core.checkRequest(f.request, peer)
	defer checked.clearTransient()
	if !checked.Accepted {
		t.Fatal("initial request failed")
	}
	changed := f.host
	changed.ToolInput = json.RawMessage(`{"command":"conflicting replacement"}`)
	if result := f.core.registerHost(changed, f.hookPeer); result.Accepted {
		t.Fatal("conflicting source input accepted")
	}
	if _, result := f.core.acquireDecisionContext(checked.contextTurnRef, checked.contextToolUseRef); result.Accepted || result.ErrorCode != "tool-input-observation-conflict" {
		t.Fatal("a pending lease retained a conflicted snapshot")
	}
}

func TestConcurrentDirectReadAndPatchHaveIndependentRequestBindings(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	f.core.registerHost(f.host, f.hookPeer)
	transport, err := newTransportCoordinator(f.core, f.root, filepath.Join(f.root, "unused.sock"), "", "", time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer transport.close()
	for i, operation := range []string{"secret.read", "item.patch"} {
		target := operationTarget{SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may", Operation: operation,
			TargetKind: "onepassword-item", TargetID: "dummy-item", PayloadDigest: strings.Repeat("a", 64)}
		result := transport.checkDirectOperation(f.sessionID, fmt.Sprintf("independent-request-%d", i), target, concurrentPeer(f, i*100))
		defer result.clearTransient()
		if !result.Accepted || result.Envelope.Attribution.LateBindingCandidateCount != 1 ||
			result.Envelope.Request.Operation != operation {
			t.Fatalf("concurrent %s lost its operation or execution context: %+v", operation, result)
		}
	}
	if len(f.core.claimRefByExecution) != 2 || len(f.core.nonces) != 2 {
		t.Fatal("independent direct operations shared a process binding or request nonce")
	}
}
