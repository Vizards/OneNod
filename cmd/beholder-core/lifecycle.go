package main

import "os"

type lifecycleObservation struct {
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id,omitempty"`
	ToolUseID      string `json:"tool_use_id,omitempty"`
	TranscriptPath string `json:"transcript_path"`
	Event          string `json:"event"`
	Terminal       bool   `json:"terminal"`
}

func (broker *broker) observeLifecycle(event lifecycleObservation, peer processChain) wireResponse {
	response := wireResponse{SchemaVersion: protocolSchemaVersion}
	if !safeJoinKey(event.SessionID) || !pathWithin(broker.sessionRoot, event.TranscriptPath) {
		return responseWithError(response, "invalid-lifecycle-request")
	}
	if _, _, code := broker.validateHookPeer(peer); code != "" {
		return responseWithError(response, code)
	}
	switch event.Event {
	case "PostToolUse":
		if !safeJoinKey(event.ToolUseID) || !safeJoinKey(event.TurnID) {
			return responseWithError(response, "invalid-lifecycle-request")
		}
	case "Stop", "Interrupt":
		if !safeJoinKey(event.TurnID) || event.ToolUseID != "" {
			return responseWithError(response, "invalid-lifecycle-request")
		}
	case "SessionEnd":
		if event.ToolUseID != "" {
			return responseWithError(response, "invalid-lifecycle-request")
		}
	default:
		return responseWithError(response, "invalid-lifecycle-request")
	}
	metadataID, _, err := readSessionMetadata(event.TranscriptPath)
	if err != nil || metadataID != event.SessionID {
		return responseWithError(response, "hook-evidence-conflict")
	}
	info, err := os.Stat(event.TranscriptPath)
	if err != nil {
		return responseWithError(response, "session-metadata-unavailable")
	}
	runtime := broker.processRef(peer.Nodes[firstRoleIndex(peer, "codex-runtime")])
	thread := broker.keyedRef("thread", []byte(event.SessionID))
	turn := broker.keyedRef("turn", []byte(event.TurnID))
	tool := broker.keyedRef("tool-use", []byte(event.ToolUseID))
	broker.mu.Lock()
	defer broker.mu.Unlock()
	for _, claim := range broker.claimsByToolRef {
		if claim.threadRef != thread || claim.runtimeBindingRef != runtime || claim.transcriptInfo == nil || !os.SameFile(info, claim.transcriptInfo) {
			continue
		}
		if event.Event != "SessionEnd" && !claimContainsTurn(claim, turn) {
			continue
		}
		if event.Event == "PostToolUse" && claim.toolUseRef != tool {
			continue
		}
		if event.Event == "PostToolUse" {
			if claim.returnedAt.IsZero() {
				claim.returnedAt = broker.now().UTC()
			}
			if !event.Terminal {
				continue
			}
		}
		if event.Event == "Interrupt" || event.Event == "SessionEnd" {
			broker.removeClaimLocked(claim)
		} else if claim.executionRootRef == "" {
			// A normal tool/turn return cannot prove a PTY's process has exited.
			// Already bound executions survive until kernel exit; unbound completed
			// observations must not pollute later candidate sets.
			broker.removeClaimLocked(claim)
		}
	}
	response.Accepted = true
	return response
}

func (broker *broker) removeClaimLocked(claim *hostClaim) {
	if claim.executionContext != nil {
		broker.executionContextBytes -= len(claim.executionContext.Prompt) + len(claim.executionContext.ToolInput)
		claim.executionContext.clear()
	} else {
		broker.contexts.releaseRefs(claim.contextTurnRef, claim.contextToolUseRef)
	}
	delete(broker.claimsByToolRef, claim.toolRef)
	if broker.claimRefByTool[claim.contextToolUseRef] == claim.toolRef {
		delete(broker.claimRefByTool, claim.contextToolUseRef)
	}
	if broker.claimRefByExecution[claim.executionRootRef] == claim.toolRef {
		delete(broker.claimRefByExecution, claim.executionRootRef)
	}
}
