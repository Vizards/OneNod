package main

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"time"
)

const maximumExecutionContextBytes = 64 * 1024 * 1024

// These are captured observations, not a trusted call-to-spawn mapping. A
// process can have several eligible observations, and an observation can have
// several live executions. Neither consumes the other.
type executionCandidateEvidence struct {
	TurnRef      string     `json:"turn_ref"`
	ToolUseRef   string     `json:"tool_use_ref"`
	RegisteredAt time.Time  `json:"registered_at"`
	ReturnedAt   *time.Time `json:"returned_at,omitempty"`
}

type executionBindingAttempt struct {
	Scope                string                       `json:"scope"`
	ExecutionRef         string                       `json:"execution_ref"`
	ExecutionBornAt      time.Time                    `json:"execution_born_at"`
	ObservationsExamined int                          `json:"observations_examined"`
	EligibleCount        int                          `json:"eligible_count"`
	Excluded             map[string]int               `json:"excluded"`
	Candidates           []executionCandidateEvidence `json:"candidates"`
	CandidatesTruncated  bool                         `json:"candidates_truncated"`
}

type capturedExecutionCandidate struct {
	executionCandidateEvidence
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

func candidateEvidence(claim *hostClaim) executionCandidateEvidence {
	result := executionCandidateEvidence{
		TurnRef: claim.turnRef, ToolUseRef: claim.toolUseRef, RegisteredAt: claim.registeredAt,
	}
	if !claim.returnedAt.IsZero() {
		returned := claim.returnedAt
		result.ReturnedAt = &returned
	}
	return result
}

// registerLatestExecutionRoot retains its wire entry point, but no longer
// selects one tool by time-window uniqueness. Each kernel execution gets an
// immutable snapshot of all eligible same-task observations. The model sees
// the ambiguity; the Core still binds the actual operation to that process.
func (broker *broker) registerLatestExecutionRoot(threadID, purpose string, peer processChain) wireResponse {
	response := wireResponse{SchemaVersion: protocolSchemaVersion}
	if !safeJoinKey(threadID) || len(peer.Nodes) == 0 || len(peer.Roles) != len(peer.Nodes) {
		return responseWithError(response, "late-binding-unverified")
	}
	runtimeIndex := firstRoleIndex(peer, "codex-runtime")
	if runtimeIndex < 0 || (broker.trustMode == "production" && firstRoleIndex(peer, "codex-desktop-host") < 0) {
		return responseWithError(response, "codex-host-ancestry-unverified")
	}
	if broker.trustMode == "production" && !validLateBindingRole(peer.Roles[0], purpose) {
		return responseWithError(response, "late-binding-requester-mismatch")
	}
	threadRef := broker.keyedRef("thread", []byte(threadID))
	runtimeRef := broker.processRef(peer.Nodes[runtimeIndex])
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.expireLocked(broker.now().UTC())
	for _, node := range peer.Nodes {
		if ref, found := broker.claimRefByExecution[broker.processRef(node)]; found {
			claim := broker.claimsByToolRef[ref]
			if claim == nil || claim.threadRef != threadRef || claim.runtimeBindingRef != runtimeRef {
				return responseWithError(response, "late-binding-conflict")
			}
			response.Accepted = true
			response.BindingAttempt = claim.bindingAttempt
			return response
		}
	}
	executionIndex := runtimeIndex - 1
	if executionIndex < 0 || peer.Nodes[executionIndex].ParentPID != peer.Nodes[runtimeIndex].PID {
		return responseWithError(response, "execution-root-unverified")
	}
	execution := peer.Nodes[executionIndex]
	executionRef := broker.processRef(execution)
	born := time.Unix(int64(execution.StartSeconds), int64(execution.StartMicroseconds)*1000).UTC()
	attempt := &executionBindingAttempt{
		Scope:        "same-task-time-compatible-observations-not-spawn-proof",
		ExecutionRef: executionRef, ExecutionBornAt: born, Excluded: map[string]int{},
		Candidates: []executionCandidateEvidence{},
	}
	response.BindingAttempt = attempt
	candidates := make([]*hostClaim, 0)
	for _, claim := range broker.claimsByToolRef {
		if claim == nil || claim.executionContext != nil {
			continue // Execution snapshots are not additional Hook observations.
		}
		attempt.ObservationsExamined++
		code := ""
		switch {
		case claim.threadRef != threadRef:
			code = "different-task"
		case claim.runtimeBindingRef != runtimeRef:
			code = "different-runtime"
		case claim.executionRootRef != "":
			code = "explicitly-bound-observation"
		case claim.conflictCode != "":
			code = "conflicting-observation"
		case claim.registeredAt.After(born):
			code = "registered-after-process-birth"
		case !claim.returnedAt.IsZero() && born.After(claim.returnedAt):
			code = "returned-before-process-birth"
		}
		if code != "" {
			attempt.Excluded[code]++
			continue
		}
		candidates = append(candidates, claim)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].registeredAt.Equal(candidates[j].registeredAt) {
			return candidates[i].registeredAt.Before(candidates[j].registeredAt)
		}
		return candidates[i].toolUseRef < candidates[j].toolUseRef
	})
	attempt.EligibleCount = len(candidates)
	for _, claim := range candidates {
		if len(attempt.Candidates) < 32 {
			attempt.Candidates = append(attempt.Candidates, candidateEvidence(claim))
		} else {
			attempt.CandidatesTruncated = true // Diagnostics only; never omit model candidates.
		}
	}
	if len(candidates) == 0 {
		return responseWithError(response, "late-binding-missing")
	}
	anchor := candidates[0] // Chronology anchor only; not a selected causal tool.
	for _, claim := range candidates {
		if claim.transcriptInfo == nil || anchor.transcriptInfo == nil ||
			!os.SameFile(claim.transcriptInfo, anchor.transcriptInfo) {
			return responseWithError(response, "late-binding-session-conflict")
		}
	}
	if len(broker.claimsByToolRef) >= maximumHostObservations {
		return responseWithError(response, "observation-capacity-exceeded")
	}
	context, sources, code := broker.captureExecutionContextLocked(candidates)
	if code != "" {
		return responseWithError(response, code)
	}
	bytes := len(context.Prompt) + len(context.ToolInput)
	if bytes > maximumTransientContextSize || broker.executionContextBytes+bytes > maximumExecutionContextBytes {
		context.clear()
		return responseWithError(response, "execution-context-capacity-exceeded")
	}
	claim := *anchor
	// An invalidated execution can be observed again while the same PID lives.
	// Give each snapshot a new generation so an old in-flight model decision
	// cannot validate against a replacement snapshot for that same PID.
	broker.executionSequence++
	claim.toolRef = broker.keyedRef("execution-binding", []byte(executionRef+":"+strconv.FormatUint(broker.executionSequence, 10)))
	claim.executionRootRef, claim.executionIdentity = executionRef, execution
	claim.bindingMethod, claim.lateBindingCandidates = "process-birth-candidate-set", len(candidates)
	claim.bindingAttempt, claim.executionCandidates = attempt, sources
	claim.executionContext = &context
	claim.contextTurnRef, claim.contextToolUseRef = claim.toolRef, claim.toolRef
	if len(candidates) > 1 {
		claim.turnRef, claim.toolUseRef = "", ""
		claim.host.ToolName = "concurrent-tool-candidates"
		claim.host.ToolInputFeatures = toolInputFeatures{}
		for _, candidate := range candidates[1:] {
			if candidate.host.Model != claim.host.Model {
				claim.host.Model = ""
			}
			if candidate.host.PermissionMode != claim.host.PermissionMode {
				claim.host.PermissionMode = ""
			}
		}
	}
	broker.executionContextBytes += bytes
	broker.claimsByToolRef[claim.toolRef] = &claim
	broker.claimRefByTool[claim.contextToolUseRef] = claim.toolRef
	broker.claimRefByExecution[executionRef] = claim.toolRef
	response.Accepted = true
	return response
}

func (broker *broker) captureExecutionContextLocked(candidates []*hostClaim) (transientDecisionContext, []executionCandidateEvidence, string) {
	var output transientDecisionContext
	var sources []executionCandidateEvidence
	var captured []capturedExecutionCandidate
	defer func() {
		for i := range captured {
			clear(captured[i].ToolInput)
		}
	}()
	for i, claim := range candidates {
		context, result := broker.contexts.acquireRefs(claim.contextTurnRef, claim.contextToolUseRef)
		if !result.Accepted {
			output.clear()
			return transientDecisionContext{}, nil, result.ErrorCode
		}
		if i == 0 {
			output.Prompt = append([]byte(nil), context.Prompt...)
		}
		source := candidateEvidence(claim)
		sources = append(sources, source)
		captured = append(captured, capturedExecutionCandidate{
			executionCandidateEvidence: source, ToolName: claim.host.ToolName,
			ToolInput: append(json.RawMessage(nil), context.ToolInput...),
		})
		context.clear()
	}
	if len(captured) == 1 {
		output.ToolInput = append(json.RawMessage(nil), captured[0].ToolInput...)
	} else {
		var err error
		output.ToolInput, err = json.Marshal(struct {
			Kind        string                       `json:"kind"`
			Scope       string                       `json:"verification_scope"`
			AnchorScope string                       `json:"prompt_anchor_scope"`
			Candidates  []capturedExecutionCandidate `json:"candidates"`
		}{"concurrent-tool-candidates", "same-task-observations; exact-causal-tool-unresolved",
			"earliest-eligible-observation-for-chronology-only", captured})
		if err != nil {
			output.clear()
			return transientDecisionContext{}, nil, "execution-context-unavailable"
		}
	}
	return output, sources, ""
}

func (broker *broker) acquireDecisionContext(turnRef, toolRef string) (transientDecisionContext, transientContextResult) {
	broker.mu.Lock()
	broker.expireLocked(broker.now().UTC())
	claim := broker.claimsByToolRef[toolRef]
	if claim != nil && claim.executionContext != nil && claim.contextTurnRef == turnRef {
		if claim.conflictCode != "" {
			broker.mu.Unlock()
			return transientDecisionContext{}, transientContextResult{ErrorCode: claim.conflictCode}
		}
		context := transientDecisionContext{
			Prompt:    append([]byte(nil), claim.executionContext.Prompt...),
			ToolInput: append(json.RawMessage(nil), claim.executionContext.ToolInput...),
		}
		broker.mu.Unlock()
		return context, transientContextResult{Accepted: true, turnRef: turnRef, toolRef: toolRef}
	}
	broker.mu.Unlock()
	return broker.contexts.acquireRefs(turnRef, toolRef)
}

func (broker *broker) invalidateExecutionCandidatesLocked(source *hostClaim, code string) {
	for _, claim := range broker.claimsByToolRef {
		if claim.executionContext == nil || claim.threadRef != source.threadRef {
			continue
		}
		for _, candidate := range claim.executionCandidates {
			if candidate.TurnRef == source.turnRef && candidate.ToolUseRef == source.toolUseRef {
				claim.conflictCode = code
				break
			}
		}
	}
}

func claimContainsTurn(claim *hostClaim, turn string) bool {
	if claim.turnRef == turn {
		return true
	}
	for _, candidate := range claim.executionCandidates {
		if candidate.TurnRef == turn {
			return true
		}
	}
	return false
}
