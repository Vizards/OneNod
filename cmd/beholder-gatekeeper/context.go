package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	maximumSessionLineSize     = 16 * 1024 * 1024
	maximumRelatedTextBytes    = maximumRelatedContextBytes
	maximumToolExcerptBytes    = maximumRelatedContextBytes
	maximumEvidenceCandidates  = 256
	earlyExcludedSamples       = 32
	maximumRelatedContextBytes = 2 * 1024 * 1024
)

var codexTaskIDPattern = regexp.MustCompile(`([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$`)

type sessionEnvelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type messagePayload struct {
	Type    string `json:"type"`
	Role    string `json:"role"`
	Phase   string `json:"phase"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	InternalMetadata struct {
		ContentItemKinds []string `json:"content_item_kinds"`
	} `json:"internal_chat_message_metadata_passthrough"`
}

type toolCallPayload struct {
	Type      string          `json:"type"`
	CallID    string          `json:"call_id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Output    json.RawMessage `json:"output"`
	Arguments json.RawMessage `json:"arguments"`
}

type relatedContext struct {
	priorHumans          []sourceText
	currentPromptOrdinal int
	priorAgentMessages   []sourceText
	currentAgentMessages []sourceText
	ambientContext       []sourceText
	completedTools       []recentToolContext
	omittedUnsafe        int
	candidates           []contextCandidate
	candidateSummary     []contextCandidateSummary
	transcriptSnapshot   transcriptSnapshot
	coverage             contextCoverage
	sessionCWD           string
	workspaceRoots       []string
}

type rawEventMetadata struct {
	bytes  int
	sha256 string
}

type countingWriter struct {
	writer io.Writer
	bytes  int64
}

func (writer *countingWriter) Write(value []byte) (int, error) {
	written, err := writer.writer.Write(value)
	writer.bytes += int64(written)
	return written, err
}

type pendingToolContext struct {
	entry          recentToolContext
	candidateIndex int
}

// transcriptCapture pins both the open session file and its exact byte length
// before the Core is acknowledged. Reading can then happen asynchronously
// without admitting later task events into the decision that caused them.
type transcriptCapture struct {
	file       *os.File
	info       os.FileInfo
	path       string
	capturedAt time.Time
	deadline   time.Time
}

func openTranscriptCapture(path string) (*transcriptCapture, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("invalid session path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		file.Close()
		return nil, errors.New("invalid session path")
	}
	return &transcriptCapture{
		file: file, info: info, path: path, capturedAt: time.Now().UTC(),
	}, nil
}

func (capture *transcriptCapture) close() {
	if capture == nil || capture.file == nil {
		return
	}
	_ = capture.file.Close()
	capture.file = nil
}

func buildExternalDecisionInput(
	request localDecisionRequest,
	targetAliases map[string]string,
) (externalDecisionInput, contextMetrics, error) {
	output, metrics, _, err := buildExternalDecisionInputWithEvidence(request, targetAliases)
	return output, metrics, err
}

func buildExternalDecisionInputWithEvidence(
	request localDecisionRequest,
	targetAliases map[string]string,
) (externalDecisionInput, contextMetrics, sourceContextEvidence, error) {
	return buildExternalDecisionInputWithEvidenceFromCapture(request, targetAliases, nil)
}

func buildExternalDecisionInputWithEvidenceFromCapture(
	request localDecisionRequest,
	targetAliases map[string]string,
	capture *transcriptCapture,
) (externalDecisionInput, contextMetrics, sourceContextEvidence, error) {
	var output externalDecisionInput
	metrics := contextMetrics{}
	capturedAt := time.Now().UTC()
	if capture != nil {
		capturedAt = capture.capturedAt
	}
	source := sourceContextEvidence{
		SchemaVersion:         gatekeeperWireSchemaVersion,
		RecordType:            "beholder_source_context",
		EvidenceID:            request.RequestID,
		CapturedAt:            capturedAt,
		TargetAlias:           externalizeTarget(request.ActualRequest, targetAliases).TargetAlias,
		OperationTargetSHA256: localOperationTargetSHA256(request.ActualRequest),
		LocalRequest:          localRequestForEvidence(request),
		Candidates:            []contextCandidate{},
		CandidateSummary:      []contextCandidateSummary{},
		RequesterContext:      rawJSONCopy(request.ActualRequest.RequesterContext),
		GatekeeperProcess:     collectEvidenceProcessContext(),
		ProcessEnvironment:    collectEvidenceEnvironment(),
	}
	prompt, validationErr := validateLocalDecisionEnvelope(request)
	if validationErr != nil {
		code := validationErr.Error()
		source.CollectorError = stringPointer(code)
		return output, metrics, source, validationErr
	}
	var related relatedContext
	var err error
	if capture == nil {
		ownedCapture, captureErr := openTranscriptCapture(request.TranscriptPath)
		if captureErr != nil {
			err = captureErr
		} else {
			ownedCapture.deadline = request.decisionDeadline
			defer ownedCapture.close()
			related, err = readRelatedContextFromCapture(ownedCapture, prompt)
		}
	} else if capture.path != request.TranscriptPath {
		err = errors.New("transcript capture path mismatch")
	} else {
		capture.deadline = request.decisionDeadline
		related, err = readRelatedContextFromCapture(capture, prompt)
	}
	source.Candidates = related.candidates
	source.CandidateSummary = related.candidateSummary
	source.TranscriptSnapshot = related.transcriptSnapshot
	if err != nil {
		code := "related-context-unavailable"
		if err.Error() == "human-context-budget-exceeded" || err.Error() == "gatekeeper-decision-budget-exhausted" {
			code = err.Error()
		}
		source.CollectorError = stringPointer(code)
		return output, metrics, source, errors.New(code)
	}

	workspace := collectWorkspaceContext(request.CWD, request.ToolInput, request.decisionDeadline)
	workspace.SessionCWD = related.sessionCWD
	workspace.WorkspaceRoots = related.workspaceRoots
	workspace.CWDSource = "core-kernel-observed-request-process"
	workspace.RepositoryScope = "repository-containing-request-process-cwd; operation-target-may-differ"
	requester := externalizeRequesterContext(request.ActualRequest.RequesterContext)
	coreEvidence, err := externalizeCoreEvidence(request.Evidence)
	if err != nil {
		code := "core-evidence-unavailable"
		source.CollectorError = stringPointer(code)
		return output, metrics, source, errors.New(code)
	}
	target := externalizeTarget(request.ActualRequest, targetAliases)
	output.SchemaVersion = externalDecisionInputSchemaVersion
	output.HumanIntent.CurrentPrompt = prompt
	output.HumanIntent.CurrentPromptOrdinal = related.currentPromptOrdinal
	output.HumanIntent.PriorMessages = related.priorHumans
	output.AgentContext.PriorTaskTrajectory = related.priorAgentMessages
	output.AgentContext.CurrentExecutionTrajectory = related.currentAgentMessages
	output.AgentContext.AmbientContext = related.ambientContext
	output.ToolCall.Name = request.ToolName
	output.ToolCall.Input = append(json.RawMessage(nil), request.ToolInput...)
	output.CompletedToolActivity = related.completedTools
	output.Coverage = related.coverage
	output.Environment = workspace
	output.RequesterContext = requester
	output.CoreEvidence = coreEvidence
	output.ActualRequest = target
	encoded, err := json.Marshal(output)
	if err != nil || len(encoded) > maximumLocalWireSize {
		clear(encoded)
		clearExternalInput(&output)
		code := "model-input-build-failed"
		if err == nil {
			code = "model-input-too-large"
		}
		if err != nil && strings.Contains(err.Error(), "model-input-provenance-invalid") {
			code = "model-input-provenance-invalid"
		}
		source.CollectorError = stringPointer(code)
		return externalDecisionInput{}, metrics, source, errors.New(code)
	}
	metrics = contextMetrics{
		PriorHumanMessages: len(related.priorHumans), PriorAgentMessages: len(related.priorAgentMessages),
		CurrentAgentMessages: len(related.currentAgentMessages), AmbientContext: len(related.ambientContext),
		CompletedTools: len(related.completedTools),
		InputBytes:     len(encoded), OmittedUnsafe: related.omittedUnsafe,
	}
	source.SelectionMetrics = metrics
	selected := cloneExternalDecisionInput(output)
	source.SelectedModelInput = &selected
	clear(encoded)
	return output, metrics, source, nil
}

func validateLocalDecisionEnvelope(request localDecisionRequest) (string, error) {
	if request.SchemaVersion != gatekeeperWireSchemaVersion ||
		(request.Mode != "shadow" && request.Mode != "shadow-submit" && request.Mode != "authoritative") ||
		request.RequestID == "" || request.ToolName == "" || !filepath.IsAbs(request.TranscriptPath) ||
		!filepath.IsAbs(request.CWD) || len(request.Prompt) == 0 || len(request.ToolInput) == 0 ||
		!json.Valid(request.ToolInput) || len(request.Evidence) == 0 || !json.Valid(request.Evidence) ||
		request.HumanOutcome != nil || !validSHA256(request.CoreBinarySHA256) ||
		!validLocalOperationTarget(request.ActualRequest) {
		return "", errors.New("invalid-local-decision-input")
	}
	prompt, ok := safeUTF8Text(request.Prompt, maximumLocalWireSize)
	if !ok {
		return "", errors.New("invalid-prompt-encoding")
	}
	return prompt, nil
}

func localOperationTargetSHA256(target operationTarget) string {
	encoded, err := json.Marshal(target)
	if err != nil {
		return ""
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func readRelatedContext(path, currentPrompt string) (relatedContext, error) {
	return readRelatedContextWithSnapshotHook(path, currentPrompt, nil)
}

func readRelatedContextWithSnapshotHook(
	path, currentPrompt string,
	afterSnapshot func(),
) (relatedContext, error) {
	capture, err := openTranscriptCapture(path)
	if err != nil {
		return relatedContext{}, err
	}
	defer capture.close()
	if afterSnapshot != nil {
		afterSnapshot()
	}
	return readRelatedContextFromCapture(capture, currentPrompt)
}

func readRelatedContextFromCapture(
	capture *transcriptCapture,
	currentPrompt string,
) (relatedContext, error) {
	var output relatedContext
	if capture == nil || capture.file == nil || capture.info == nil ||
		!capture.info.Mode().IsRegular() || capture.info.Size() <= 0 || !filepath.IsAbs(capture.path) {
		return output, errors.New("invalid session capture")
	}
	file := capture.file
	info := capture.info
	path := capture.path
	transcriptDigest := sha256.New()
	transcriptWriter := &countingWriter{writer: transcriptDigest}
	// The Codex session remains live while a decision is being built. Restrict
	// the reader to the exact descriptor size captured above so later Agent/tool
	// events cannot leak backwards into the decision that caused them.
	snapshotReader := io.NewSectionReader(file, 0, info.Size())
	scanner := bufio.NewScanner(io.TeeReader(snapshotReader, transcriptWriter))
	scanner.Buffer(make([]byte, 64*1024), maximumSessionLineSize)
	pendingTools := map[string]pendingToolContext{}
	rawMetadataByOrdinal := map[int]rawEventMetadata{}
	currentPromptBoundaryFound := false
	ordinal := 0
	for scanner.Scan() {
		if !capture.deadline.IsZero() && time.Now().After(capture.deadline) {
			return output, errors.New("gatekeeper-decision-budget-exhausted")
		}
		if err := enforceRelatedContextBudget(&output); err != nil {
			return output, err
		}
		ordinal++
		line := scanner.Bytes()
		rawDigest := sha256.Sum256(line)
		rawMetadataByOrdinal[ordinal] = rawEventMetadata{
			bytes: len(line), sha256: hex.EncodeToString(rawDigest[:]),
		}
		var envelope sessionEnvelope
		if json.Unmarshal(line, &envelope) != nil || envelope.Type == "" {
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: "invalid-session-envelope", Disposition: "excluded",
				Reason: "invalid-session-envelope",
			})
			continue
		}
		if envelope.Type == "session_meta" {
			var metadata struct {
				CWD            string   `json:"cwd"`
				WorkspaceRoots []string `json:"workspace_roots"`
			}
			if json.Unmarshal(envelope.Payload, &metadata) == nil {
				output.sessionCWD, output.workspaceRoots = metadata.CWD, metadata.WorkspaceRoots
			}
		}
		if envelope.Type != "response_item" {
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: "session-event", Disposition: "excluded",
				Reason: "non-response-item-session-event",
			})
			continue
		}
		var header struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(envelope.Payload, &header) != nil || header.Type == "" {
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: "response_item", Disposition: "excluded",
				Reason: "invalid-response-item-header",
			})
			continue
		}
		switch header.Type {
		case "message":
			var message messagePayload
			if json.Unmarshal(envelope.Payload, &message) != nil {
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: header.Type, Disposition: "excluded",
					Reason: "invalid-message-payload",
				})
				continue
			}
			message.Role = normalizedMessageRole(message.Role)
			message.Phase = normalizedMessagePhase(message.Phase)
			text := messageText(message)
			if text == "" {
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: "message", Role: message.Role, Phase: message.Phase,
					Disposition: "excluded", Reason: "empty-message",
				})
				continue
			}
			if message.Role == "user" && text == currentPrompt {
				// Use the last exact match as the current boundary. If the same prompt
				// occurred earlier, its execution becomes prior task trajectory instead
				// of disappearing from the long-horizon context.
				if currentPromptBoundaryFound {
					supersedeCurrentPromptBoundary(&output)
					for index := range output.currentAgentMessages {
						output.currentAgentMessages[index].Relation = "before-current-prompt"
						output.priorAgentMessages = append(output.priorAgentMessages, output.currentAgentMessages[index])
					}
					output.currentAgentMessages = nil
					for index := range output.completedTools {
						if output.completedTools[index].Relation == "after-current-prompt" {
							output.completedTools[index].Relation = "before-current-prompt"
						}
					}
					for callID, pending := range pendingTools {
						pending.entry.Relation = "before-current-prompt"
						pendingTools[callID] = pending
					}
				}
				currentPromptBoundaryFound = true
				output.currentPromptOrdinal = ordinal
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: "message", Role: message.Role, Phase: message.Phase,
					Content: text, Disposition: "boundary", Reason: "exact-current-prompt-from-core",
				})
				continue
			}

			// Human text must remain complete: a missing suffix can reverse consent.
			if message.Role == "user" && classifyUserMessageProvenance(message, text).humanAuthored && len(text) > maximumRelatedContextBytes {
				return output, errors.New("human-context-budget-exceeded")
			}
			trimmed, ok := safeUTF8Text([]byte(text), maximumRelatedTextBytes)
			if !ok {
				output.omittedUnsafe++
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: "message", Role: message.Role, Phase: message.Phase,
					Disposition: "excluded", Reason: "invalid-or-oversized-model-context",
				})
				continue
			}
			disposition, reason := "excluded", "role-or-phase-not-selected"
			switch {
			case message.Role == "user":
				relation := relationForBoundary(currentPromptBoundaryFound)
				provenance := classifyUserMessageProvenance(message, text)
				entry := sourceText{
					Source: provenance.source, TrustClass: provenance.trustClass, Ordinal: ordinal,
					Relation: relation, Text: trimmed,
				}
				if provenance.humanAuthored {
					output.priorHumans = append(output.priorHumans, entry)
					disposition, reason = "included", "prior-human-message"
				} else {
					var displaced, superseded int
					output.ambientContext, displaced, superseded = appendAmbientContext(
						output.ambientContext, entry, len(output.ambientContext)+1,
					)
					if displaced > 0 {
						displaceCandidateByOrdinal(&output, displaced, "bounded-ambient-context-window")
					}
					if superseded > 0 {
						displaceCandidateByOrdinal(&output, superseded, "superseded-duplicate-ambient-context")
					}
					disposition, reason = "included", provenance.reason
				}
			case message.Role == "assistant" && (message.Phase == "commentary" || message.Phase == "final_answer"):
				relation := relationForBoundary(currentPromptBoundaryFound)
				entry := sourceText{
					Source: "agent-visible-message", TrustClass: "agent-explanation", Ordinal: ordinal,
					Relation: relation, Text: trimmed,
				}
				if currentPromptBoundaryFound {
					output.currentAgentMessages = append(output.currentAgentMessages, entry)
					disposition, reason = "included", "current-execution-trajectory"
				} else {
					output.priorAgentMessages = append(output.priorAgentMessages, entry)
					disposition, reason = "included", "prior-task-trajectory"
				}
			}
			candidateContent := ""
			if disposition == "included" {
				candidateContent = trimmed
			}
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: "message", Role: message.Role, Phase: message.Phase,
				Content: candidateContent, Disposition: disposition, Reason: reason,
			})
		case "custom_tool_call", "function_call":
			var call toolCallPayload
			if json.Unmarshal(envelope.Payload, &call) != nil ||
				!validContextIdentifier(call.Name) || !validContextIdentifier(call.CallID) {
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: header.Type, Disposition: "excluded",
					Reason: "invalid-tool-call-payload",
				})
				continue
			}
			if len(call.Input) == 0 {
				call.Input = call.Arguments
			}
			entry := recentToolContext{
				CallID: call.CallID, Source: "codex-tool-activity", TrustClass: "session-store-derived",
				CallOrdinal: ordinal, Relation: relationForBoundary(currentPromptBoundaryFound), Name: call.Name,
			}
			if len(call.Input) > 0 {
				if excerpt, ok := safeUTF8Text(call.Input, maximumToolExcerptBytes); ok {
					entry.Input = excerpt
				}
			}
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: header.Type, CallID: call.CallID, Name: call.Name,
				Input: entry.Input, Disposition: "pending", Reason: "awaiting-tool-result",
			})
			pendingTools[call.CallID] = pendingToolContext{entry: entry, candidateIndex: len(output.candidates) - 1}
		case "custom_tool_call_output", "function_call_output":
			var result toolCallPayload
			if json.Unmarshal(envelope.Payload, &result) != nil || len(result.Output) == 0 {
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: header.Type, Disposition: "excluded",
					Reason: "invalid-or-empty-tool-output",
				})
				continue
			}

			pending, found := pendingTools[result.CallID]
			if !found {
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: header.Type, CallID: result.CallID,
					Disposition: "excluded", Reason: "tool-call-not-selected-or-outside-boundary",
				})
				continue
			}
			excerpt, ok := safeUTF8Text(result.Output, maximumToolExcerptBytes)
			if !ok {
				output.omittedUnsafe++
				output.candidates[pending.candidateIndex].Disposition = "excluded"
				output.candidates[pending.candidateIndex].Reason = "invalid-or-oversized-tool-result"
				delete(pendingTools, result.CallID)
				output.candidates = append(output.candidates, contextCandidate{
					Ordinal: ordinal, Type: header.Type, CallID: result.CallID,
					Disposition: "excluded", Reason: "invalid-or-oversized-model-context",
				})
				continue
			}
			pending.entry.Output = excerpt
			pending.entry.ResultOrdinal = ordinal
			output.completedTools = append(output.completedTools, pending.entry)
			output.candidates[pending.candidateIndex].Disposition = "included"
			output.candidates[pending.candidateIndex].Reason = "completed-relevant-tool-activity"
			delete(pendingTools, result.CallID)
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: header.Type, CallID: result.CallID, Output: excerpt,
				Disposition: "included", Reason: "paired-completed-tool-result",
			})
		default:
			output.candidates = append(output.candidates, contextCandidate{
				Ordinal: ordinal, Type: "unsupported-response-item", Disposition: "excluded", Reason: "unsupported-session-payload-type",
			})
		}
	}
	if err := scanner.Err(); err != nil {
		finalizeRelatedContextEvidence(&output, info, ordinal, transcriptWriter, transcriptDigest, rawMetadataByOrdinal, path)
		return output, err
	}
	for _, pending := range pendingTools {
		output.candidates[pending.candidateIndex].Disposition = "excluded"
		output.candidates[pending.candidateIndex].Reason = "pending-tool-call-without-result"
	}
	if !currentPromptBoundaryFound {
		// The exact prompt remains available from the trusted Core handoff, but
		// without a transcript boundary no earlier Agent/tool context is safe to
		// associate with it.
		output.priorAgentMessages = nil
		output.currentAgentMessages = nil
		output.ambientContext = nil
		output.completedTools = nil
		for index := range output.candidates {
			candidate := &output.candidates[index]
			if candidate.Disposition == "included" &&
				(candidate.Role == "assistant" || candidate.Role == "user" ||
					strings.HasPrefix(candidate.Type, "custom_tool_")) {
				candidate.Disposition = "excluded"
				candidate.Reason = "current-prompt-boundary-not-found"
			}
		}
	}
	if err := enforceRelatedContextBudget(&output); err != nil {
		return output, err
	}
	finalizeRelatedContextEvidence(&output, info, ordinal, transcriptWriter, transcriptDigest, rawMetadataByOrdinal, path)
	output.coverage.Summary = append([]contextCandidateSummary(nil), output.candidateSummary...)
	output.coverage.BoundaryFound = currentPromptBoundaryFound
	output.coverage.Selection = "complete-human-history-first; agent-and-ambient-before-historical-tools; context-by-byte-budget; excerpts-identify-omitted-middle-and-source-sha256; no-semantic-filter"
	if output.priorHumans == nil {
		output.priorHumans = []sourceText{}
	}
	if output.priorAgentMessages == nil {
		output.priorAgentMessages = []sourceText{}
	}
	if output.currentAgentMessages == nil {
		output.currentAgentMessages = []sourceText{}
	}
	if output.ambientContext == nil {
		output.ambientContext = []sourceText{}
	}
	if output.completedTools == nil {
		output.completedTools = []recentToolContext{}
	}
	return output, nil
}

func relationForBoundary(currentPromptBoundaryFound bool) string {
	if currentPromptBoundaryFound {
		return "after-current-prompt"
	}
	return "before-current-prompt"
}

func normalizedMessageRole(value string) string {
	switch value {
	case "user", "assistant", "developer", "system", "tool":
		return value
	default:
		return "other"
	}
}

func normalizedMessagePhase(value string) string {
	switch value {
	case "", "commentary", "final_answer", "analysis":
		return value
	default:
		return "other"
	}
}

func validContextIdentifier(value string) bool {
	return value != "" && len(value) <= 256 && !strings.ContainsAny(value, "\r\n\x00")
}

func appendAmbientContext(
	values []sourceText,
	value sourceText,
	maximum int,
) ([]sourceText, int, int) {
	for index := range values {
		if values[index].Source != value.Source || values[index].TrustClass != value.TrustClass ||
			values[index].Text != value.Text {
			continue
		}
		superseded := values[index].Ordinal
		values = append(values[:index], values[index+1:]...)
		values = append(values, value)
		return values, 0, superseded
	}
	if maximum <= 0 {
		return values, value.Ordinal, 0
	}
	values = append(values, value)
	if len(values) <= maximum {
		return values, 0, 0
	}
	displaced := values[0].Ordinal
	return append([]sourceText(nil), values[len(values)-maximum:]...), displaced, 0
}

func displaceCandidateByOrdinal(context *relatedContext, ordinal int, reason string) {
	if context == nil || ordinal <= 0 {
		return
	}
	for index := range context.candidates {
		candidate := &context.candidates[index]
		if candidate.Ordinal == ordinal && candidate.Disposition == "included" {
			candidate.Disposition = "excluded"
			candidate.Reason = reason
			clearCandidateContent(candidate)
			return
		}
	}
}

func displaceToolCandidates(context *relatedContext, callID, reason string) {
	if context == nil || callID == "" {
		return
	}
	for index := range context.candidates {
		candidate := &context.candidates[index]
		if candidate.CallID == callID && candidate.Disposition == "included" {
			candidate.Disposition = "excluded"
			candidate.Reason = reason
			clearCandidateContent(candidate)
		}
	}
}

func supersedeCurrentPromptBoundary(context *relatedContext) {
	if context == nil {
		return
	}
	for index := range context.candidates {
		candidate := &context.candidates[index]
		if candidate.Disposition == "boundary" {
			candidate.Disposition = "excluded"
			candidate.Reason = "superseded-current-prompt-boundary"
			clearCandidateContent(candidate)
		}
	}
}

func clearCandidateContent(candidate *contextCandidate) {
	if candidate == nil {
		return
	}
	candidate.Content = ""
	candidate.Input = ""
	candidate.Output = ""
	clear(candidate.RawEvent)
	candidate.RawEvent = nil
	candidate.RawEventText = ""
}

func attachSessionEventMetadata(candidates []contextCandidate, events map[int]rawEventMetadata) {
	for index := range candidates {
		candidate := &candidates[index]
		candidate.Source = "codex-session-jsonl"
		metadata := events[candidate.Ordinal]
		candidate.RawEventBytes = metadata.bytes
		candidate.RawEventSHA256 = metadata.sha256
	}
}

func finalizeRelatedContextEvidence(
	output *relatedContext,
	info os.FileInfo,
	scannedEvents int,
	transcriptWriter *countingWriter,
	transcriptDigest interface{ Sum([]byte) []byte },
	rawMetadata map[int]rawEventMetadata,
	path string,
) {
	if output == nil || info == nil || transcriptWriter == nil || transcriptDigest == nil {
		return
	}
	attachSessionEventMetadata(output.candidates, rawMetadata)
	observed := len(output.candidates)
	output.candidates, output.candidateSummary = compactContextCandidates(output.candidates)
	output.transcriptSnapshot = transcriptSnapshot{
		Source: "codex-session-jsonl", TaskID: codexTaskID(path), CaptureBoundary: "file-size-at-open",
		FileBytesAtOpen: info.Size(), FileModifiedAtOpen: info.ModTime().UTC(),
		ScannedBytes: transcriptWriter.bytes, ScannedEvents: scannedEvents,
		ScannedContentSHA256: hex.EncodeToString(transcriptDigest.Sum(nil)),
		ObservedCandidates:   observed, RetainedCandidates: len(output.candidates),
	}
}

func codexTaskID(path string) string {
	match := codexTaskIDPattern.FindStringSubmatch(filepath.Base(path))
	if len(match) == 2 {
		return match[1]
	}
	return ""
}

func compactContextCandidates(values []contextCandidate) ([]contextCandidate, []contextCandidateSummary) {
	type summaryKey struct {
		typeName, role, phase, disposition, reason string
	}
	summaries := map[summaryKey]contextCandidateSummary{}
	retained := map[int]bool{}
	for index := range values {
		candidate := &values[index]
		if candidate.Disposition != "included" && candidate.Disposition != "boundary" {
			clearCandidateContent(candidate)
		}
		key := summaryKey{candidate.Type, candidate.Role, candidate.Phase, candidate.Disposition, candidate.Reason}
		summary := summaries[key]
		if summary.Count == 0 {
			summary = contextCandidateSummary{
				Type: candidate.Type, Role: candidate.Role, Phase: candidate.Phase,
				Disposition: candidate.Disposition, Reason: candidate.Reason,
				FirstOrdinal: candidate.Ordinal,
			}
		}
		summary.Count++
		summary.LastOrdinal = candidate.Ordinal
		summaries[key] = summary
		if candidate.Disposition == "included" || candidate.Disposition == "boundary" {
			retained[index] = true
		}
	}
	remaining := maximumEvidenceCandidates - len(retained)
	if remaining > 0 {
		for index := 0; index < len(values) && index < earlyExcludedSamples && remaining > 0; index++ {
			if !retained[index] {
				retained[index] = true
				remaining--
			}
		}
	}
	if remaining > 0 {
		for index := len(values) - 1; index >= 0 && remaining > 0; index-- {
			if !retained[index] {
				retained[index] = true
				remaining--
			}
		}
	}
	compacted := make([]contextCandidate, 0, len(retained))
	for index := range values {
		if retained[index] {
			compacted = append(compacted, values[index])
		}
	}
	resultSummary := make([]contextCandidateSummary, 0, len(summaries))
	for _, summary := range summaries {
		resultSummary = append(resultSummary, summary)
	}
	sort.Slice(resultSummary, func(left, right int) bool {
		if resultSummary[left].FirstOrdinal != resultSummary[right].FirstOrdinal {
			return resultSummary[left].FirstOrdinal < resultSummary[right].FirstOrdinal
		}
		return resultSummary[left].Reason < resultSummary[right].Reason
	})
	return compacted, resultSummary
}

type userMessageProvenance struct {
	source        string
	trustClass    string
	reason        string
	humanAuthored bool
}

func classifyUserMessageProvenance(message messagePayload, text string) userMessageProvenance {
	kinds := message.InternalMetadata.ContentItemKinds
	if len(kinds) > 0 {
		allHuman := true
		agents, environment, application := false, false, false
		for _, kind := range kinds {
			if strings.HasPrefix(kind, "user.") {
				continue
			}
			allHuman = false
			switch kind {
			case "agents_md.instructions":
				agents = true
			case "environments.environment_context":
				environment = true
			default:
				application = true
			}
		}
		if allHuman {
			return userMessageProvenance{
				source: "human-message", trustClass: "human-authored",
				reason: "prior-human-message", humanAuthored: true,
			}
		}
		if len(kinds) == 1 && agents {
			return userMessageProvenance{
				source: "codex-injected-agents-md", trustClass: "repository-policy-context",
				reason: "injected-repository-policy-context",
			}
		}
		if len(kinds) == 1 && environment {
			return userMessageProvenance{
				source: "codex-injected-environment", trustClass: "runtime-environment-context",
				reason: "injected-runtime-environment-context",
			}
		}
		if len(kinds) == 1 && application {
			return userMessageProvenance{
				source: "codex-injected-application-context", trustClass: "application-supplied-context",
				reason: "injected-application-context",
			}
		}
		return userMessageProvenance{
			source: "codex-injected-mixed-context", trustClass: "non-human-context",
			reason: "injected-mixed-context",
		}
	}
	// Older Codex transcripts did not retain typed item provenance. Recognize
	// only wrapper-shaped records as non-human; ordinary user text that happens
	// to discuss these marker names remains human-authored.
	trimmed := strings.TrimSpace(text)
	switch {
	case strings.HasPrefix(trimmed, "# AGENTS.md instructions"):
		return userMessageProvenance{
			source: "legacy-codex-injected-agents-md", trustClass: "repository-policy-context",
			reason: "legacy-injected-repository-policy-context",
		}
	case strings.HasPrefix(trimmed, "<environment_context>"):
		return userMessageProvenance{
			source: "legacy-codex-injected-environment", trustClass: "runtime-environment-context",
			reason: "legacy-injected-runtime-environment-context",
		}
	case strings.HasPrefix(trimmed, "<recommended_plugins>"):
		return userMessageProvenance{
			source: "legacy-codex-injected-application-context", trustClass: "application-supplied-context",
			reason: "legacy-injected-application-context",
		}
	default:
		return userMessageProvenance{
			source: "human-message", trustClass: "human-authored",
			reason: "prior-human-message", humanAuthored: true,
		}
	}
}

func localRequestForEvidence(request localDecisionRequest) localDecisionRequestEvidence {
	target := request.ActualRequest
	// The requester snapshot is persisted as parsed JSON at the source-context
	// root so field-aware redaction can operate on it. Avoid duplicating it as
	// an opaque JSON string inside actual_request.
	target.RequesterContext = ""
	return localDecisionRequestEvidence{
		SchemaVersion: request.SchemaVersion, RequestID: request.RequestID, Mode: request.Mode,
		Prompt: string(request.Prompt), ToolName: request.ToolName,
		ToolInput:      string(request.ToolInput),
		TranscriptPath: request.TranscriptPath, CWD: request.CWD,
		Evidence: string(request.Evidence), ActualRequest: target,
		CoreBinarySHA256: request.CoreBinarySHA256,
	}
}

func rawJSONCopy(value string) json.RawMessage {
	if value == "" || !json.Valid([]byte(value)) {
		return nil
	}
	return append(json.RawMessage(nil), []byte(value)...)
}

func cloneExternalDecisionInput(input externalDecisionInput) externalDecisionInput {
	// This is an in-memory ownership copy, not a wire validation round trip.
	// Using MarshalJSON followed by the strict UnmarshalJSON contract made a
	// recoverable evidence copy silently collapse to schema_version=0 whenever
	// a newly observed context shape tripped a decoder invariant. The original
	// model input remained usable, but persisting SelectedModelInput then failed
	// before the provider call. Copy each owned container directly instead.
	clone := input
	clone.HumanIntent.PriorMessages = slices.Clone(input.HumanIntent.PriorMessages)
	clone.AgentContext.PriorTaskTrajectory = slices.Clone(input.AgentContext.PriorTaskTrajectory)
	clone.AgentContext.CurrentExecutionTrajectory = slices.Clone(input.AgentContext.CurrentExecutionTrajectory)
	clone.AgentContext.AmbientContext = slices.Clone(input.AgentContext.AmbientContext)
	clone.ToolCall.Input = slices.Clone(input.ToolCall.Input)
	clone.CompletedToolActivity = slices.Clone(input.CompletedToolActivity)
	clone.Coverage.Summary = slices.Clone(input.Coverage.Summary)
	clone.Environment.WorkspaceRoots = slices.Clone(input.Environment.WorkspaceRoots)
	if input.Environment.ResolvedExecutables != nil {
		clone.Environment.ResolvedExecutables = make(map[string]string, len(input.Environment.ResolvedExecutables))
	}
	for name, path := range input.Environment.ResolvedExecutables {
		clone.Environment.ResolvedExecutables[name] = path
	}
	clone.RequesterContext.Arguments = slices.Clone(input.RequesterContext.Arguments)
	clone.RequesterContext.RelevantEnvironment = slices.Clone(input.RequesterContext.RelevantEnvironment)
	clone.CoreEvidence = slices.Clone(input.CoreEvidence)
	clone.ActualRequest.TargetID = slices.Clone(input.ActualRequest.TargetID)
	clone.ActualRequest.RequestContext = slices.Clone(input.ActualRequest.RequestContext)
	return clone
}

func collectEvidenceEnvironment() []evidenceEnvironmentEntry {
	entries := make([]evidenceEnvironmentEntry, 0, len(os.Environ()))
	for _, pair := range os.Environ() {
		name, value, found := strings.Cut(pair, "=")
		if !found || name == "" {
			continue
		}
		// Collect values only from the fixed process-metadata contract. All other
		// environment names are recorded without reading their values into evidence.
		if !evidenceEnvironmentValueAllowed(name) {
			value = ""
		}
		entry := evidenceEnvironmentEntry{Name: name, Value: value, Redacted: !evidenceEnvironmentValueAllowed(name)}
		entries = append(entries, entry)
	}
	return entries
}

func collectEvidenceProcessContext() evidenceProcessContext {
	executable, _ := os.Executable()
	cwd, _ := os.Getwd()
	digest, _ := currentExecutableSHA256()
	return evidenceProcessContext{
		Executable: executable, ExecutableSHA256: digest,
		Arguments: append([]string(nil), os.Args...), CWD: cwd,
		PID: os.Getpid(), ParentPID: os.Getppid(), UID: os.Getuid(), EffectiveUID: os.Geteuid(),
	}
}

func messageText(message messagePayload) string {
	var pieces []string
	for _, item := range message.Content {
		if (item.Type == "input_text" || item.Type == "output_text" || item.Type == "text") && item.Text != "" {
			pieces = append(pieces, item.Text)
		}
	}
	return strings.Join(pieces, "\n")
}

func collectWorkspaceContext(cwd string, toolInput json.RawMessage, deadlines ...time.Time) workspaceContext {
	git := func(args ...string) string { return gitOutputWithDeadline(cwd, deadlines, args...) }
	result := workspaceContext{CWD: cwd, ResolvedExecutables: map[string]string{}}
	if !filepath.IsAbs(cwd) {
		return result
	}
	if root := git("rev-parse", "--show-toplevel"); filepath.IsAbs(root) {
		result.RepositoryRoot = filepath.Clean(root)
		result.Branch = git("branch", "--show-current")
		result.Head = git("rev-parse", "--verify", "HEAD")
		result.Remote = safeRemote(git("remote", "get-url", "origin"))
	}
	var commandInput struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(toolInput, &commandInput) == nil {
		for _, name := range []string{"may", "git", "ssh", "gh", "curl"} {
			if !containsShellWord(commandInput.Command, name) {
				continue
			}
			if path, err := exec.LookPath(name); err == nil && filepath.IsAbs(path) {
				result.ResolvedExecutables[name] = filepath.Clean(path)
			}
		}
	}
	if len(result.ResolvedExecutables) == 0 {
		result.ResolvedExecutables = nil
	}
	return result
}

func gitOutput(cwd string, args ...string) string { return gitOutputWithDeadline(cwd, nil, args...) }

func gitOutputWithDeadline(cwd string, deadlines []time.Time, args ...string) string {
	deadline := time.Now().Add(time.Second)
	for _, candidate := range deadlines {
		if !candidate.IsZero() && candidate.Before(deadline) {
			deadline = candidate
		}
	}
	if !deadline.After(time.Now()) {
		return ""
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	command := exec.CommandContext(ctx, "git", append([]string{"-C", cwd}, args...)...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	output, err := command.Output()
	if err != nil || len(output) > 16*1024 {
		clear(output)
		return ""
	}
	value := strings.TrimSpace(string(output))
	clear(output)
	return value
}

func safeRemote(value string) string {
	if value == "" {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" {
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return parsed.String()
	}
	if at := strings.Index(value, "@"); at >= 0 {
		return value[at+1:]
	}
	return value
}

func containsShellWord(command, word string) bool {
	for _, token := range strings.FieldsFunc(command, func(character rune) bool {
		return !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
			!(character >= '0' && character <= '9') && character != '_' && character != '-' && character != '/'
	}) {
		if filepath.Base(token) == word {
			return true
		}
	}
	return false
}

func externalizeRequesterContext(raw string) requesterExecutionContext {
	result := requesterExecutionContext{
		Source: "onenod-requester-context", TrustClass: "request-self-report",
		Arguments: []requesterArgument{}, RelevantEnvironment: []requesterEnvironmentValue{},
	}
	if raw == "" || !json.Valid([]byte(raw)) {
		return result
	}
	var captured struct {
		Executable        string                      `json:"executable"`
		ExecutableSHA256  string                      `json:"executable_sha256"`
		Arguments         []requesterArgument         `json:"arguments"`
		CWD               string                      `json:"cwd"`
		GatewayOrigin     string                      `json:"gateway_origin"`
		ApprovalTimeoutMS int                         `json:"approval_timeout_ms"`
		PollIntervalMS    int                         `json:"poll_interval_ms"`
		Environment       []requesterEnvironmentValue `json:"environment"`
	}
	if json.Unmarshal([]byte(raw), &captured) != nil {
		return result
	}
	if filepath.IsAbs(captured.Executable) {
		result.Executable = filepath.Clean(captured.Executable)
	}
	if validSHA256(captured.ExecutableSHA256) {
		result.ExecutableSHA256 = captured.ExecutableSHA256
	}
	if filepath.IsAbs(captured.CWD) {
		result.CWD = filepath.Clean(captured.CWD)
	}
	if parsed, err := url.Parse(captured.GatewayOrigin); err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil {
		parsed.RawQuery = ""
		parsed.Fragment = ""
		result.GatewayOrigin = parsed.String()
	}
	if captured.ApprovalTimeoutMS > 0 && captured.ApprovalTimeoutMS <= 24*60*60*1000 {
		result.ApprovalTimeoutMS = captured.ApprovalTimeoutMS
	}
	if captured.PollIntervalMS > 0 && captured.PollIntervalMS <= 60*60*1000 {
		result.PollIntervalMS = captured.PollIntervalMS
	}
	for _, argument := range captured.Arguments {
		if len(result.Arguments) >= 64 {
			break
		}
		if argument.Redacted {
			argument.Value = "[REDACTED:CREDENTIAL]"
			argument.Redacted = true
			if argument.RedactionRule == "" {
				argument.RedactionRule = "gatekeeper-requester-argument"
			}
		}
		if trimmed, ok := safeUTF8Text([]byte(argument.Value), maximumToolExcerptBytes); ok {
			argument.Value = trimmed
			result.Arguments = append(result.Arguments, argument)
		}
	}
	relevantNames := map[string]bool{
		"CODEX_CI": true, "CODEX_INTERNAL_ORIGINATOR_OVERRIDE": true, "CODEX_PERMISSION_PROFILE": true,
		"GITHUB_ACTIONS": true, "LANG": true, "LC_ALL": true, "PWD": true, "SHELL": true,
		"SSH_AUTH_SOCK": true, "TERM": true,
	}
	threadID, sessionID := "", ""
	for _, entry := range captured.Environment {
		switch entry.Name {
		case "CODEX_THREAD_ID":
			threadID = entry.Value
			result.ThreadIDPresent = entry.Value != ""
		case "CODEX_SESSION_ID":
			sessionID = entry.Value
			result.SessionIDPresent = entry.Value != ""
		}
		if !relevantNames[entry.Name] || len(result.RelevantEnvironment) >= 16 {
			continue
		}
		if entry.Redacted {
			entry.Value = "[REDACTED:CREDENTIAL]"
			entry.Redacted = true
			if entry.RedactionRule == "" {
				entry.RedactionRule = "gatekeeper-requester-environment"
			}
		}
		if trimmed, ok := safeUTF8Text([]byte(entry.Value), maximumToolExcerptBytes); ok {
			entry.Value = trimmed
			result.RelevantEnvironment = append(result.RelevantEnvironment, entry)
		}
	}
	result.ThreadSessionEqual = result.ThreadIDPresent && result.SessionIDPresent && threadID == sessionID
	return result
}

func externalizeCoreEvidence(raw json.RawMessage) (json.RawMessage, error) {
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, errors.New("invalid Core evidence")
	}
	if request, ok := envelope["request"].(map[string]any); ok {
		// Older Core evidence emitted requester_reason_accepted=false to mean that
		// requester prose was not treated as authority. Models read that as a
		// substantive rejection. Replace the ambiguous boolean with its actual
		// provenance meaning while preserving the raw evidence in 01-source-context.
		delete(request, "requester_reason_accepted")
		request["requester_context_role"] = "explanatory context only; neither authorization nor rejection evidence"
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func externalizeTarget(target operationTarget, aliases map[string]string) externalTarget {
	result := externalTarget{
		Surface: target.Surface, Operation: target.Operation, TargetKind: target.TargetKind,
		KeyFingerprint: target.KeyFingerprint, RemoteUser: target.RemoteUser,
		HostKeyFingerprint: target.HostKeyFingerprint,
	}
	if target.RequestContext != "" && json.Valid([]byte(target.RequestContext)) {
		result.RequestContext = append(json.RawMessage(nil), []byte(target.RequestContext)...)
	}
	if target.TargetID != "" {
		if json.Valid([]byte(target.TargetID)) {
			result.TargetID = append(json.RawMessage(nil), []byte(target.TargetID)...)
		} else if encoded, err := json.Marshal(target.TargetID); err == nil {
			result.TargetID = encoded
		}
		itemID := target.TargetID
		var descriptor struct {
			ItemID string `json:"item_id"`
		}
		if json.Unmarshal([]byte(target.TargetID), &descriptor) == nil && descriptor.ItemID != "" {
			itemID = descriptor.ItemID
		}
		result.TargetAlias = aliases[itemID]
	}
	return result
}

func clearExternalInput(input *externalDecisionInput) {
	if input == nil {
		return
	}
	input.HumanIntent.CurrentPrompt = ""
	for index := range input.HumanIntent.PriorMessages {
		input.HumanIntent.PriorMessages[index].Text = ""
	}
	for index := range input.AgentContext.PriorTaskTrajectory {
		input.AgentContext.PriorTaskTrajectory[index].Text = ""
	}
	for index := range input.AgentContext.CurrentExecutionTrajectory {
		input.AgentContext.CurrentExecutionTrajectory[index].Text = ""
	}
	for index := range input.AgentContext.AmbientContext {
		input.AgentContext.AmbientContext[index].Text = ""
	}
	clear(input.ToolCall.Input)
	input.ToolCall.Input = nil
	for index := range input.CompletedToolActivity {
		input.CompletedToolActivity[index].Input = ""
		input.CompletedToolActivity[index].Output = ""
	}
	for index := range input.RequesterContext.Arguments {
		input.RequesterContext.Arguments[index].Value = ""
	}
	for index := range input.RequesterContext.RelevantEnvironment {
		input.RequesterContext.RelevantEnvironment[index].Value = ""
	}
	clear(input.CoreEvidence)
	input.CoreEvidence = nil
	clear(input.ActualRequest.TargetID)
	input.ActualRequest.TargetID = nil
	clear(input.ActualRequest.RequestContext)
	input.ActualRequest.RequestContext = nil
}

func joinModelContent(input externalDecisionInput) ([]byte, error) {
	captured, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	defer clear(captured)
	encoded, err := modelcontract.DirectModelInput(captured)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(bytes.TrimSpace(encoded), encoded) {
		return nil, errors.New("unexpected model input whitespace")
	}
	return encoded, nil
}

func evidenceEnvironmentValueAllowed(name string) bool {
	switch name {
	case "HOME", "USER", "LOGNAME", "PATH", "PWD", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM", "SSH_AUTH_SOCK", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_CI", "CODEX_PERMISSION_PROFILE", "BEHOLDER_CORE_SOCKET":
		return true
	}
	return false
}
