package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/retrieval"
)

type retrievalSourceAudit struct {
	SchemaVersion     int             `json:"schema_version"`
	SnapshotID        string          `json:"snapshot_id"`
	SessionFile       string          `json:"session_file"`
	RequestFile       string          `json:"request_file"`
	ToolsSHA256       string          `json:"tools_sha256"`
	InitialInput      json.RawMessage `json:"initial_input"`
	PrefetchedHistory bool            `json:"prefetched_history"`
	GeneratedSummary  bool            `json:"generated_summary"`
}
type retrievalRequestAudit struct {
	Model      string            `json:"model"`
	Messages   []json.RawMessage `json:"messages"`
	Tools      json.RawMessage   `json:"tools"`
	ToolChoice string            `json:"tool_choice"`
}
type retrievalCallAudit struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}
type retrievalAssistantAudit struct {
	Role      string               `json:"role"`
	Content   string               `json:"content"`
	Reasoning string               `json:"reasoning_content"`
	ToolCalls []retrievalCallAudit `json:"tool_calls"`
}
type retrievalResponseAudit struct {
	Model   string `json:"model"`
	Choices []struct {
		Message      json.RawMessage `json:"message"`
		FinishReason string          `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		Details struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details"`
	} `json:"usage"`
}
type retrievalToolAudit struct {
	ID            string  `json:"tool_call_id"`
	Name          string  `json:"name"`
	ArgumentsText string  `json:"arguments_text"`
	Content       string  `json:"serialized_content"`
	LatencyMS     float64 `json:"local_ms"`
}

var retrievalRoundPattern = regexp.MustCompile(`^round-thinking-(disabled|enabled)-(00[1-9]|01[0-9]|02[0-4])-(request|response|tools)\.json$`)
var retrievalReferencePattern = regexp.MustCompile(`^(session|request):L[1-9][0-9]*$`)

func retrievalVersion(version string) bool { return version == "e2-authoritative-dogfood-v33" }
func validRetrievalStage(name string, base []string) bool {
	return slices.Contains(base, name) || name == "07-session-snapshot.jsonl" || name == "08-retrieval-request.json" || retrievalRoundPattern.MatchString(name)
}
func evidenceFileLimit(name string) int64 {
	if name == "07-session-snapshot.jsonl" {
		return 256 * 1024 * 1024
	}
	return 64 * 1024 * 1024
}
func compactJSON(raw []byte) []byte {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return nil
	}
	return b.Bytes()
}
func hashBytes(raw []byte) string { d := sha256.Sum256(raw); return hex.EncodeToString(d[:]) }

func retrievalInitialMatches(selected, body json.RawMessage) bool {
	var req retrievalRequestAudit
	var initial map[string]json.RawMessage
	if json.Unmarshal(body, &req) != nil || len(req.Messages) != 2 || req.Model != "deepseek-flash" || req.ToolChoice != "auto" ||
		!jsonSemanticallyEqual(req.Tools, retrieval.Tools()) || json.Unmarshal(selected, &initial) != nil || len(initial) != 1 || initial["pending_request"] == nil {
		return false
	}
	var msg struct{ Role, Content string }
	if json.Unmarshal(req.Messages[1], &msg) != nil || msg.Role != "user" {
		return false
	}
	return jsonSemanticallyEqual(selected, []byte(msg.Content))
}
func retrievalPolicyMatches(m manifest, body json.RawMessage) bool {
	var req retrievalRequestAudit
	var system struct{ Role, Content string }
	if json.Unmarshal(body, &req) != nil || len(req.Messages) != 2 || json.Unmarshal(req.Messages[0], &system) != nil || system.Role != "system" {
		return false
	}
	return hashBytes(append([]byte(strings.TrimSuffix(system.Content, "\n")+"\n"), compactJSON(req.Tools)...)) == m.PolicySHA256
}
func retrievalDecisionMatches(summary modelResponseAuditRecord) bool {
	var response retrievalResponseAudit
	if json.Unmarshal(summary.Body, &response) != nil || response.Model != "deepseek-flash" || len(response.Choices) != 1 || response.Choices[0].FinishReason != "stop" {
		return false
	}
	var message retrievalAssistantAudit
	if json.Unmarshal(response.Choices[0].Message, &message) != nil || message.Role != "assistant" || len(message.ToolCalls) != 0 {
		return false
	}
	var decision struct {
		Decision, Reason string
		EvidenceRefs     json.RawMessage `json:"evidence_refs"`
	}
	if json.Unmarshal([]byte(message.Content), &decision) != nil {
		return false
	}
	var refs, normalized []string
	if json.Unmarshal(decision.EvidenceRefs, &refs) == nil {
		for _, ref := range refs {
			if len(ref) <= 256 && retrievalReferencePattern.MatchString(ref) {
				normalized = append(normalized, ref)
			}
		}
	}
	return decision.Decision == summary.Decision && decision.Reason == summary.Reason && summary.ScopeResolution == "" && equalStrings(normalized, summary.EvidenceRefs)
}

func inspectRetrieval(bundle string, m manifest, source sourceAuditRecord, primary modelRequestAuditRecord, primaryResult modelResponseAuditRecord, comparison modelRequestAuditRecord, comparisonResult modelResponseAuditRecord, out *bundleInspection) {
	if !primary.RequestSent && !comparison.RequestSent {
		return
	}
	fail := func(code string) { out.Errors = append(out.Errors, "retrieval-"+code) }
	r := source.Retrieval
	if r == nil || r.SchemaVersion != 1 || r.PrefetchedHistory || r.GeneratedSummary || r.SessionFile != "07-session-snapshot.jsonl" || r.RequestFile != "08-retrieval-request.json" || r.ToolsSHA256 != hashBytes(retrieval.Tools()) {
		fail("source-contract-invalid")
		return
	}
	session, err := readPrivateFile(filepath.Join(bundle, r.SessionFile), evidenceFileLimit(r.SessionFile))
	if err != nil {
		fail("snapshot-unavailable")
		return
	}
	defer clear(session)
	request, err := readPrivateFile(filepath.Join(bundle, r.RequestFile), evidenceFileLimit(r.RequestFile))
	if err != nil {
		fail("request-unavailable")
		return
	}
	defer clear(request)
	store, err := retrieval.New(context.Background(), session, string(request), m.EvidenceID)
	if err != nil || store.ID() != r.SnapshotID || hashBytes(session) != source.TranscriptSnapshot.ScannedContentSHA256 || int64(len(session)) != source.TranscriptSnapshot.ScannedBytes || store.Count() != source.TranscriptSnapshot.ScannedEvents {
		fail("snapshot-identity-mismatch")
		return
	}
	var original struct {
		Request map[string]json.RawMessage `json:"core_local_decision_request"`
	}
	if !decodeBundleRecord(bundle, "01-source-context.json", &original) {
		fail("request-origin-invalid")
		return
	}
	original.Request["transcript_path"] = json.RawMessage(`""`)
	normalized, _ := json.Marshal(original.Request)
	if !jsonSemanticallyEqual(normalized, request) {
		fail("request-origin-mismatch")
	}
	for _, pair := range []struct {
		request modelRequestAuditRecord
		summary modelResponseAuditRecord
	}{{primary, primaryResult}, {comparison, comparisonResult}} {
		if pair.request.RequestSent {
			inspectRetrievalRounds(bundle, m, store, pair.request, pair.summary, out)
		}
	}
}

func inspectRetrievalRounds(bundle string, m manifest, store *retrieval.Store, initial modelRequestAuditRecord, summary modelResponseAuditRecord, out *bundleInspection) {
	fail := func(code string) { out.Errors = append(out.Errors, "retrieval-"+initial.Variant+"-"+code) }
	if summary.ModelRounds < 1 || summary.ModelRounds > 24 {
		fail("round-count-invalid")
		return
	}
	expected := append(json.RawMessage(nil), initial.Body...)
	var last json.RawMessage
	calls, reasoningBytes, reasoningTokens := 0, 0, 0
	reasoningPresent := false
	localMS := 0.0
	readEvidence := false
	for round := 1; round <= summary.ModelRounds; round++ {
		prefix := fmt.Sprintf("round-%s-%03d-", initial.Variant, round)
		var req modelRequestAuditRecord
		var resp modelResponseAuditRecord
		if m.Files[prefix+"request.json"] == nil || !decodeBundleRecord(bundle, prefix+"request.json", &req) || req.EvidenceID != m.EvidenceID || req.Variant != initial.Variant ||
			verifyRawBody(req.RawBodyBase64, req.BodyBytes, req.BodySHA256, req.Body, false) != nil || !jsonSemanticallyEqual(req.Body, expected) {
			fail("request-continuation-mismatch")
			return
		}
		if m.Files[prefix+"response.json"] == nil || !decodeBundleRecord(bundle, prefix+"response.json", &resp) || resp.EvidenceID != m.EvidenceID || resp.Variant != initial.Variant ||
			verifyRawBody(resp.RawBodyBase64, resp.BodyBytes, resp.BodySHA256, resp.Body, false) != nil {
			fail("round-response-invalid")
			return
		}
		last = resp.Body
		var response retrievalResponseAudit
		if json.Unmarshal(resp.Body, &response) != nil || response.Model != "deepseek-flash" || len(response.Choices) != 1 {
			if summary.ModelUsed {
				fail("provider-response-invalid")
			}
			break
		}
		var assistant retrievalAssistantAudit
		if json.Unmarshal(response.Choices[0].Message, &assistant) != nil || assistant.Role != "assistant" {
			if summary.ModelUsed {
				fail("assistant-message-invalid")
			}
			break
		}
		reasoningBytes += len(assistant.Reasoning)
		reasoningTokens += max(0, response.Usage.Details.ReasoningTokens)
		reasoningPresent = reasoningPresent || strings.TrimSpace(assistant.Reasoning) != ""
		if m.Files[prefix+"tools.json"] == nil {
			if round < summary.ModelRounds || (len(assistant.ToolCalls) > 0 && summary.ModelUsed) {
				fail("tool-results-missing")
			}
			continue
		}
		var outputs []retrievalToolAudit
		if !decodeBundleRecord(bundle, prefix+"tools.json", &outputs) || len(outputs) != len(assistant.ToolCalls) {
			fail("tool-count-mismatch")
			return
		}
		var reqBody map[string]json.RawMessage
		var messages []json.RawMessage
		_ = json.Unmarshal(req.Body, &reqBody)
		_ = json.Unmarshal(reqBody["messages"], &messages)
		messages = append(messages, response.Choices[0].Message)
		for i, output := range outputs {
			call := assistant.ToolCalls[i]
			if output.ID != call.ID || output.Name != call.Function.Name || output.ArgumentsText != call.Function.Arguments {
				fail("tool-call-mismatch")
				return
			}
			replayed := store.Call(context.Background(), output.Name, json.RawMessage(output.ArgumentsText))
			encoded, _ := json.Marshal(replayed)
			if !jsonSemanticallyEqual(encoded, []byte(output.Content)) {
				fail("tool-source-replay-mismatch")
				return
			}
			readEvidence = readEvidence || replayed.Error == ""
			msg, _ := json.Marshal(map[string]any{"role": "tool", "tool_call_id": output.ID, "content": output.Content})
			messages = append(messages, msg)
			calls++
			localMS += output.LatencyMS
		}
		reqBody["messages"], _ = json.Marshal(messages)
		expected, _ = json.Marshal(reqBody)
	}
	if summary.ModelUsed && (!readEvidence || !jsonSemanticallyEqual(last, summary.Body)) {
		fail("final-response-mismatch")
	}
	if calls != summary.ToolCalls || reasoningBytes != summary.ReasoningBytes || reasoningTokens != summary.ReasoningTokens || reasoningPresent != summary.ReasoningPresent || localMS != summary.ToolLatencyMS {
		fail("aggregate-telemetry-mismatch")
	}
}
