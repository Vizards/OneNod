package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestViewerShowsAndVerifiesPrivateBundle(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	if err := os.WriteFile(filepath.Join(root, "outcome-delivery.jsonl"),
		[]byte(`{"schema_version":1,"record_type":"beholder_outcome_delivery_event"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var verified bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &verified); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(verified.Bytes(), []byte(`"valid": true`)) {
		t.Fatalf("verification output was invalid: %s", verified.Bytes())
	}
	var shown bytes.Buffer
	if err := showEvidence(root, evidenceID, &shown); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shown.Bytes(), []byte(`"03-model-response.json"`)) ||
		!bytes.Contains(shown.Bytes(), []byte(`"reasoning_content"`)) {
		t.Fatalf("show omitted evidence files: %s", shown.Bytes())
	}
	var audited bytes.Buffer
	if err := auditEvidence(root, &audited); err != nil ||
		!bytes.Contains(audited.Bytes(), []byte(`"valid": true`)) ||
		!bytes.Contains(audited.Bytes(), []byte(`"requester_executable_proven": 1`)) {
		t.Fatalf("root audit failed: %v %s", err, audited.Bytes())
	}
}

func TestViewerVerifiesDualThinkingPair(t *testing.T) {
	root, evidenceID := writeDualThinkingViewerFixture(t)
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err != nil ||
		!bytes.Contains(output.Bytes(), []byte(`"comparison_decision": "allow"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"comparison_latency_ms": 3`)) {
		t.Fatalf("dual-thinking bundle failed verification: err=%v output=%s", err, output.Bytes())
	}
}

func TestViewerVerifiesAuthoritativeDisabledPrimaryAndEnabledComparison(t *testing.T) {
	root, evidenceID := writeDualThinkingViewerFixture(t, true)
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err != nil ||
		!bytes.Contains(output.Bytes(), []byte(`"gatekeeper_version": "e2-authoritative-dogfood-v26"`)) ||
		!bytes.Contains(output.Bytes(), []byte(`"comparison_decision": "allow"`)) {
		t.Fatalf("authoritative dual-route bundle failed verification: err=%v output=%s", err, output.Bytes())
	}
}

func TestProviderDecisionMatchMirrorsOptionalDiagnosticNormalization(t *testing.T) {
	providerBody := json.RawMessage(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"content":"{\"decision\":\"allow\",\"reason\":\"Fixture is consistent.\",\"scope_resolution\":\"invented-value\",\"evidence_refs\":[\"human_intent.prior_messages[725]\"]}"}}]}`)
	response := modelResponseAuditRecord{
		Body: providerBody, Decision: "allow", Reason: "Fixture is consistent.",
		EvidenceRefs: []string{},
	}
	if !providerDecisionMatches(response, "e2-auditable-dogfood-v15", false) {
		t.Fatal("viewer did not mirror Gatekeeper dropping invalid optional diagnostics")
	}

	response.ScopeResolution = "task-consistent"
	if providerDecisionMatches(response, "e2-auditable-dogfood-v15", false) {
		t.Fatal("viewer accepted a stored diagnostic that the provider did not validly supply")
	}

	malformedOptionalBody := json.RawMessage(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"content":"{\"decision\":\"allow\",\"reason\":\"Fixture is consistent.\",\"evidence_refs\":[\"human_intent.current_prompt\",0]}"}}]}`)
	malformedOptionalResponse := modelResponseAuditRecord{
		Body: malformedOptionalBody, Decision: "allow", Reason: "Fixture is consistent.", EvidenceRefs: nil,
	}
	if !providerDecisionMatches(malformedOptionalResponse, "e2-dual-shadow-r7-benchmark-v18", false) {
		t.Fatal("viewer did not mirror Gatekeeper dropping a malformed optional diagnostic")
	}

	r4Body := json.RawMessage(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"content":"{\"decision\":\"allow\",\"reason\":\"Fixture is consistent.\",\"scope_resolution\":\"current-prompt-authorizes\",\"evidence_refs\":[\"human_intent.active_prior_constraints[2]\"]}"}}]}`)
	r4Response := modelResponseAuditRecord{
		Body: r4Body, Decision: "allow", Reason: "Fixture is consistent.",
		ScopeResolution: "current-prompt-authorizes",
		EvidenceRefs:    []string{"human_intent.active_prior_constraints[2]"},
	}
	if !providerDecisionMatches(r4Response, "e2-observability-async-v8", false) {
		t.Fatal("viewer did not apply the historical R4 optional diagnostic allowlist")
	}
}

func TestProviderDecisionMatchAllowsOnlyReasoningLengthChangeAfterDeclaredRedaction(t *testing.T) {
	providerBody := json.RawMessage(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"content":"{\"decision\":\"escalate\",\"reason\":\"Human authorization provenance is absent.\"}","reasoning_content":"ta[REDACTED:TOKEN]/goal drift"}}],"usage":{"completion_tokens_details":{"reasoning_tokens":17}}}`)
	response := modelResponseAuditRecord{
		Body: providerBody, Decision: "escalate", Reason: "Human authorization provenance is absent.",
		ReasoningPresent: true, ReasoningBytes: 36, ReasoningTokens: 17,
	}
	if providerDecisionMatches(response, "e2-dual-shadow-dogfood-v17", false) {
		t.Fatal("viewer accepted changed reasoning length without a declared response redaction")
	}
	if !providerDecisionMatches(response, "e2-dual-shadow-dogfood-v17", true) {
		t.Fatal("viewer rejected an otherwise matching provider decision after declared response redaction")
	}
	response.Decision = "allow"
	if providerDecisionMatches(response, "e2-dual-shadow-dogfood-v17", true) {
		t.Fatal("declared response redaction bypassed semantic decision verification")
	}
}

func TestRepeatedBenchmarkDivergenceIsObservationOnly(t *testing.T) {
	if !repeatedDecisionBenchmarkVersions(map[string]bool{"e2-dual-shadow-r7-benchmark-v18": true}) {
		t.Fatal("R7 repeated benchmark divergence was not classified as an observation")
	}
	if !repeatedDecisionBenchmarkVersions(map[string]bool{"e2-r8-provenance-focused-benchmark-v19": true}) {
		t.Fatal("R8 repeated benchmark divergence was not classified as an observation")
	}
	if !repeatedDecisionBenchmarkVersions(map[string]bool{"e2-r9-corrected-focused-benchmark-v20": true}) {
		t.Fatal("R9 repeated benchmark divergence was not classified as an observation")
	}
	if !repeatedDecisionBenchmarkVersions(map[string]bool{"e2-r10-luna-focused-benchmark-v21": true}) {
		t.Fatal("R10 repeated benchmark divergence was not classified as an observation")
	}
	if repeatedDecisionBenchmarkVersions(map[string]bool{"e2-dual-shadow-dogfood-v17": true}) ||
		repeatedDecisionBenchmarkVersions(map[string]bool{
			"e2-dual-shadow-dogfood-v17":      true,
			"e2-dual-shadow-r7-benchmark-v18": true,
		}) {
		t.Fatal("non-benchmark or mixed-version divergence was incorrectly downgraded")
	}
}

func TestThreeDomainEvidenceReferences(t *testing.T) {
	for _, version := range []string{
		"e2-r8-provenance-focused-benchmark-v19",
		"e2-r9-corrected-focused-benchmark-v20",
		"e2-r10-luna-focused-benchmark-v21",
		"e2-authoritative-dogfood-v22",
		"e2-authoritative-dogfood-v23",
		"e2-authoritative-dogfood-v24",
		"e2-authoritative-dogfood-v26",
	} {
		if !validProviderEvidenceRefs([]string{"user_messages", "core_verified_facts"}, version) {
			t.Fatalf("valid three-domain references were rejected for %s", version)
		}
		if validProviderEvidenceRefs([]string{"human_intent.current_prompt"}, version) ||
			validProviderEvidenceRefs([]string{"user_messages", "assistant_messages", "core_verified_facts", "actual_request"}, version) {
			t.Fatalf("legacy or oversized evidence references were accepted for %s", version)
		}
	}
}

func TestViewerRejectsTamperingUnsafeModesAndManifestPaths(t *testing.T) {
	t.Run("tampered-content", func(t *testing.T) {
		root, evidenceID := writeViewerFixture(t)
		path := filepath.Join(root, "2026-09", evidenceID, "03-model-response.json")
		if err := os.WriteFile(path, []byte(`{"tampered":true}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := verifyEvidence(root, evidenceID, &bytes.Buffer{}); err == nil {
			t.Fatal("tampered evidence passed verification")
		}
	})
	t.Run("unsafe-mode", func(t *testing.T) {
		root, evidenceID := writeViewerFixture(t)
		path := filepath.Join(root, "2026-09", evidenceID, "01-source-context.json")
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := verifyEvidence(root, evidenceID, &bytes.Buffer{}); err == nil {
			t.Fatal("world-readable evidence passed verification")
		}
	})
	t.Run("path-traversal", func(t *testing.T) {
		root, evidenceID := writeViewerFixture(t)
		bundle := filepath.Join(root, "2026-09", evidenceID)
		manifestPath := filepath.Join(bundle, "manifest.json")
		contents, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var value manifest
		if json.Unmarshal(contents, &value) != nil {
			t.Fatal("fixture manifest invalid")
		}
		delete(value.Files, "04-human-outcome.json")
		digest := hex.EncodeToString(make([]byte, sha256.Size))
		value.Files["../../outside.json"] = &digest
		encoded, err := json.Marshal(value)
		if err != nil || os.WriteFile(manifestPath, append(encoded, '\n'), 0o600) != nil {
			t.Fatal("write malicious manifest failed")
		}
		if _, _, err := loadManifest(root, evidenceID); err == nil {
			t.Fatal("manifest path traversal was accepted")
		}
	})
}

func TestViewerRejectsSemanticallyForgedButHashConsistentBundle(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	bundle := filepath.Join(root, "2026-09", evidenceID)
	sourcePath := filepath.Join(bundle, "01-source-context.json")
	contents, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if json.Unmarshal(contents, &source) != nil {
		t.Fatal("source fixture invalid")
	}
	source["evidence_id"] = "shadow-forged-00000001"
	forged := mustViewerJSON(t, source)
	if err := os.WriteFile(sourcePath, forged, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(bundle, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var value manifest
	if json.Unmarshal(manifestBytes, &value) != nil {
		t.Fatal("manifest fixture invalid")
	}
	digest := sha256.Sum256(forged)
	digestString := hex.EncodeToString(digest[:])
	value.Files["01-source-context.json"] = &digestString
	updated := mustViewerJSON(t, value)
	if err := os.WriteFile(manifestPath, updated, 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep the append-only index internally current so only the semantic join,
	// not a stale hash, exposes this forged bundle.
	indexBytes, err := os.ReadFile(filepath.Join(root, "index.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var index indexRecord
	if json.Unmarshal(indexBytes, &index) != nil {
		t.Fatal("index fixture invalid")
	}
	manifestDigest := sha256.Sum256(updated)
	index.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	if err := os.WriteFile(filepath.Join(root, "index.jsonl"), mustViewerJSON(t, index), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err == nil ||
		!bytes.Contains(output.Bytes(), []byte("source-identity-mismatch")) {
		t.Fatalf("hash-consistent semantic forgery passed: err=%v output=%s", err, output.Bytes())
	}
}

func TestViewerDetectsAStaleLatestIndexManifestHash(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	manifestPath := filepath.Join(root, "2026-09", evidenceID, "manifest.json")
	contents, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var value manifest
	if json.Unmarshal(contents, &value) != nil {
		t.Fatal("manifest fixture invalid")
	}
	value.CreatedAt = value.CreatedAt.Add(time.Nanosecond)
	if err := os.WriteFile(manifestPath, mustViewerJSON(t, value), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err == nil ||
		!bytes.Contains(output.Bytes(), []byte("latest-index-manifest-mismatch")) {
		t.Fatalf("stale index passed: err=%v output=%s", err, output.Bytes())
	}
}

func TestViewerFailsV10BundleWhenHumanOutcomeIsOverdue(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	bundle := filepath.Join(root, "2026-09", evidenceID)
	sourcePath := filepath.Join(bundle, "01-source-context.json")
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if json.Unmarshal(sourceBytes, &source) != nil {
		t.Fatal("source fixture invalid")
	}
	source["captured_at"] = time.Now().UTC().Add(-time.Hour)
	updatedSource := mustViewerJSON(t, source)
	if err := os.WriteFile(sourcePath, updatedSource, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(bundle, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var value manifest
	if json.Unmarshal(manifestBytes, &value) != nil {
		t.Fatal("manifest fixture invalid")
	}
	digest := sha256.Sum256(updatedSource)
	digestString := hex.EncodeToString(digest[:])
	value.Files["01-source-context.json"] = &digestString
	updatedManifest := mustViewerJSON(t, value)
	if err := os.WriteFile(manifestPath, updatedManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "index.jsonl")
	indexBytes, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index indexRecord
	if json.Unmarshal(indexBytes, &index) != nil {
		t.Fatal("index fixture invalid")
	}
	manifestDigest := sha256.Sum256(updatedManifest)
	index.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
	if err := os.WriteFile(indexPath, mustViewerJSON(t, index), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err == nil ||
		!bytes.Contains(output.Bytes(), []byte("human-outcome-overdue")) {
		t.Fatalf("overdue v10 outcome was not detected: err=%v output=%s", err, output.Bytes())
	}
}

func TestViewerReconcilesDecisionRecordsWithEvidenceBundles(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	recordRoot := filepath.Join(t.TempDir(), "records")
	if err := os.Mkdir(recordRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	validRecord := map[string]any{
		"schema_version": 1, "record_type": "e2_shadow_decision", "observed_at": now,
		"request_id": evidenceID, "gatekeeper_version": "e2-auditable-dogfood-v10",
		"decision": "allow", "model_called": true, "model_used": true,
		"evidence_id": evidenceID, "evidence_state": "model-finalized",
	}
	path := filepath.Join(recordRoot, "e2-authoritative-v23.jsonl")
	if err := os.WriteFile(path, mustViewerJSON(t, validRecord), 0o600); err != nil {
		t.Fatal(err)
	}
	var validOutput bytes.Buffer
	if err := auditEvidenceWithRecordRoot(root, recordRoot, &validOutput); err != nil ||
		!bytes.Contains(validOutput.Bytes(), []byte(`"decision_records_with_bundle": 1`)) {
		t.Fatalf("valid decision/evidence join failed: err=%v output=%s", err, validOutput.Bytes())
	}

	orphanID := "shadow-orphan-00000001"
	orphanRecord := map[string]any{
		"schema_version": 1, "record_type": "e2_shadow_decision", "observed_at": now,
		"request_id": orphanID, "gatekeeper_version": "e2-auditable-dogfood-v10",
		"decision": "escalate", "model_called": false, "model_used": false,
		"evidence_id": "", "evidence_state": "unavailable",
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(mustViewerJSON(t, orphanRecord)); err != nil || file.Close() != nil {
		t.Fatal("append orphan decision record failed")
	}
	var orphanOutput bytes.Buffer
	if err := auditEvidenceWithRecordRoot(root, recordRoot, &orphanOutput); err == nil ||
		!bytes.Contains(orphanOutput.Bytes(), []byte("decision-record-without-evidence:"+orphanID)) ||
		!bytes.Contains(orphanOutput.Bytes(), []byte(`"orphan_decision_records": 1`)) {
		t.Fatalf("orphan decision record was missed: err=%v output=%s", err, orphanOutput.Bytes())
	}
}

func TestViewerVerifiesV12CausalCodexTaskSnapshot(t *testing.T) {
	root, evidenceID := writeViewerFixture(t)
	bundle := filepath.Join(root, "2026-09", evidenceID)
	sourcePath := filepath.Join(bundle, "01-source-context.json")
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	var source map[string]any
	if json.Unmarshal(sourceBytes, &source) != nil {
		t.Fatal("source fixture invalid")
	}
	const taskID = "11111111-1111-4111-8111-111111111111"
	local := source["core_local_decision_request"].(map[string]any)
	local["mode"] = "shadow-submit"
	local["transcript_path"] = "/Users/fixture/.codex/sessions/2026/09/04/rollout-" + taskID + ".jsonl"
	source["transcript_snapshot"] = map[string]any{
		"codex_task_id": taskID, "capture_boundary": "file-size-at-open",
		"file_bytes_at_open": 100, "scanned_bytes": 100,
		"scanned_events": 1, "scanned_content_sha256": strings.Repeat("a", 64),
		"observed_candidates": 1, "retained_candidates": 1,
	}
	persist := func() {
		updatedSource := mustViewerJSON(t, source)
		if err := os.WriteFile(sourcePath, updatedSource, 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := filepath.Join(bundle, "manifest.json")
		manifestBytes, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var value manifest
		if json.Unmarshal(manifestBytes, &value) != nil {
			t.Fatal("manifest fixture invalid")
		}
		value.GatekeeperVersion = "e2-auditable-dogfood-v12"
		digest := sha256.Sum256(updatedSource)
		digestString := hex.EncodeToString(digest[:])
		value.Files["01-source-context.json"] = &digestString
		updatedManifest := mustViewerJSON(t, value)
		if err := os.WriteFile(manifestPath, updatedManifest, 0o600); err != nil {
			t.Fatal(err)
		}
		indexPath := filepath.Join(root, "index.jsonl")
		indexBytes, err := os.ReadFile(indexPath)
		if err != nil {
			t.Fatal(err)
		}
		var index indexRecord
		if json.Unmarshal(indexBytes, &index) != nil {
			t.Fatal("index fixture invalid")
		}
		manifestDigest := sha256.Sum256(updatedManifest)
		index.ManifestSHA256 = hex.EncodeToString(manifestDigest[:])
		if err := os.WriteFile(indexPath, mustViewerJSON(t, index), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	persist()
	if err := verifyEvidence(root, evidenceID, &bytes.Buffer{}); err != nil {
		t.Fatalf("valid v12 task snapshot failed: %v", err)
	}
	snapshot := source["transcript_snapshot"].(map[string]any)
	snapshot["scanned_bytes"] = float64(101)
	persist()
	var causalOutput bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &causalOutput); err == nil ||
		!bytes.Contains(causalOutput.Bytes(), []byte("transcript-causal-boundary-invalid")) {
		t.Fatalf("post-capture bytes passed v12 audit: err=%v output=%s", err, causalOutput.Bytes())
	}
	snapshot["scanned_bytes"] = float64(100)
	snapshot["scanned_content_sha256"] = "invalid"
	persist()
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err == nil ||
		!bytes.Contains(output.Bytes(), []byte("transcript-snapshot-invalid")) {
		t.Fatalf("invalid v11 transcript snapshot passed: err=%v output=%s", err, output.Bytes())
	}
}

func TestV12ModelContextProvenanceRejectsInjectedHumanAuthority(t *testing.T) {
	valid := json.RawMessage(`{
		"human_intent":{"prior_messages":[{"source":"human-message","trust_class":"human-authored"}]},
		"agent_context":{"ambient_context":[{"source":"codex-injected-agents-md","trust_class":"repository-policy-context"}]}
	}`)
	if !modelContextProvenanceValid(valid) {
		t.Fatal("valid separated model context provenance was rejected")
	}
	invalid := json.RawMessage(`{
		"human_intent":{"prior_messages":[{"source":"codex-injected-agents-md","trust_class":"human-authored"}]},
		"agent_context":{"ambient_context":[]}
	}`)
	if modelContextProvenanceValid(invalid) {
		t.Fatal("injected repository context was accepted as human authority")
	}
}

func writeViewerFixture(t *testing.T) (string, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "evidence")
	month := filepath.Join(root, "2026-09")
	const evidenceID = "shadow-viewer-00000001"
	bundle := filepath.Join(month, evidenceID)
	for _, directory := range []string{root, month, bundle} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	policy := "fixture policy"
	policyDigest := sha256.Sum256([]byte(policy))
	selected := json.RawMessage(`{"schema_version":1,"human_intent":{"current_prompt":"fixture"}}`)
	requestBody, err := json.Marshal(map[string]any{
		"model": "deepseek-v4-flash", "stream": false,
		"messages": []map[string]string{{"role": "system", "content": policy}, {"role": "user", "content": string(selected)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(requestBody)
	providerBody := []byte(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"reasoning_content":"diagnostic","content":"{\"decision\":\"allow\",\"reason\":\"Fixture is consistent.\"}"}}],"usage":{"completion_tokens_details":{"reasoning_tokens":3}}}`)
	providerDigest := sha256.Sum256(providerBody)
	now := time.Now().UTC()
	files := map[string][]byte{
		"01-source-context.json": mustViewerJSON(t, map[string]any{
			"schema_version": 1, "record_type": "beholder_source_context", "evidence_id": evidenceID,
			"captured_at": now, "operation_target_sha256": hex.EncodeToString(make([]byte, sha256.Size)),
			"selected_model_input": selected,
			"onenod_requester_context": map[string]any{
				"executable": "/fixture/may", "executable_sha256": hex.EncodeToString(make([]byte, sha256.Size)),
				"arguments": []any{},
			},
			"selection_metrics": map[string]any{"completed_tools": 1},
			"core_local_decision_request": map[string]any{
				"request_id": evidenceID, "prompt": "fixture", "tool_input": `{}`, "evidence": `{}`,
				"actual_request": map[string]any{
					"surface": "direct-may", "operation": "secret.read",
					"payload_digest": hex.EncodeToString(make([]byte, sha256.Size)),
				},
			},
		}),
		"02-model-request.json": mustViewerJSON(t, map[string]any{
			"schema_version": 1, "record_type": "beholder_model_request", "evidence_id": evidenceID,
			"request_sent": true, "body_bytes": len(requestBody),
			"body_sha256":     hex.EncodeToString(requestDigest[:]),
			"raw_body_base64": base64.StdEncoding.EncodeToString(requestBody), "body": json.RawMessage(requestBody),
			"build_error": nil,
		}),
		"03-model-response.json": mustViewerJSON(t, map[string]any{
			"schema_version": 1, "record_type": "beholder_model_response", "evidence_id": evidenceID,
			"http_status": 200, "body_bytes": len(providerBody),
			"body_sha256":     hex.EncodeToString(providerDigest[:]),
			"raw_body_base64": base64.StdEncoding.EncodeToString(providerBody), "body": json.RawMessage(providerBody),
			"transport_error": nil, "parser_error": nil, "decision": "allow", "reason": "Fixture is consistent.",
			"evidence_refs": []string{}, "response_shape": "decision-json-valid", "model_used": true,
			"model_called": true, "reasoning_present": true, "reasoning_bytes": len("diagnostic"),
			"reasoning_tokens": 3, "finish_reason": "stop", "latency_ms": 5,
		}),
		"redactions.json": mustViewerJSON(t, map[string]any{
			"schema_version": 1, "record_type": "beholder_evidence_redactions",
			"evidence_id": evidenceID, "events": []any{},
		}),
	}
	digests := map[string]*string{
		"01-source-context.json": nil,
		"02-model-request.json":  nil,
		"03-model-response.json": nil,
		"04-human-outcome.json":  nil,
		"redactions.json":        nil,
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(bundle, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		value := hex.EncodeToString(digest[:])
		digests[name] = &value
	}
	manifestValue := manifest{
		SchemaVersion: 1, RecordType: "beholder_decision_evidence_manifest",
		EvidenceID: evidenceID, State: "model-finalized", CreatedAt: now,
		GatekeeperVersion: "e2-auditable-dogfood-v10",
		PolicySHA256:      hex.EncodeToString(policyDigest[:]), Files: digests,
	}
	encoded, err := json.Marshal(manifestValue)
	if err != nil || os.WriteFile(filepath.Join(bundle, "manifest.json"), append(encoded, '\n'), 0o600) != nil {
		t.Fatal("write fixture manifest failed")
	}
	manifestDigest := sha256.Sum256(append(encoded, '\n'))
	called, used, status, latency := true, true, 200, int64(5)
	index := indexRecord{
		SchemaVersion: 1, RecordType: "beholder_evidence_index_event", ObservedAt: now,
		EvidenceID: evidenceID, Phase: "model-decision", Surface: "direct-may", Operation: "secret.read",
		Decision: "allow", Reason: "Fixture is consistent.", ModelCalled: &called, ModelUsed: &used,
		ResponseShape: "decision-json-valid", HTTPStatus: &status, LatencyMS: &latency,
		BundlePath: bundle, State: "model-finalized", ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}
	if err := os.WriteFile(filepath.Join(root, "index.jsonl"), mustViewerJSON(t, index), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, evidenceID
}

func writeDualThinkingViewerFixture(t *testing.T, authoritative ...bool) (string, string) {
	t.Helper()
	isAuthoritative := len(authoritative) == 1 && authoritative[0]
	primaryVariant, comparisonVariant := "thinking-enabled", "thinking-disabled"
	gatekeeperVersion := "e2-dual-shadow-dogfood-v17"
	if isAuthoritative {
		primaryVariant, comparisonVariant = "thinking-disabled", "thinking-enabled"
		gatekeeperVersion = "e2-authoritative-dogfood-v26"
	}
	comparisonRequestName := "05-model-request-" + comparisonVariant + ".json"
	comparisonResponseName := "06-model-response-" + comparisonVariant + ".json"
	root, evidenceID := writeViewerFixture(t)
	bundle := filepath.Join(root, "2026-09", evidenceID)

	readObject := func(name string) map[string]any {
		contents, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if json.Unmarshal(contents, &value) != nil {
			t.Fatalf("invalid fixture object %s", name)
		}
		return value
	}
	writeObject := func(name string, value map[string]any) string {
		contents := mustViewerJSON(t, value)
		if err := os.WriteFile(filepath.Join(bundle, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(contents)
		return hex.EncodeToString(digest[:])
	}
	updateRawBody := func(record map[string]any, body map[string]any) {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		record["body"] = body
		record["body_bytes"] = len(raw)
		record["body_sha256"] = hex.EncodeToString(digest[:])
		record["raw_body_base64"] = base64.StdEncoding.EncodeToString(raw)
	}

	source := readObject("01-source-context.json")
	source["transcript_snapshot"] = map[string]any{
		"capture_boundary":   "file-size-at-open",
		"file_bytes_at_open": 100, "scanned_bytes": 100, "scanned_events": 1,
		"scanned_content_sha256": strings.Repeat("a", 64),
		"observed_candidates":    1, "retained_candidates": 1,
	}
	sourceDigest := writeObject("01-source-context.json", source)

	primaryRequest := readObject("02-model-request.json")
	primaryRequest["variant"] = primaryVariant
	primaryRequest["endpoint"] = "https://example.invalid/v1/chat/completions"
	primaryBody := primaryRequest["body"].(map[string]any)
	primaryBody["thinking"] = map[string]any{"type": strings.TrimPrefix(primaryVariant, "thinking-")}
	updateRawBody(primaryRequest, primaryBody)
	primaryRequestDigest := writeObject("02-model-request.json", primaryRequest)

	comparisonRequestBytes, _ := json.Marshal(primaryRequest)
	var comparisonRequest map[string]any
	_ = json.Unmarshal(comparisonRequestBytes, &comparisonRequest)
	comparisonRequest["variant"] = comparisonVariant
	comparisonBody := comparisonRequest["body"].(map[string]any)
	comparisonBody["thinking"] = map[string]any{"type": strings.TrimPrefix(comparisonVariant, "thinking-")}
	updateRawBody(comparisonRequest, comparisonBody)
	comparisonRequestDigest := writeObject(comparisonRequestName, comparisonRequest)

	primaryResponse := readObject("03-model-response.json")
	primaryResponse["variant"] = primaryVariant
	primaryResponse["model_transport"] = "go-http"
	primaryResponseDigest := writeObject("03-model-response.json", primaryResponse)

	comparisonProviderBody := []byte(`{"model":"deepseek-v4-flash","choices":[{"finish_reason":"stop","message":{"content":"{\"decision\":\"allow\",\"reason\":\"Fixture is consistent.\"}"}}]}`)
	comparisonProviderDigest := sha256.Sum256(comparisonProviderBody)
	comparisonResponse := map[string]any{
		"schema_version": 1, "record_type": "beholder_model_response", "evidence_id": evidenceID,
		"variant": comparisonVariant, "http_status": 200, "body_bytes": len(comparisonProviderBody),
		"body_sha256":     hex.EncodeToString(comparisonProviderDigest[:]),
		"raw_body_base64": base64.StdEncoding.EncodeToString(comparisonProviderBody),
		"body":            json.RawMessage(comparisonProviderBody), "transport_error": nil, "parser_error": nil,
		"decision": "allow", "reason": "Fixture is consistent.", "evidence_refs": []string{},
		"response_shape": "decision-json-valid", "model_used": true, "model_called": true,
		"model_transport": "go-http", "reasoning_present": false, "reasoning_bytes": 0,
		"reasoning_tokens": 0, "finish_reason": "stop", "latency_ms": 3,
	}
	comparisonResponseDigest := writeObject(comparisonResponseName, comparisonResponse)

	manifestPath := filepath.Join(bundle, "manifest.json")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifestValue manifest
	if json.Unmarshal(manifestBytes, &manifestValue) != nil {
		t.Fatal("invalid fixture manifest")
	}
	manifestValue.GatekeeperVersion = gatekeeperVersion
	manifestValue.SchemaVersion = 2
	manifestValue.Files["01-source-context.json"] = &sourceDigest
	manifestValue.Files["02-model-request.json"] = &primaryRequestDigest
	manifestValue.Files["03-model-response.json"] = &primaryResponseDigest
	manifestValue.Files[comparisonRequestName] = &comparisonRequestDigest
	manifestValue.Files[comparisonResponseName] = &comparisonResponseDigest
	updatedManifest := mustViewerJSON(t, manifestValue)
	if err := os.WriteFile(manifestPath, updatedManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(updatedManifest)
	called, used, status := true, true, 200
	primaryLatency, comparisonLatency := int64(5), int64(3)
	indexRecords := []indexRecord{
		{
			SchemaVersion: 1, RecordType: "beholder_evidence_index_event", ObservedAt: time.Now().UTC(),
			EvidenceID: evidenceID, Phase: "model-decision", Variant: primaryVariant,
			Decision: "allow", Reason: "Fixture is consistent.", ModelCalled: &called, ModelUsed: &used,
			ResponseShape: "decision-json-valid", HTTPStatus: &status, LatencyMS: &primaryLatency,
			BundlePath: bundle, State: "model-finalized", ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		},
		{
			SchemaVersion: 1, RecordType: "beholder_evidence_index_event", ObservedAt: time.Now().UTC(),
			EvidenceID: evidenceID, Phase: "model-comparison", Variant: comparisonVariant,
			Decision: "allow", Reason: "Fixture is consistent.", ModelCalled: &called, ModelUsed: &used,
			ResponseShape: "decision-json-valid", HTTPStatus: &status, LatencyMS: &comparisonLatency,
			BundlePath: bundle, State: "model-finalized", ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
		},
	}
	var index bytes.Buffer
	for _, record := range indexRecords {
		index.Write(mustViewerJSON(t, record))
	}
	if err := os.WriteFile(filepath.Join(root, "index.jsonl"), index.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, evidenceID
}

func mustViewerJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(encoded, '\n')
}
