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

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
)

func TestV30ViewerChecksChronologyWithoutHistoricalRecordLimit(t *testing.T) {
	root, evidenceID := writeDualThinkingViewerFixture(t, true)
	input := v5ViewerInput()
	rewriteV30ViewerFixture(t, root, evidenceID, input)
	var output bytes.Buffer
	if err := verifyEvidence(root, evidenceID, &output); err != nil {
		t.Fatalf("valid v30 evidence failed: %v %s", err, output.Bytes())
	}
	// All bodies, stage hashes and index hashes are updated too. Provenance,
	// rather than a stale digest, must expose the forged human authority.
	users := input["user_messages"].(map[string]any)["messages"].([]any)
	users[1].(map[string]any)["source"] = "repository-file"
	rewriteV30ViewerFixture(t, root, evidenceID, input)
	output.Reset()
	if err := verifyEvidence(root, evidenceID, &output); err == nil ||
		!bytes.Contains(output.Bytes(), []byte("context-provenance-invalid")) {
		t.Fatalf("hash-consistent provenance forgery passed: %v %s", err, output.Bytes())
	}
}

func TestViewerDoesNotTreatUnknownSchemasAsLegacy(t *testing.T) {
	if modelContextProvenanceValid(json.RawMessage(`{"schema_version":999}`)) {
		t.Fatal("unknown schema bypassed provenance validation")
	}
	for _, version := range []string{"e2-authoritative-dogfood-v27", "e2-authoritative-dogfood-v30", "e2-authoritative-dogfood-v31"} {
		if !authoritativeDogfoodVersion(version) || primaryVariantForVersion(version) != "thinking-disabled" ||
			!validProviderEvidenceRefs([]string{"user_messages", "core_verified_facts"}, version) {
			t.Fatalf("missing authoritative evidence contract for %s", version)
		}
	}
}

func TestV31ViewerRequiresExactDirectInputProjection(t *testing.T) {
	source := v5ViewerInput()
	captured := source["core_verified_facts"].(map[string]any)["captured_context"].(map[string]any)
	captured["completed_tool_activity"] = []any{map[string]any{"output": "archived fixture result"}}
	captured["coverage"] = map[string]any{"selection": "fixture capture", "other_text_bytes": 23}
	raw := mustViewerJSON(t, source)
	projected, err := modelcontract.DirectModelInput(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"messages": []any{
		map[string]any{"role": "system", "content": "fixture policy"},
		map[string]any{"role": "user", "content": string(projected)},
	}}
	if !modelInputMatches(raw, mustViewerJSON(t, body), "e2-authoritative-dogfood-v31") ||
		modelInputMatches(raw, mustViewerJSON(t, body), "e2-authoritative-dogfood-v30") {
		t.Fatal("projection must be exact and version-bound")
	}
	for _, field := range []string{"tools", "tool_choice"} {
		body[field] = nil
		if modelInputMatches(raw, mustViewerJSON(t, body), "e2-authoritative-dogfood-v31") {
			t.Fatalf("unexpected %s escaped the no-tools contract", field)
		}
		delete(body, field)
	}
	source["user_messages"].(map[string]any)["messages"].([]any)[0].(map[string]any)["text"] = "changed human instruction"
	if modelInputMatches(mustViewerJSON(t, source), mustViewerJSON(t, body), "e2-authoritative-dogfood-v31") {
		t.Fatal("changed human direction passed the source-to-model check")
	}
}

func v5ViewerInput() map[string]any {
	users := make([]any, 300)
	for i := range users {
		source, relation := "human-message", "after-current-prompt"
		if i == 0 {
			source, relation = "managed-current-user-prompt", "turn-binding-anchor"
		}
		users[i] = map[string]any{
			"text": "fixture direction", "source": source, "trust_class": "human-authored",
			"session_ordinal": i + 1, "is_latest": i == len(users)-1, "temporal_relation": relation,
		}
	}
	return map[string]any{
		"schema_version": 5,
		"user_messages": map[string]any{
			"order": "oldest-to-newest", "messages": users, "latest_message_index": len(users) - 1,
			"turn_anchor_index": 0,
		},
		"assistant_messages": map[string]any{},
		"core_verified_facts": map[string]any{
			"actual_request": map[string]any{"verification_scope": "operation-and-target-bound-by-core"},
			"captured_context": map[string]any{
				"current_tool_call": map[string]any{
					"source": "managed-pre-tool-use", "trust_class": "core-captured",
					"temporal_relation": "associated-execution-candidate",
				},
			},
		},
	}
}

func rewriteV30ViewerFixture(t *testing.T, root, evidenceID string, input map[string]any) {
	t.Helper()
	bundle := filepath.Join(root, "2026-09", evidenceID)
	read := func(name string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	write := func(name string, value any) string {
		raw := mustViewerJSON(t, value)
		if err := os.WriteFile(filepath.Join(bundle, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(raw)
		return hex.EncodeToString(digest[:])
	}
	manifest := read("manifest.json")
	manifest["gatekeeper_version"] = "e2-authoritative-dogfood-v30"
	files := manifest["files"].(map[string]any)
	source := read("01-source-context.json")
	source["selected_model_input"] = input
	snapshot := source["transcript_snapshot"].(map[string]any)
	snapshot["scanned_events"] = 300
	snapshot["observed_candidates"] = 300
	snapshot["retained_candidates"] = 300
	files["01-source-context.json"] = write("01-source-context.json", source)
	for _, name := range []string{"02-model-request.json", "05-model-request-thinking-enabled.json"} {
		record := read(name)
		body := record["body"].(map[string]any)
		messages := body["messages"].([]any)
		messages[1].(map[string]any)["content"] = string(bytes.TrimSpace(mustViewerJSON(t, input)))
		raw := bytes.TrimSpace(mustViewerJSON(t, body))
		digest := sha256.Sum256(raw)
		record["body_bytes"] = len(raw)
		record["body_sha256"] = hex.EncodeToString(digest[:])
		record["raw_body_base64"] = base64.StdEncoding.EncodeToString(raw)
		files[name] = write(name, record)
	}
	manifestDigest := write("manifest.json", manifest)
	indexPath := filepath.Join(root, "index.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index bytes.Buffer
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatal(err)
		}
		entry["manifest_sha256"] = manifestDigest
		index.Write(mustViewerJSON(t, entry))
	}
	if err := os.WriteFile(indexPath, index.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}
