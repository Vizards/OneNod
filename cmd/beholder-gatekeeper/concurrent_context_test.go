package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
)

func TestEvidenceClonePreservesEmptyAndNilContainersInExactProviderProjection(t *testing.T) {
	for _, empty := range []bool{false, true} {
		input := focusedR9CounterexamplePairs()[0].control
		input.SchemaVersion = externalDecisionInputSchemaVersion
		if empty {
			input.RequesterContext.Arguments = []requesterArgument{}
			input.RequesterContext.RelevantEnvironment = []requesterEnvironmentValue{}
			input.Environment.WorkspaceRoots = []string{}
			input.Environment.ResolvedExecutables = map[string]string{}
		} else {
			input.RequesterContext.Arguments = nil
			input.RequesterContext.RelevantEnvironment = nil
			input.Environment.WorkspaceRoots = nil
			input.Environment.ResolvedExecutables = nil
		}
		original, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		copied, err := json.Marshal(cloneExternalDecisionInput(input))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(original, copied) {
			t.Fatalf("evidence source copy changed nil/empty containers (allocated=%t)", empty)
		}
		provider, err := modelcontract.DirectModelInput(original)
		if err != nil {
			t.Fatal(err)
		}
		fromEvidence, err := modelcontract.DirectModelInput(copied)
		if err != nil || !bytes.Equal(provider, fromEvidence) {
			t.Fatal("evidence does not reproduce the exact provider input")
		}
	}
}

func TestConcurrentCandidateContextSurvivesProviderProjectionWithoutInventedAttribution(t *testing.T) {
	input := focusedR9CounterexamplePairs()[0].control
	input.SchemaVersion = externalDecisionInputSchemaVersion
	input.ToolCall.Name = "concurrent-tool-candidates"
	input.ToolCall.Input = json.RawMessage(`{"kind":"concurrent-tool-candidates","verification_scope":"same-task-observations; exact-causal-tool-unresolved","prompt_anchor_scope":"earliest-eligible-observation-for-chronology-only","candidates":[{"tool_use_ref":"tool-a","tool_name":"Bash","tool_input":{"command":"sleep 20"}},{"tool_use_ref":"tool-b","tool_name":"Bash","tool_input":{"command":"may read fixture"}}]}`)
	input.CoreEvidence = json.RawMessage(`{"collection":{"status":"ready"},"attribution":{"result":"task-bound-tool-candidates","execution_root_matched":true,"request_thread_matched":true,"tool_ref_matched":false,"late_binding_candidate_count":2}}`)
	selected, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := modelcontract.DirectModelInput(selected)
	if err != nil {
		t.Fatal(err)
	}
	var delivered modelDecisionInputWire
	if err := json.Unmarshal(provider, &delivered); err != nil {
		t.Fatal(err)
	}
	call := delivered.CoreVerifiedFacts.CapturedContext.CurrentToolCall
	if call.Name != "concurrent-tool-candidates" || call.TemporalRelation != "associated-execution-candidate" ||
		!bytes.Equal(call.Input, input.ToolCall.Input) ||
		!bytes.Equal(delivered.CoreVerifiedFacts.Evidence, input.CoreEvidence) {
		t.Fatal("candidate evidence was dropped or presented as a unique causal tool")
	}
	var restored externalDecisionInput
	if err := json.Unmarshal(selected, &restored); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := json.Marshal(restored)
	if err != nil || !bytes.Equal(roundTrip, selected) {
		t.Fatal("candidate provenance did not survive exact evidence reconstruction")
	}
}
