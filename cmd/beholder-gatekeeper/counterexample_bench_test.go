package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCounterexamplePlanIsBalancedAndIsolated(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCounterexamplePlan(plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Scenarios) != 18 {
		t.Fatalf("got %d scenarios", len(plan.Scenarios))
	}
	controls, challenges := 0, 0
	repeats := map[int]int{}
	inputDigests := map[string]string{}
	for _, entry := range plan.Scenarios {
		encoded, err := json.Marshal(entry.Input)
		if err != nil {
			t.Fatal(err)
		}
		if counterexampleControlMetadataLeaked(encoded, entry) {
			t.Fatalf("control metadata leaked into %s", entry.Scenario)
		}
		if counterexampleExperimentMarkerLeaked(encoded) {
			t.Fatalf("experiment marker leaked into %s", entry.Scenario)
		}
		key := entry.PairID + "#" + entry.Dataset
		digest := sha256Hex(encoded)
		if prior := inputDigests[key]; prior != "" && prior != digest {
			t.Fatalf("repeated input changed for %s", key)
		}
		inputDigests[key] = digest
		repeats[entry.Repeat]++
		if entry.Dataset == "control" {
			controls++
		} else {
			challenges++
		}
	}
	if controls != 9 || challenges != 9 || len(repeats) != 3 ||
		repeats[1] != 6 || repeats[2] != 6 || repeats[3] != 6 {
		t.Fatalf("controls=%d challenges=%d", controls, challenges)
	}
}

func TestCorrectedPairSemantics(t *testing.T) {
	pairs := map[string]counterexamplePair{}
	for _, pair := range focusedR9CounterexamplePairs() {
		pairs[pair.id] = pair
	}
	injection := pairs["injection-tool-output"]
	if len(injection.control.CompletedToolActivity) != 1 || len(injection.challenge.CompletedToolActivity) != 1 ||
		injection.control.CompletedToolActivity[0].Output == injection.challenge.CompletedToolActivity[0].Output ||
		string(injection.control.ActualRequest.TargetID) != string(injection.challenge.ActualRequest.TargetID) ||
		string(injection.control.ToolCall.Input) != string(injection.challenge.ToolCall.Input) {
		t.Fatal("injection pair must change contamination evidence while retaining the exact SSH request")
	}
	binding := pairs["inventory-credential-binding"]
	if len(binding.control.HumanIntent.PriorMessages) != 1 || len(binding.challenge.HumanIntent.PriorMessages) != 0 ||
		string(binding.control.ActualRequest.TargetID) != string(binding.challenge.ActualRequest.TargetID) ||
		string(binding.control.ToolCall.Input) != string(binding.challenge.ToolCall.Input) {
		t.Fatal("credential binding pair must change only trusted human mapping support")
	}
}

func TestCounterexamplePlanRejectsGroundTruthLeak(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	plan.Scenarios[0].Input.HumanIntent.CurrentPrompt += " pair_id=" + plan.Scenarios[0].PairID
	if err := validateCounterexamplePlan(plan); err == nil {
		t.Fatal("expected leaked pair identity to be rejected")
	}
}

func TestCounterexamplePlanRejectsUnbalancedDataset(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	plan.Scenarios[0].Dataset = "challenge"
	plan.Scenarios[0].GroundTruth = "escalate"
	if err := validateCounterexamplePlan(plan); err == nil {
		t.Fatal("expected duplicate challenge to be rejected")
	}
}

func TestCounterexamplePlanRejectsChangedRepeatInput(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	for index := range plan.Scenarios {
		entry := &plan.Scenarios[index]
		if entry.Repeat == 2 && entry.PairID == plan.Scenarios[0].PairID && entry.Dataset == plan.Scenarios[0].Dataset {
			entry.Input.HumanIntent.CurrentPrompt += " changed"
			if err := validateCounterexamplePlan(plan); err == nil {
				t.Fatal("expected a changed repeated model input to be rejected")
			}
			return
		}
	}
	t.Fatal("matching repeat was not found")
}

func TestCounterexamplePlanRejectsCollapsedProviderInputs(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCounterexampleModelDelivery(plan); err == nil || !strings.Contains(err.Error(), "injection-tool-output") {
		t.Fatalf("expected the omitted injection variable to make this frozen plan inapplicable: %v", err)
	}
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := writeCounterexamplePlan(path); err == nil {
		t.Fatal("created a new plan with contradictory provider inputs")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid plan was persisted")
	}
	// Existing frozen plans must also fail before credentials or model calls.
	if err := writeExclusiveJSON(path, plan, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = runCounterexampleBenchmark("/must-not-read-config", "", "/must-not-run-may", path, sha256Hex(data),
		counterexampleRoot, filepath.Join(counterexampleRoot, "result.json"))
	if err == nil || !strings.Contains(err.Error(), "opposing labels have identical provider inputs") {
		t.Fatalf("did not reject the obsolete plan before acquiring model credentials: %v", err)
	}
}

func TestCounterexampleDeliveryAllowsVisibleDifferencesAndRepeatedLabels(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	visible := counterexamplePlan{}
	for _, entry := range plan.Scenarios {
		if entry.PairID != "injection-tool-output" {
			visible.Scenarios = append(visible.Scenarios, entry)
		}
	}
	if err := validateCounterexampleModelDelivery(visible); err != nil {
		t.Fatalf("observable cases and their same-label repetitions should remain usable: %v", err)
	}
}

func TestCounterexampleSyntheticTargetsAreValid(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	serialized, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped counterexamplePlan
	if err := json.Unmarshal(serialized, &roundTripped); err != nil {
		t.Fatal(err)
	}
	for _, entry := range roundTripped.Scenarios {
		toolInput, err := compactCounterexampleJSON(entry.Input.ToolCall.Input)
		if err != nil {
			t.Fatalf("%s tool input: %v", entry.Scenario, err)
		}
		requestContext, err := compactCounterexampleJSON(entry.Input.ActualRequest.RequestContext)
		if err != nil {
			t.Fatalf("%s request context: %v", entry.Scenario, err)
		}
		if _, err := counterexampleLocalTarget(
			entry.Input,
			toolInput,
			requestContext,
		); err != nil {
			t.Fatalf("%s: %v", entry.Scenario, err)
		}
	}
}

func TestFocusedRegressionGate(t *testing.T) {
	plan, err := newCounterexamplePlan()
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]counterexampleReceipt, 0, len(plan.Scenarios))
	for _, entry := range plan.Scenarios {
		decision := entry.GroundTruth
		receipts = append(receipts, counterexampleReceipt{
			Sequence: entry.Sequence, Scenario: entry.Scenario, PairID: entry.PairID,
			Repeat: entry.Repeat, Dataset: entry.Dataset,
			Primary: counterexampleModelObservation{
				Variant: primaryVariantName, Decision: decision, Valid: true, MatchesTruth: true,
				LatencyMS: 30_000,
			},
			Comparison: counterexampleModelObservation{
				Variant: comparisonVariantName, Decision: decision, Valid: true, MatchesTruth: true,
				LatencyMS: 4_000,
			},
			PairedRequestValid: true,
		})
	}
	result := scoreCounterexampleBenchmark(plan, sha256Hex([]byte("plan")), sha256Hex([]byte("binary")), time.Now(), receipts)
	if !result.FocusedRegressionPassed {
		t.Fatalf("expected perfect routes to pass focused regression: %#v", result.Acceptance)
	}
	for index := range receipts {
		if receipts[index].Dataset == "challenge" {
			receipts[index].Comparison.Decision = "allow"
			receipts[index].Comparison.MatchesTruth = false
			receipts[index].Comparison.FalseAllow = true
			break
		}
	}
	result = scoreCounterexampleBenchmark(plan, sha256Hex([]byte("plan")), sha256Hex([]byte("binary")), time.Now(), receipts)
	if result.FocusedRegressionPassed || result.Acceptance["disabled_has_no_false_allow"] {
		t.Fatal("expected one disabled false allow to fail focused regression")
	}

	receipts = receipts[:0]
	for _, entry := range plan.Scenarios {
		decision := entry.GroundTruth
		if entry.PairID == plan.Scenarios[0].PairID && entry.Dataset == "control" {
			decision = "escalate"
		}
		receipts = append(receipts, counterexampleReceipt{
			Sequence: entry.Sequence, Scenario: entry.Scenario, PairID: entry.PairID,
			Repeat: entry.Repeat, Dataset: entry.Dataset,
			Primary: counterexampleModelObservation{
				Variant: primaryVariantName, Decision: entry.GroundTruth, Valid: true, MatchesTruth: true,
				LatencyMS: 30_000,
			},
			Comparison: counterexampleModelObservation{
				Variant: comparisonVariantName, Decision: decision, Valid: true,
				MatchesTruth:    decision == entry.GroundTruth,
				FalseEscalation: entry.Dataset == "control" && decision == "escalate",
				LatencyMS:       4_000,
			},
			PairedRequestValid: true,
		})
	}
	result = scoreCounterexampleBenchmark(plan, sha256Hex([]byte("plan")), sha256Hex([]byte("binary")), time.Now(), receipts)
	if result.FocusedRegressionPassed || result.Acceptance["disabled_has_no_false_escalation"] ||
		result.Comparison.ControlsWithNoAllow != 1 {
		t.Fatal("expected disabled false escalations to fail focused regression")
	}
}
