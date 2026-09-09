package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type blindedScenarioPlan struct {
	SchemaVersion int                    `json:"schema_version"`
	RecordType    string                 `json:"record_type"`
	PlanVersion   string                 `json:"plan_version"`
	Scenarios     []blindedScenarioEntry `json:"scenarios"`
}

type blindedScenarioEntry struct {
	Sequence       int    `json:"sequence"`
	Scenario       string `json:"scenario"`
	Dataset        string `json:"dataset"`
	Category       string `json:"category"`
	TargetAlias    string `json:"target_alias"`
	GroundTruth    string `json:"ground_truth"`
	IntentContract string `json:"intent_contract"`
}

type evaluationRecord struct {
	SchemaVersion             int       `json:"schema_version"`
	RecordType                string    `json:"record_type"`
	ObservedAt                time.Time `json:"observed_at"`
	PlanVersion               string    `json:"plan_version"`
	PlanSHA256                string    `json:"plan_sha256"`
	Scenario                  string    `json:"scenario"`
	Dataset                   string    `json:"dataset"`
	Category                  string    `json:"category"`
	TargetAlias               string    `json:"target_alias"`
	GroundTruth               string    `json:"ground_truth"`
	HumanDecision             string    `json:"human_decision"`
	Executed                  bool      `json:"executed"`
	GatekeeperRequestID       string    `json:"gatekeeper_request_id"`
	GatekeeperDecision        string    `json:"gatekeeper_decision"`
	GatekeeperReason          string    `json:"gatekeeper_reason"`
	GatekeeperErrorCode       *string   `json:"gatekeeper_error_code"`
	GatekeeperVersion         string    `json:"gatekeeper_version"`
	GatekeeperBinarySHA256    string    `json:"gatekeeper_binary_sha256"`
	PolicySHA256              string    `json:"policy_sha256"`
	ConfigSHA256              string    `json:"config_sha256"`
	Model                     string    `json:"model"`
	ModelUsed                 bool      `json:"model_used"`
	ModelCalled               bool      `json:"model_called"`
	ResponseShape             string    `json:"response_shape"`
	ScopeResolution           string    `json:"scope_resolution"`
	EvidenceRefs              []string  `json:"evidence_refs"`
	ReasoningPresent          bool      `json:"reasoning_present"`
	ReasoningBytes            int       `json:"reasoning_bytes"`
	ReasoningTokens           int       `json:"reasoning_tokens"`
	FinishReason              string    `json:"finish_reason"`
	LatencyMS                 int64     `json:"latency_ms"`
	CollectionStatus          string    `json:"collection_status"`
	CollectionErrorCode       *string   `json:"collection_error_code"`
	AttributionResult         string    `json:"attribution_result"`
	AttributionCandidateCount int       `json:"attribution_candidate_count"`
	AttributionConflicts      []string  `json:"attribution_conflicts"`
	ObservedFeatureGroups     []string  `json:"observed_feature_groups"`
	FalseAllow                bool      `json:"false_allow"`
	DecisionMatchesTruth      bool      `json:"decision_matches_ground_truth"`
	RawPromptStored           bool      `json:"raw_prompt_stored"`
	RawToolInputStored        bool      `json:"raw_tool_input_stored"`
	RawModelResponseStored    bool      `json:"raw_model_response_stored"`
	RawReasoningContentStored bool      `json:"raw_reasoning_content_stored"`
	CredentialMaterialStored  bool      `json:"credential_material_stored"`
	TaskRefSHA256             string    `json:"task_ref_sha256,omitempty"`
	TaskCWDRefSHA256          string    `json:"task_cwd_ref_sha256,omitempty"`
	DecisionStartLine         int       `json:"decision_start_line,omitempty"`
	DecisionLine              int       `json:"decision_line,omitempty"`
	IOSVisibilityConfirmed    bool      `json:"ios_visibility_confirmed,omitempty"`
	UserAuthoredPrompt        bool      `json:"user_authored_prompt,omitempty"`
}

func finalizeUnassignedEvaluation(
	planPath, planSHA256, expectedDecisionBinarySHA256, decisionPath, evaluationPath,
	scenario, requestID, taskRefSHA256, taskCWDRefSHA256 string,
	decisionStartLine int,
	humanDecision string,
	executed bool,
) error {
	if !filepath.IsAbs(planPath) || !filepath.IsAbs(decisionPath) || !filepath.IsAbs(evaluationPath) ||
		!validSHA256(expectedDecisionBinarySHA256) || !validSHA256(taskRefSHA256) ||
		!validSHA256(taskCWDRefSHA256) || !safeRecordLabel(scenario) ||
		!safeRecordLabel(requestID) || decisionStartLine < 0 ||
		!validHumanDecision(humanDecision) || (executed && humanDecision != "approved") {
		return errors.New("invalid unassigned evaluation input")
	}
	plan, entry, actualPlanSHA256, err := loadBlindedScenario(planPath, planSHA256, scenario)
	if err != nil {
		return err
	}
	decision, decisionLine, err := readUnassignedDecisionAfterLine(decisionPath, requestID, decisionStartLine)
	if err != nil {
		return err
	}
	if decision.Dataset != "unassigned-live-shadow" || decision.Scenario != "unlabeled-live" ||
		decision.TargetAlias != entry.TargetAlias || decision.GatekeeperVersion != gatekeeperVersion ||
		decision.ConfigSHA256 != confirmedConfigSHA256 ||
		decision.GatekeeperBinarySHA256 != expectedDecisionBinarySHA256 ||
		decision.PolicySHA256 != gatekeeperPolicySHA256() ||
		!decision.RawPromptStored || !decision.RawToolInputStored || !decision.RawModelResponseStored ||
		decision.RawReasoningContentStored != decision.ReasoningPresent || decision.CredentialMaterialStored ||
		decision.ReasoningBytes < 0 || decision.ReasoningTokens < 0 ||
		(decision.ModelUsed != (decision.ResponseShape == "decision-json-valid")) ||
		(decision.ModelUsed && (!decision.ModelCalled || !validRecordedFinishReason(decision.FinishReason) ||
			(decision.ScopeResolution != "" && !validScopeResolution(decision.ScopeResolution)) ||
			(len(decision.EvidenceRefs) != 0 && !validEvidenceRefs(decision.EvidenceRefs)))) {
		return errors.New("unassigned decision does not match the frozen scenario")
	}
	if err := ensureScenarioNotFinalized(evaluationPath, scenario); err != nil {
		return err
	}
	writer, err := newRecordWriter(evaluationPath)
	if err != nil {
		return err
	}
	record := evaluationRecord{
		SchemaVersion: 1, RecordType: "e2_evaluation", ObservedAt: time.Now().UTC(),
		PlanVersion: plan.PlanVersion, PlanSHA256: actualPlanSHA256,
		Scenario: scenario, Dataset: entry.Dataset, Category: entry.Category,
		TargetAlias: entry.TargetAlias, GroundTruth: entry.GroundTruth,
		HumanDecision: humanDecision, Executed: executed,
		GatekeeperRequestID: decision.RequestID, GatekeeperDecision: decision.Decision,
		GatekeeperReason: decision.Reason, GatekeeperErrorCode: decision.ErrorCode,
		GatekeeperVersion:      decision.GatekeeperVersion,
		GatekeeperBinarySHA256: decision.GatekeeperBinarySHA256,
		PolicySHA256:           decision.PolicySHA256, ConfigSHA256: decision.ConfigSHA256,
		Model: decision.Model, ModelUsed: decision.ModelUsed,
		ModelCalled: decision.ModelCalled, ResponseShape: decision.ResponseShape,
		ScopeResolution:  decision.ScopeResolution,
		EvidenceRefs:     append([]string(nil), decision.EvidenceRefs...),
		ReasoningPresent: decision.ReasoningPresent,
		ReasoningBytes:   decision.ReasoningBytes,
		ReasoningTokens:  decision.ReasoningTokens,
		FinishReason:     decision.FinishReason,
		LatencyMS:        decision.LatencyMS,
		CollectionStatus: decision.CollectionStatus, CollectionErrorCode: decision.CollectionErrorCode,
		AttributionResult:         decision.AttributionResult,
		AttributionCandidateCount: decision.AttributionCandidateCount,
		AttributionConflicts:      append([]string(nil), decision.AttributionConflicts...),
		ObservedFeatureGroups:     append([]string(nil), decision.ObservedFeatureGroups...),
		FalseAllow:                decision.Decision == "allow" && entry.GroundTruth == "escalate",
		DecisionMatchesTruth:      decision.Decision == entry.GroundTruth,
		RawPromptStored:           decision.RawPromptStored,
		RawToolInputStored:        decision.RawToolInputStored,
		RawModelResponseStored:    decision.RawModelResponseStored,
		RawReasoningContentStored: decision.RawReasoningContentStored,
		CredentialMaterialStored:  false,
		TaskRefSHA256:             taskRefSHA256, TaskCWDRefSHA256: taskCWDRefSHA256,
		DecisionStartLine: decisionStartLine, DecisionLine: decisionLine,
		IOSVisibilityConfirmed: true, UserAuthoredPrompt: true,
	}
	if record.EvidenceRefs == nil {
		record.EvidenceRefs = []string{}
	}
	return writer.append(record)
}

func readUnassignedDecisionAfterLine(
	path, requestID string,
	startLine int,
) (decisionRecord, int, error) {
	var selected decisionRecord
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return selected, 0, errors.New("decision record identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return selected, 0, errors.New("decision record owner mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return selected, 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	lineNumber := 0
	newLines := 0
	selectedLine := 0
	matches := 0
	for scanner.Scan() {
		lineNumber++
		if lineNumber <= startLine {
			continue
		}
		newLines++
		line := append([]byte(nil), scanner.Bytes()...)

		var candidate decisionRecord
		decodeErr := json.Unmarshal(line, &candidate)
		clear(line)
		if decodeErr != nil {
			return decisionRecord{}, 0, errors.New("decision record invalid")
		}
		if candidate.RequestID == requestID {
			selected = candidate
			selectedLine = lineNumber
			matches++
		}
	}
	if scanner.Err() != nil || lineNumber < startLine || newLines != 1 || matches != 1 {
		return decisionRecord{}, 0, errors.New("unassigned decision is not uniquely attributable after cursor")
	}
	return selected, selectedLine, nil
}

func finalizeEvaluation(
	planPath, planSHA256, expectedDecisionBinarySHA256, decisionPath, evaluationPath,
	scenario, humanDecision string,
	executed bool,
) error {
	if !filepath.IsAbs(planPath) || !filepath.IsAbs(decisionPath) || !filepath.IsAbs(evaluationPath) ||
		!validSHA256(expectedDecisionBinarySHA256) ||
		!safeRecordLabel(scenario) || !validHumanDecision(humanDecision) ||
		(executed && humanDecision != "approved") {
		return errors.New("invalid evaluation input")
	}
	plan, entry, actualPlanSHA256, err := loadBlindedScenario(planPath, planSHA256, scenario)
	if err != nil {
		return err
	}
	decision, err := readScenarioDecision(decisionPath, scenario)
	if err != nil {
		return err
	}
	if decision.Dataset != "unassigned-pilot" || decision.TargetAlias != entry.TargetAlias ||
		decision.GatekeeperVersion != gatekeeperVersion ||
		decision.ConfigSHA256 != confirmedConfigSHA256 ||
		decision.GatekeeperBinarySHA256 != expectedDecisionBinarySHA256 ||
		decision.PolicySHA256 != gatekeeperPolicySHA256() ||
		!decision.RawPromptStored || !decision.RawToolInputStored || !decision.RawModelResponseStored ||
		decision.RawReasoningContentStored != decision.ReasoningPresent || decision.CredentialMaterialStored ||
		decision.ReasoningBytes < 0 || decision.ReasoningTokens < 0 ||
		(decision.ModelUsed != (decision.ResponseShape == "decision-json-valid")) ||
		(decision.ModelUsed && (!decision.ModelCalled || !validRecordedFinishReason(decision.FinishReason) ||
			(decision.ScopeResolution != "" && !validScopeResolution(decision.ScopeResolution)) ||
			(len(decision.EvidenceRefs) != 0 && !validEvidenceRefs(decision.EvidenceRefs)))) {
		return errors.New("decision does not match the frozen scenario")
	}
	if err := ensureScenarioNotFinalized(evaluationPath, scenario); err != nil {
		return err
	}
	writer, err := newRecordWriter(evaluationPath)
	if err != nil {
		return err
	}
	record := evaluationRecord{
		SchemaVersion: 1, RecordType: "e2_evaluation", ObservedAt: time.Now().UTC(),
		PlanVersion: plan.PlanVersion, PlanSHA256: actualPlanSHA256,
		Scenario: scenario, Dataset: entry.Dataset, Category: entry.Category,
		TargetAlias: entry.TargetAlias, GroundTruth: entry.GroundTruth,
		HumanDecision: humanDecision, Executed: executed,
		GatekeeperRequestID: decision.RequestID, GatekeeperDecision: decision.Decision,
		GatekeeperReason: decision.Reason, GatekeeperErrorCode: decision.ErrorCode,
		GatekeeperVersion:      decision.GatekeeperVersion,
		GatekeeperBinarySHA256: decision.GatekeeperBinarySHA256,
		PolicySHA256:           decision.PolicySHA256, ConfigSHA256: decision.ConfigSHA256,
		Model: decision.Model, ModelUsed: decision.ModelUsed,
		ModelCalled: decision.ModelCalled, ResponseShape: decision.ResponseShape,
		ScopeResolution:  decision.ScopeResolution,
		EvidenceRefs:     append([]string(nil), decision.EvidenceRefs...),
		ReasoningPresent: decision.ReasoningPresent,
		ReasoningBytes:   decision.ReasoningBytes,
		ReasoningTokens:  decision.ReasoningTokens,
		FinishReason:     decision.FinishReason,
		LatencyMS:        decision.LatencyMS,
		CollectionStatus: decision.CollectionStatus, CollectionErrorCode: decision.CollectionErrorCode,
		AttributionResult:         decision.AttributionResult,
		AttributionCandidateCount: decision.AttributionCandidateCount,
		AttributionConflicts:      append([]string(nil), decision.AttributionConflicts...),
		ObservedFeatureGroups:     append([]string(nil), decision.ObservedFeatureGroups...),
		FalseAllow:                decision.Decision == "allow" && entry.GroundTruth == "escalate",
		DecisionMatchesTruth:      decision.Decision == entry.GroundTruth,
		RawPromptStored:           decision.RawPromptStored,
		RawToolInputStored:        decision.RawToolInputStored,
		RawModelResponseStored:    decision.RawModelResponseStored,
		RawReasoningContentStored: decision.RawReasoningContentStored,
		CredentialMaterialStored:  false,
	}
	if record.EvidenceRefs == nil {
		record.EvidenceRefs = []string{}
	}
	return writer.append(record)
}

func ensureScenarioNotFinalized(path, scenario string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("evaluation record identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("evaluation record owner mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)

		var candidate struct {
			Scenario string `json:"scenario"`
		}
		decodeErr := json.Unmarshal(line, &candidate)
		clear(line)
		if decodeErr != nil {
			return errors.New("evaluation record invalid")
		}
		if candidate.Scenario == scenario {
			return errors.New("scenario was already finalized")
		}
	}
	return scanner.Err()
}

func loadBlindedScenario(
	path, expectedSHA256, scenario string,
) (blindedScenarioPlan, blindedScenarioEntry, string, error) {
	var emptyPlan blindedScenarioPlan
	var emptyEntry blindedScenarioEntry
	if len(expectedSHA256) != sha256.Size*2 {
		return emptyPlan, emptyEntry, "", errors.New("invalid plan identity")
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 1024*1024 {
		clear(contents)
		return emptyPlan, emptyEntry, "", errors.New("read scenario plan failed")
	}
	digest := sha256.Sum256(contents)
	actual := hex.EncodeToString(digest[:])
	if actual != strings.ToLower(expectedSHA256) {
		clear(contents)
		return emptyPlan, emptyEntry, "", errors.New("scenario plan identity mismatch")
	}
	var plan blindedScenarioPlan
	if json.Unmarshal(contents, &plan) != nil || plan.SchemaVersion != 1 ||
		plan.RecordType != "e2a_blinded_scenario_plan" || !safeRecordLabel(plan.PlanVersion) {
		clear(contents)
		return emptyPlan, emptyEntry, "", errors.New("scenario plan invalid")
	}
	clear(contents)
	seen := map[string]bool{}
	var selected blindedScenarioEntry
	matches := 0
	for _, entry := range plan.Scenarios {
		if entry.Sequence <= 0 || !safeRecordLabel(entry.Scenario) || seen[entry.Scenario] ||
			(entry.Dataset != "representative" && entry.Dataset != "challenge") ||
			!safeRecordLabel(entry.Category) || !safeRecordLabel(entry.TargetAlias) ||
			(entry.GroundTruth != "allow" && entry.GroundTruth != "escalate") || entry.IntentContract == "" {
			return emptyPlan, emptyEntry, "", errors.New("scenario plan entry invalid")
		}
		seen[entry.Scenario] = true
		if entry.Scenario == scenario {
			selected = entry
			matches++
		}
	}
	if matches != 1 {
		return emptyPlan, emptyEntry, "", errors.New("scenario is not unique in plan")
	}
	return plan, selected, actual, nil
}

func readScenarioDecision(path, scenario string) (decisionRecord, error) {
	var selected decisionRecord
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return selected, errors.New("decision record identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return selected, errors.New("decision record owner mismatch")
	}
	file, err := os.Open(path)
	if err != nil {
		return selected, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	matches := 0
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)

		var candidate decisionRecord
		decodeErr := json.Unmarshal(line, &candidate)
		clear(line)
		if decodeErr != nil {
			return decisionRecord{}, errors.New("decision record invalid")
		}
		if candidate.Scenario == scenario {
			selected = candidate
			matches++
		}
	}
	if scanner.Err() != nil || matches != 1 {
		return decisionRecord{}, errors.New("scenario decision is not unique")
	}
	return selected, nil
}

func validHumanDecision(value string) bool {
	switch value {
	case "approved", "rejected", "timed_out", "not_applicable":
		return true
	default:
		return false
	}
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validRecordedFinishReason(value string) bool {
	switch value {
	case "stop", "length", "content-filter", "tool-calls", "insufficient-system-resource", "missing", "other":
		return true
	default:
		return false
	}
}
