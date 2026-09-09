package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var scenarioPattern = regexp.MustCompile(`(?:^|[[:space:]])--scenario(?:=|[[:space:]])([A-Za-z0-9._-]{1,96})(?:$|[[:space:]])`)

type recordWriter struct {
	mu   sync.Mutex
	path string
}

func newRecordWriter(path string) (*recordWriter, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("record path must be absolute")
	}
	parent := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("record parent must be a private directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("record parent owner mismatch")
	}
	if target, err := os.Lstat(filepath.Clean(path)); err == nil {
		targetStat, targetOK := target.Sys().(*syscall.Stat_t)
		if !target.Mode().IsRegular() || target.Mode()&os.ModeSymlink != 0 ||
			target.Mode().Perm() != 0o600 || !targetOK || targetStat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("existing record target identity mismatch")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("inspect record target failed")
	}
	return &recordWriter{path: filepath.Clean(path)}, nil
}

func (writer *recordWriter) append(record any) error {
	if writer == nil {
		return errors.New("record writer unavailable")
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		clear(encoded)
		return errors.New("record encoding failed")
	}
	encoded = append(encoded, '\n')
	writer.mu.Lock()
	defer writer.mu.Unlock()
	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		clear(encoded)
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		clear(encoded)
		return err
	}
	_, writeErr := file.Write(encoded)
	clear(encoded)
	if syncErr := file.Sync(); writeErr == nil {
		writeErr = syncErr
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

func (service *gatekeeperService) writeRecord(
	request localDecisionRequest,
	response localDecisionResponse,
	metrics contextMetrics,
	httpStatus int,
	comparisonResults ...modelCallResult,
) {
	if service.records == nil {
		return
	}
	scenario := extractScenario(request.ToolInput)
	dataset := "unassigned-live-shadow"
	switch {
	case strings.HasPrefix(scenario, "e2a-s-"):
		dataset = "unassigned-pilot"
	case strings.HasPrefix(scenario, "e2b-s-"):
		dataset = "unassigned-evaluation"
	}
	targetAlias := externalizeTarget(request.ActualRequest, service.targetAliases).TargetAlias
	evidence := summarizeRecordEvidence(request.Evidence)
	presence := evidencePresence{state: "unavailable"}
	if service.evidence != nil {
		presence = service.evidence.presence(request.RequestID)
	}
	evidenceID := ""
	if presence.source {
		evidenceID = request.RequestID
	}
	fullSourceStored := presence.source
	if response.ErrorCode != nil && strings.HasPrefix(*response.ErrorCode, "evidence-") {
		fullSourceStored = false
	}
	record := decisionRecord{
		SchemaVersion: 1, RecordType: "e2_shadow_decision", ObservedAt: time.Now().UTC(),
		RequestID: request.RequestID, Dataset: dataset, Scenario: scenario, Mode: "shadow",
		ConfigSHA256: service.configSHA256, Provider: service.config.Provider.Name,
		Model: service.config.Model.PrimaryID, GatekeeperVersion: gatekeeperVersion,
		GatekeeperBinarySHA256: service.binarySHA256, PolicySHA256: service.policySHA256,
		TargetAlias: targetAlias,
		Surface:     request.ActualRequest.Surface, Operation: request.ActualRequest.Operation,
		Decision: response.Decision, Reason: response.Reason, ErrorCode: response.ErrorCode,
		ModelUsed: response.ModelUsed, ModelCalled: response.ModelCalled,
		ModelTransport: response.ModelTransport, TransportDetail: response.TransportDetail,
		ResponseShape:    response.ResponseShape,
		ScopeResolution:  response.ScopeResolution,
		EvidenceRefs:     append([]string(nil), response.EvidenceRefs...),
		ReasoningPresent: response.ReasoningPresent,
		ReasoningBytes:   response.ReasoningBytes,
		ReasoningTokens:  response.ReasoningTokens,
		FinishReason:     response.FinishReason,
		LatencyMS:        response.LatencyMS,
		HTTPStatus:       httpStatus,
		Metrics:          metrics, RawPromptStored: fullSourceStored && len(request.Prompt) > 0,
		RawToolInputStored:        fullSourceStored && len(request.ToolInput) > 0,
		RawModelResponseStored:    presence.response && response.ModelCalled,
		RawReasoningContentStored: presence.response && response.ReasoningPresent,
		ComparisonRequestStored:   presence.comparisonRequest,
		ComparisonResponseStored:  presence.comparisonResponse,
		CredentialMaterialStored:  false,
		EvidenceID:                evidenceID, EvidenceState: presence.state,
		PrimaryVariant:   primaryVariantName,
		CollectionStatus: evidence.CollectionStatus, CollectionErrorCode: evidence.CollectionErrorCode,
		AttributionResult:         evidence.AttributionResult,
		AttributionCandidateCount: evidence.AttributionCandidateCount,
		AttributionConflicts:      append([]string(nil), evidence.AttributionConflicts...),
		ObservedFeatureGroups:     append([]string(nil), evidence.ObservedFeatureGroups...),
	}
	if len(comparisonResults) == 1 {
		comparison := comparisonResults[0]
		record.Comparison = &comparisonDecisionRecord{
			Variant: comparisonVariantName, ThinkingType: comparisonModelVariant.thinkingType,
			Decision: comparison.decision, Reason: comparison.reason,
			ErrorCode: optionalString(comparison.errorCode), ModelUsed: comparison.modelUsed,
			ModelCalled: comparison.modelCalled, ModelTransport: comparison.modelTransport,
			TransportDetail: optionalString(comparison.transportDetail), ResponseShape: comparison.responseShape,
			ScopeResolution:  comparison.scopeResolution,
			EvidenceRefs:     append([]string(nil), comparison.evidenceRefs...),
			ReasoningPresent: comparison.reasoningPresent, ReasoningBytes: comparison.reasoningBytes,
			ReasoningTokens: comparison.reasoningTokens, FinishReason: comparison.finishReason,
			LatencyMS: comparison.latencyMS, HTTPStatus: comparison.httpStatus,
		}
		if record.Comparison.EvidenceRefs == nil {
			record.Comparison.EvidenceRefs = []string{}
		}
	}
	if record.EvidenceRefs == nil {
		record.EvidenceRefs = []string{}
	}
	_ = service.records.append(record)
}

type recordEvidenceSummary struct {
	CollectionStatus          string
	CollectionErrorCode       *string
	AttributionResult         string
	AttributionCandidateCount int
	AttributionConflicts      []string
	ObservedFeatureGroups     []string
}

func summarizeRecordEvidence(raw json.RawMessage) recordEvidenceSummary {
	var envelope struct {
		Collection struct {
			Status    string  `json:"status"`
			ErrorCode *string `json:"error_code"`
		} `json:"collection"`
		Attribution struct {
			Result                string   `json:"result"`
			SessionCandidateCount int      `json:"session_candidate_count"`
			Conflicts             []string `json:"conflicts"`
		} `json:"attribution"`
		Features []struct {
			Name     string `json:"name"`
			Observed bool   `json:"observed"`
		} `json:"features"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return recordEvidenceSummary{
			CollectionStatus: "unavailable", AttributionResult: "unavailable",
			AttributionConflicts: []string{"evidence-summary-invalid"}, ObservedFeatureGroups: []string{},
		}
	}
	summary := recordEvidenceSummary{
		CollectionStatus: envelope.Collection.Status, CollectionErrorCode: envelope.Collection.ErrorCode,
		AttributionResult:         envelope.Attribution.Result,
		AttributionCandidateCount: envelope.Attribution.SessionCandidateCount,
		AttributionConflicts:      append([]string(nil), envelope.Attribution.Conflicts...),
		ObservedFeatureGroups:     []string{},
	}
	for _, feature := range envelope.Features {
		if feature.Observed && safeRecordLabel(feature.Name) {
			summary.ObservedFeatureGroups = append(summary.ObservedFeatureGroups, feature.Name)
		}
	}
	if summary.AttributionConflicts == nil {
		summary.AttributionConflicts = []string{}
	}
	return summary
}

func safeRecordLabel(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func extractScenario(toolInput json.RawMessage) string {
	var input struct {
		Command string `json:"command"`
	}
	if json.Unmarshal(toolInput, &input) != nil {
		return "unlabeled-live"
	}
	match := scenarioPattern.FindStringSubmatch(input.Command + " ")
	if len(match) != 2 {
		return "unlabeled-live"
	}
	return match[1]
}
