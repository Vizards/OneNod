package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/providercontract"
)

const missingHumanOutcomeGrace = 10 * time.Minute

type indexRecord struct {
	SchemaVersion       int       `json:"schema_version"`
	RecordType          string    `json:"record_type"`
	ObservedAt          time.Time `json:"observed_at"`
	EvidenceID          string    `json:"evidence_id"`
	Phase               string    `json:"phase"`
	Variant             string    `json:"variant,omitempty"`
	Surface             string    `json:"surface,omitempty"`
	Operation           string    `json:"operation,omitempty"`
	TargetAlias         string    `json:"target_alias,omitempty"`
	Decision            string    `json:"decision,omitempty"`
	Reason              string    `json:"reason,omitempty"`
	ErrorCode           *string   `json:"error_code,omitempty"`
	ModelCalled         *bool     `json:"model_called,omitempty"`
	ModelUsed           *bool     `json:"model_used,omitempty"`
	ResponseShape       string    `json:"response_shape,omitempty"`
	HTTPStatus          *int      `json:"http_status,omitempty"`
	LatencyMS           *int64    `json:"latency_ms,omitempty"`
	AuthorizationSource string    `json:"authorization_source,omitempty"`
	HumanDecision       string    `json:"human_decision,omitempty"`
	BundlePath          string    `json:"bundle_path"`
	State               string    `json:"state"`
	ManifestSHA256      string    `json:"manifest_sha256"`
}

type sourceAuditRecord struct {
	SchemaVersion         int             `json:"schema_version"`
	RecordType            string          `json:"record_type"`
	EvidenceID            string          `json:"evidence_id"`
	CapturedAt            time.Time       `json:"captured_at"`
	OperationTargetSHA256 string          `json:"operation_target_sha256"`
	SelectedModelInput    json.RawMessage `json:"selected_model_input"`
	RequesterContext      json.RawMessage `json:"onenod_requester_context"`
	CollectorError        *string         `json:"collector_error"`
	TranscriptSnapshot    struct {
		TaskID               string `json:"codex_task_id"`
		CaptureBoundary      string `json:"capture_boundary"`
		FileBytesAtOpen      int64  `json:"file_bytes_at_open"`
		ScannedBytes         int64  `json:"scanned_bytes"`
		ScannedEvents        int    `json:"scanned_events"`
		ScannedContentSHA256 string `json:"scanned_content_sha256"`
		ObservedCandidates   int    `json:"observed_candidates"`
		RetainedCandidates   int    `json:"retained_candidates"`
	} `json:"transcript_snapshot"`
	SelectionMetrics struct {
		CompletedTools int `json:"completed_tools"`
	} `json:"selection_metrics"`
	LocalRequest struct {
		RequestID      string `json:"request_id"`
		Mode           string `json:"mode"`
		Prompt         string `json:"prompt"`
		ToolInput      string `json:"tool_input"`
		Evidence       string `json:"evidence"`
		TranscriptPath string `json:"transcript_path"`
		ActualRequest  struct {
			Surface       string `json:"surface"`
			Operation     string `json:"operation"`
			PayloadDigest string `json:"payload_digest"`
		} `json:"actual_request"`
	} `json:"core_local_decision_request"`
}

type modelRequestAuditRecord struct {
	SchemaVersion int             `json:"schema_version"`
	RecordType    string          `json:"record_type"`
	EvidenceID    string          `json:"evidence_id"`
	Variant       string          `json:"variant"`
	Endpoint      string          `json:"endpoint"`
	RequestSent   bool            `json:"request_sent"`
	BodyBytes     int             `json:"body_bytes"`
	BodySHA256    string          `json:"body_sha256"`
	RawBodyBase64 string          `json:"raw_body_base64"`
	Body          json.RawMessage `json:"body"`
	BuildError    *string         `json:"build_error"`
}

type modelResponseAuditRecord struct {
	SchemaVersion    int             `json:"schema_version"`
	RecordType       string          `json:"record_type"`
	EvidenceID       string          `json:"evidence_id"`
	Variant          string          `json:"variant"`
	HTTPStatus       int             `json:"http_status"`
	BodyBytes        int             `json:"body_bytes"`
	BodySHA256       string          `json:"body_sha256"`
	RawBodyBase64    string          `json:"raw_body_base64"`
	Body             json.RawMessage `json:"body"`
	TransportError   *string         `json:"transport_error"`
	TransportDetail  *string         `json:"transport_error_detail"`
	ParserError      *string         `json:"parser_error"`
	Decision         string          `json:"decision"`
	Reason           string          `json:"reason"`
	ScopeResolution  string          `json:"scope_resolution"`
	EvidenceRefs     []string        `json:"evidence_refs"`
	ResponseShape    string          `json:"response_shape"`
	ModelUsed        bool            `json:"model_used"`
	ModelCalled      bool            `json:"model_called"`
	ModelTransport   string          `json:"model_transport"`
	ReasoningPresent bool            `json:"reasoning_present"`
	ReasoningBytes   int             `json:"reasoning_bytes"`
	ReasoningTokens  int             `json:"reasoning_tokens"`
	FinishReason     string          `json:"finish_reason"`
	LatencyMS        int64           `json:"latency_ms"`
}

type humanOutcomeAuditRecord struct {
	SchemaVersion         int       `json:"schema_version"`
	RecordType            string    `json:"record_type"`
	EvidenceID            string    `json:"evidence_id"`
	OperationTargetSHA256 string    `json:"operation_target_sha256"`
	AuthorizationSource   string    `json:"authorization_source"`
	Decision              string    `json:"decision"`
	OperationCompleted    bool      `json:"operation_completed"`
	CredentialDelivered   bool      `json:"credential_delivered"`
	ObservedAt            time.Time `json:"observed_at"`
}

type redactionAuditRecord struct {
	SchemaVersion int    `json:"schema_version"`
	RecordType    string `json:"record_type"`
	EvidenceID    string `json:"evidence_id"`
	Events        []struct {
		Source           string `json:"source"`
		JSONPath         string `json:"json_path"`
		Rule             string `json:"rule"`
		OriginalBytes    int    `json:"original_bytes"`
		ReplacementBytes int    `json:"replacement_bytes"`
	} `json:"events"`
}

type bundleFacts struct {
	Surface                   string `json:"surface,omitempty"`
	Operation                 string `json:"operation,omitempty"`
	PayloadDigest             string `json:"payload_digest,omitempty"`
	OperationTargetSHA256     string `json:"operation_target_sha256,omitempty"`
	ModelRequestSHA256        string `json:"model_request_sha256,omitempty"`
	ModelDecision             string `json:"model_decision,omitempty"`
	ModelReason               string `json:"model_reason,omitempty"`
	ComparisonRequestSHA256   string `json:"comparison_request_sha256,omitempty"`
	ComparisonDecision        string `json:"comparison_decision,omitempty"`
	ComparisonReason          string `json:"comparison_reason,omitempty"`
	PrimaryLatencyMS          int64  `json:"primary_latency_ms,omitempty"`
	ComparisonLatencyMS       int64  `json:"comparison_latency_ms,omitempty"`
	HumanDecision             string `json:"human_decision,omitempty"`
	AuthorizationSource       string `json:"authorization_source,omitempty"`
	RequesterExecutableProven bool   `json:"requester_executable_proven"`
	CompletedTools            int    `json:"completed_tools"`
	CodexTaskID               string `json:"codex_task_id,omitempty"`
}

type bundleInspection struct {
	SchemaVersion     int             `json:"schema_version"`
	EvidenceID        string          `json:"evidence_id"`
	GatekeeperVersion string          `json:"gatekeeper_version,omitempty"`
	State             string          `json:"state"`
	Valid             bool            `json:"valid"`
	FileChecks        map[string]bool `json:"file_checks"`
	Errors            []string        `json:"errors"`
	Warnings          []string        `json:"warnings"`
	Facts             bundleFacts     `json:"facts"`
}

type auditSummary struct {
	SchemaVersion      int                `json:"schema_version"`
	RecordType         string             `json:"record_type"`
	ObservedAt         time.Time          `json:"observed_at"`
	EvidenceRoot       string             `json:"evidence_root"`
	DecisionRecordRoot string             `json:"decision_record_root,omitempty"`
	Valid              bool               `json:"valid"`
	Totals             map[string]int     `json:"totals"`
	Bundles            []bundleInspection `json:"bundles"`
	Findings           []string           `json:"cross_bundle_findings"`
	Observations       []string           `json:"cross_bundle_observations,omitempty"`
}

type decisionRecordAudit struct {
	SchemaVersion     int       `json:"schema_version"`
	RecordType        string    `json:"record_type"`
	ObservedAt        time.Time `json:"observed_at"`
	RequestID         string    `json:"request_id"`
	GatekeeperVersion string    `json:"gatekeeper_version"`
	Decision          string    `json:"decision"`
	ModelCalled       bool      `json:"model_called"`
	ModelUsed         bool      `json:"model_used"`
	EvidenceID        string    `json:"evidence_id"`
	EvidenceState     string    `json:"evidence_state"`
}

func inspectBundle(root, evidenceID string, allIndex []indexRecord) bundleInspection {
	result := bundleInspection{
		SchemaVersion: 1, EvidenceID: evidenceID, FileChecks: map[string]bool{},
		Errors: []string{}, Warnings: []string{},
	}
	bundle, manifestValue, err := loadManifest(root, evidenceID)
	if err != nil {
		result.Errors = append(result.Errors, "manifest-invalid")
		return result
	}
	result.State = manifestValue.State
	result.GatekeeperVersion = manifestValue.GatekeeperVersion
	redactedStages := declaredRedactionStages(bundle, evidenceID, manifestValue)
	strictTargetBinding := strictAuditableVersion(manifestValue.GatekeeperVersion)
	if strictTargetBinding && manifestValue.CreatedAt.IsZero() {
		result.Errors = append(result.Errors, "manifest-created-at-missing")
	}
	for name, expected := range manifestValue.Files {
		if expected == nil {
			continue
		}
		actual, digestErr := digestPrivateFile(filepath.Join(bundle, name))
		matched := digestErr == nil && actual == *expected
		result.FileChecks[name] = matched
		if !matched {
			result.Errors = append(result.Errors, "file-digest-mismatch:"+name)
		}
	}
	entries, readErr := os.ReadDir(bundle)
	if readErr != nil {
		result.Errors = append(result.Errors, "bundle-unreadable")
	} else {
		allowed := map[string]bool{"manifest.json": true}
		for name, digest := range manifestValue.Files {
			if digest != nil {
				allowed[name] = true
			}
		}
		for _, entry := range entries {
			if entry.IsDir() || !allowed[entry.Name()] {
				result.Errors = append(result.Errors, "unexpected-entry:"+entry.Name())
			}
		}
	}

	var source sourceAuditRecord
	if manifestValue.Files["01-source-context.json"] != nil {
		if !decodeBundleRecord(bundle, "01-source-context.json", &source) ||
			source.SchemaVersion != 1 || source.RecordType != "beholder_source_context" ||
			source.EvidenceID != evidenceID || source.LocalRequest.RequestID != evidenceID || source.CapturedAt.IsZero() {
			result.Errors = append(result.Errors, "source-identity-mismatch")
		} else {
			result.Facts.Surface = source.LocalRequest.ActualRequest.Surface
			result.Facts.Operation = source.LocalRequest.ActualRequest.Operation
			result.Facts.PayloadDigest = source.LocalRequest.ActualRequest.PayloadDigest
			result.Facts.OperationTargetSHA256 = source.OperationTargetSHA256
			result.Facts.CompletedTools = source.SelectionMetrics.CompletedTools
			result.Facts.CodexTaskID = source.TranscriptSnapshot.TaskID
			if manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v11" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v12" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v13" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v14" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v15" ||
				dualShadowVersion(manifestValue.GatekeeperVersion) {
				fallbackSource := source.CollectorError != nil && strings.HasPrefix(*source.CollectorError, "evidence-")
				if (source.LocalRequest.Mode == "shadow" || source.LocalRequest.Mode == "shadow-submit" ||
					source.LocalRequest.Mode == "authoritative") &&
					(source.TranscriptSnapshot.TaskID == "" ||
						!strings.HasSuffix(source.LocalRequest.TranscriptPath, source.TranscriptSnapshot.TaskID+".jsonl")) {
					result.Errors = append(result.Errors, "codex-task-reference-missing")
				}
				if !fallbackSource && (source.TranscriptSnapshot.FileBytesAtOpen <= 0 ||
					source.TranscriptSnapshot.ScannedBytes <= 0 || source.TranscriptSnapshot.ScannedEvents <= 0 ||
					!validSHA256(source.TranscriptSnapshot.ScannedContentSHA256) ||
					source.TranscriptSnapshot.ObservedCandidates < source.TranscriptSnapshot.RetainedCandidates ||
					source.TranscriptSnapshot.RetainedCandidates < 0 ||
					(manifestValue.GatekeeperVersion != "e2-authoritative-dogfood-v30" &&
						manifestValue.GatekeeperVersion != "e2-authoritative-dogfood-v31" &&
						manifestValue.GatekeeperVersion != "e2-authoritative-dogfood-v32" &&
						source.TranscriptSnapshot.RetainedCandidates > 256)) {
					result.Errors = append(result.Errors, "transcript-snapshot-invalid")
				}
				if (manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v12" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v13" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v14" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v15" ||
					dualShadowVersion(manifestValue.GatekeeperVersion)) && !fallbackSource &&
					(source.TranscriptSnapshot.CaptureBoundary != "file-size-at-open" ||
						source.TranscriptSnapshot.ScannedBytes != source.TranscriptSnapshot.FileBytesAtOpen) {
					result.Errors = append(result.Errors, "transcript-causal-boundary-invalid")
				}
				if (manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v12" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v13" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v14" ||
					manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v15" ||
					dualShadowVersion(manifestValue.GatekeeperVersion)) &&
					!modelContextProvenanceValid(source.SelectedModelInput) {
					result.Errors = append(result.Errors, "context-provenance-invalid")
				}
			}
			if !validSHA256(source.LocalRequest.ActualRequest.PayloadDigest) {
				if strictTargetBinding {
					result.Errors = append(result.Errors, "payload-digest-missing")
				} else {
					result.Warnings = append(result.Warnings, "legacy-payload-digest-missing")
				}
			}
			if source.OperationTargetSHA256 == "" {
				if strictTargetBinding {
					result.Errors = append(result.Errors, "operation-target-binding-missing")
				} else {
					result.Warnings = append(result.Warnings, "legacy-operation-target-binding-missing")
				}
			} else if !validSHA256(source.OperationTargetSHA256) {
				result.Errors = append(result.Errors, "operation-target-digest-invalid")
			}
			result.Facts.RequesterExecutableProven = requesterExecutableProven(source.RequesterContext)
			if !result.Facts.RequesterExecutableProven {
				if strictTargetBinding && (result.Facts.Surface == "direct-may" || result.Facts.Surface == "ssh-agent") {
					result.Errors = append(result.Errors, "requester-executable-unproven")
				} else {
					result.Warnings = append(result.Warnings, "requester-executable-unproven")
				}
			}
		}
	}

	var modelRequest modelRequestAuditRecord
	if manifestValue.Files["02-model-request.json"] != nil {
		if !decodeBundleRecord(bundle, "02-model-request.json", &modelRequest) ||
			modelRequest.SchemaVersion != 1 || modelRequest.RecordType != "beholder_model_request" ||
			modelRequest.EvidenceID != evidenceID ||
			(dualShadowVersion(manifestValue.GatekeeperVersion) &&
				modelRequest.Variant != primaryVariantForVersion(manifestValue.GatekeeperVersion)) {
			result.Errors = append(result.Errors, "model-request-identity-mismatch")
		} else {
			result.Facts.ModelRequestSHA256 = modelRequest.BodySHA256
			if err := verifyRawBody(modelRequest.RawBodyBase64, modelRequest.BodyBytes,
				modelRequest.BodySHA256, modelRequest.Body, redactedStages["02-model-request.json"]); err != nil {
				result.Errors = append(result.Errors, "model-request-"+err.Error())
			}
			if modelRequest.RequestSent && !modelInputMatches(source.SelectedModelInput, modelRequest.Body, manifestValue.GatekeeperVersion) {
				result.Errors = append(result.Errors, "selected-model-input-mismatch")
			}
			if modelRequest.RequestSent && !policyHashMatches(manifestValue, modelRequest.Body) {
				result.Errors = append(result.Errors, "system-policy-hash-mismatch")
			}
		}
	}

	var modelResponse modelResponseAuditRecord
	if manifestValue.Files["03-model-response.json"] != nil {
		if !decodeBundleRecord(bundle, "03-model-response.json", &modelResponse) ||
			modelResponse.SchemaVersion != 1 || modelResponse.RecordType != "beholder_model_response" ||
			modelResponse.EvidenceID != evidenceID ||
			(dualShadowVersion(manifestValue.GatekeeperVersion) &&
				modelResponse.Variant != primaryVariantForVersion(manifestValue.GatekeeperVersion)) {
			result.Errors = append(result.Errors, "model-response-identity-mismatch")
		} else {
			result.Facts.ModelDecision = modelResponse.Decision
			result.Facts.ModelReason = modelResponse.Reason
			if err := verifyRawBody(modelResponse.RawBodyBase64, modelResponse.BodyBytes,
				modelResponse.BodySHA256, modelResponse.Body, redactedStages["03-model-response.json"]); err != nil {
				result.Errors = append(result.Errors, "model-response-"+err.Error())
			}
			if modelResponse.ModelUsed && !providerDecisionMatches(modelResponse, manifestValue.GatekeeperVersion,
				redactedStages["03-model-response.json"]) {
				result.Errors = append(result.Errors, "provider-decision-summary-mismatch")
			}
			if modelResponse.TransportError != nil || modelResponse.ParserError != nil {
				result.Warnings = append(result.Warnings, "model-call-failed-closed")
			}
			if (manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v13" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v14" ||
				manifestValue.GatekeeperVersion == "e2-auditable-dogfood-v15" ||
				dualShadowVersion(manifestValue.GatekeeperVersion)) && modelResponse.ModelCalled {
				expectedTransport := "go-http"
				if providercontract.UsesSystemCurl(modelRequest.Endpoint) {
					expectedTransport = "system-curl"
				}
				if modelResponse.ModelTransport != expectedTransport {
					result.Errors = append(result.Errors, "model-transport-identity-mismatch")
				}
				if modelResponse.TransportError == nil && modelResponse.TransportDetail != nil {
					result.Errors = append(result.Errors, "unexpected-transport-error-detail")
				}
			}
		}
	}

	var comparisonRequest modelRequestAuditRecord
	var comparisonResponse modelResponseAuditRecord
	if dualShadowVersion(manifestValue.GatekeeperVersion) {
		comparisonRequestName, comparisonResponseName := comparisonStageNames(
			manifestValue.GatekeeperVersion,
		)
		comparisonVariant := comparisonVariantForVersion(manifestValue.GatekeeperVersion)
		if manifestValue.Files[comparisonRequestName] == nil {
			result.Errors = append(result.Errors, "comparison-model-request-missing")
		} else if !decodeBundleRecord(bundle, comparisonRequestName, &comparisonRequest) ||
			comparisonRequest.SchemaVersion != 1 || comparisonRequest.RecordType != "beholder_model_request" ||
			comparisonRequest.EvidenceID != evidenceID || comparisonRequest.Variant != comparisonVariant {
			result.Errors = append(result.Errors, "comparison-model-request-identity-mismatch")
		} else {
			result.Facts.ComparisonRequestSHA256 = comparisonRequest.BodySHA256
			if err := verifyRawBody(comparisonRequest.RawBodyBase64, comparisonRequest.BodyBytes,
				comparisonRequest.BodySHA256, comparisonRequest.Body, redactedStages[comparisonRequestName]); err != nil {
				result.Errors = append(result.Errors, "comparison-model-request-"+err.Error())
			}
			if comparisonRequest.RequestSent && !modelInputMatches(source.SelectedModelInput, comparisonRequest.Body, manifestValue.GatekeeperVersion) {
				result.Errors = append(result.Errors, "comparison-selected-model-input-mismatch")
			}
			if comparisonRequest.RequestSent && !policyHashMatches(manifestValue, comparisonRequest.Body) {
				result.Errors = append(result.Errors, "comparison-system-policy-hash-mismatch")
			}
			if modelRequest.RequestSent && comparisonRequest.RequestSent &&
				!pairedRequestBodiesMatch(modelRequest.Body, comparisonRequest.Body) {
				result.Errors = append(result.Errors, "paired-model-request-mismatch")
			}
		}

		if manifestValue.Files[comparisonResponseName] == nil {
			result.Errors = append(result.Errors, "comparison-model-response-missing")
		} else if !decodeBundleRecord(bundle, comparisonResponseName, &comparisonResponse) ||
			comparisonResponse.SchemaVersion != 1 || comparisonResponse.RecordType != "beholder_model_response" ||
			comparisonResponse.EvidenceID != evidenceID || comparisonResponse.Variant != comparisonVariant {
			result.Errors = append(result.Errors, "comparison-model-response-identity-mismatch")
		} else {
			result.Facts.ComparisonDecision = comparisonResponse.Decision
			result.Facts.ComparisonReason = comparisonResponse.Reason
			result.Facts.PrimaryLatencyMS = modelResponse.LatencyMS
			result.Facts.ComparisonLatencyMS = comparisonResponse.LatencyMS
			if err := verifyRawBody(comparisonResponse.RawBodyBase64, comparisonResponse.BodyBytes,
				comparisonResponse.BodySHA256, comparisonResponse.Body, redactedStages[comparisonResponseName]); err != nil {
				result.Errors = append(result.Errors, "comparison-model-response-"+err.Error())
			}
			if comparisonResponse.ModelUsed && !providerDecisionMatches(comparisonResponse, manifestValue.GatekeeperVersion,
				redactedStages[comparisonResponseName]) {
				result.Errors = append(result.Errors, "comparison-provider-decision-summary-mismatch")
			}
			if comparisonResponse.TransportError != nil || comparisonResponse.ParserError != nil {
				result.Warnings = append(result.Warnings, "comparison-model-call-failed-closed")
			}
			if comparisonResponse.ModelCalled {
				expectedTransport := "go-http"
				if providercontract.UsesSystemCurl(comparisonRequest.Endpoint) {
					expectedTransport = "system-curl"
				}
				if comparisonResponse.ModelTransport != expectedTransport {
					result.Errors = append(result.Errors, "comparison-model-transport-identity-mismatch")
				}
				if comparisonResponse.TransportError == nil && comparisonResponse.TransportDetail != nil {
					result.Errors = append(result.Errors, "comparison-unexpected-transport-error-detail")
				}
			}
		}
	}

	var outcome humanOutcomeAuditRecord
	if manifestValue.Files["04-human-outcome.json"] != nil {
		if !decodeBundleRecord(bundle, "04-human-outcome.json", &outcome) ||
			outcome.SchemaVersion != 1 || outcome.RecordType != "beholder_human_outcome" ||
			outcome.EvidenceID != evidenceID {
			result.Errors = append(result.Errors, "human-outcome-identity-mismatch")
		} else {
			result.Facts.HumanDecision = outcome.Decision
			result.Facts.AuthorizationSource = outcome.AuthorizationSource
			if !validSHA256(outcome.OperationTargetSHA256) {
				if strictTargetBinding {
					result.Errors = append(result.Errors, "human-outcome-target-binding-missing")
				} else {
					result.Warnings = append(result.Warnings, "legacy-human-target-binding-missing")
				}
			} else if source.OperationTargetSHA256 == "" {
				result.Warnings = append(result.Warnings, "human-target-binding-not-comparable")
			} else if source.OperationTargetSHA256 != outcome.OperationTargetSHA256 {
				result.Errors = append(result.Errors, "human-outcome-target-mismatch")
			}
			if outcome.CredentialDelivered && !outcome.OperationCompleted {
				result.Errors = append(result.Errors, "credential-delivery-without-completion")
			}
			if modelResponse.ModelUsed && outcome.Decision != "not_requested" && outcome.Decision != "unknown" &&
				((modelResponse.Decision == "allow" && outcome.Decision != "approved") ||
					(modelResponse.Decision == "escalate" && outcome.Decision == "approved")) {
				result.Warnings = append(result.Warnings, "model-human-decision-disagreement")
			}
		}
	} else if manifestValue.Files["03-model-response.json"] != nil &&
		!source.CapturedAt.IsZero() && time.Since(source.CapturedAt) > missingHumanOutcomeGrace {
		if strictTargetBinding {
			result.Errors = append(result.Errors, "human-outcome-overdue")
		} else {
			result.Warnings = append(result.Warnings, "human-outcome-overdue")
		}
	}
	var redactions redactionAuditRecord
	if manifestValue.Files["redactions.json"] != nil {
		if !decodeBundleRecord(bundle, "redactions.json", &redactions) || redactions.SchemaVersion != 1 ||
			redactions.RecordType != "beholder_evidence_redactions" || redactions.EvidenceID != evidenceID {
			result.Errors = append(result.Errors, "redaction-log-identity-mismatch")
		} else {
			for _, event := range redactions.Events {
				if !knownEvidenceStage(event.Source) || event.JSONPath == "" || event.Rule == "" ||
					event.OriginalBytes < 0 || event.ReplacementBytes < 0 {
					result.Errors = append(result.Errors, "redaction-event-invalid")
				}
			}
		}
	}
	if manifestValue.Files["03-model-response.json"] == nil && !source.CapturedAt.IsZero() &&
		time.Since(source.CapturedAt) > 12*time.Minute {
		if strictTargetBinding {
			result.Errors = append(result.Errors, "model-response-overdue")
		} else {
			result.Warnings = append(result.Warnings, "legacy-model-response-overdue")
		}
	}

	inspectIndex(bundle, manifestValue, modelResponse, comparisonResponse, outcome, allIndex, &result)
	result.Errors = uniqueSorted(result.Errors)
	result.Warnings = uniqueSorted(result.Warnings)
	result.Valid = len(result.Errors) == 0
	return result
}

func knownEvidenceStage(name string) bool {
	for _, candidate := range []string{
		"01-source-context.json", "02-model-request.json", "03-model-response.json", "04-human-outcome.json",
		"05-model-request-thinking-disabled.json", "06-model-response-thinking-disabled.json",
		"05-model-request-thinking-enabled.json", "06-model-response-thinking-enabled.json",
	} {
		if name == candidate {
			return true
		}
	}
	return false
}

func decodeBundleRecord(bundle, name string, target any) bool {
	contents, err := readPrivateFile(filepath.Join(bundle, name), 64*1024*1024)
	if err != nil {
		return false
	}
	defer clear(contents)
	return json.Unmarshal(contents, target) == nil
}

func verifyRawBody(encoded string, expectedBytes int, expectedSHA string, parsed json.RawMessage, parsedBodyRedacted bool) error {
	if encoded == "" {
		if expectedBytes != 0 || expectedSHA != "" || len(parsed) != 0 {
			return errors.New("raw-body-fields-inconsistent")
		}
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return errors.New("raw-body-base64-invalid")
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	if len(raw) != expectedBytes || hex.EncodeToString(digest[:]) != expectedSHA {
		return errors.New("raw-body-digest-mismatch")
	}
	if json.Valid(raw) {
		if len(parsed) == 0 || (!parsedBodyRedacted && !jsonSemanticallyEqual(raw, parsed)) {
			return errors.New("parsed-body-mismatch")
		}
	} else if len(parsed) != 0 && string(bytes.TrimSpace(parsed)) != "null" {
		return errors.New("invalid-raw-body-has-parsed-body")
	}
	return nil
}

func declaredRedactionStages(bundle, evidenceID string, manifestValue manifest) map[string]bool {
	result := map[string]bool{}
	if manifestValue.Files["redactions.json"] == nil {
		return result
	}
	var redactions redactionAuditRecord
	if !decodeBundleRecord(bundle, "redactions.json", &redactions) || redactions.SchemaVersion != 1 ||
		redactions.RecordType != "beholder_evidence_redactions" || redactions.EvidenceID != evidenceID {
		return result
	}
	for _, event := range redactions.Events {
		if knownEvidenceStage(event.Source) && event.JSONPath != "" && event.Rule != "" &&
			event.OriginalBytes >= 0 && event.ReplacementBytes >= 0 {
			result[event.Source] = true
		}
	}
	return result
}

func jsonSemanticallyEqual(left, right []byte) bool {
	var leftValue, rightValue any
	if json.Unmarshal(left, &leftValue) != nil || json.Unmarshal(right, &rightValue) != nil {
		return false
	}
	leftJSON, leftErr := json.Marshal(leftValue)
	rightJSON, rightErr := json.Marshal(rightValue)
	defer clear(leftJSON)
	defer clear(rightJSON)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func modelInputMatches(selected, requestBody json.RawMessage, versions ...string) bool {
	if len(versions) == 1 && (versions[0] == "e2-authoritative-dogfood-v31" || versions[0] == "e2-authoritative-dogfood-v32") {
		projected, err := modelcontract.DirectModelInput(selected)
		if err != nil {
			return false
		}
		defer clear(projected)
		selected = projected
		var fields map[string]json.RawMessage
		if json.Unmarshal(requestBody, &fields) != nil {
			return false
		}
		if _, present := fields["tools"]; present {
			return false
		}
		if _, present := fields["tool_choice"]; present {
			return false
		}
	}
	if len(selected) == 0 || len(requestBody) == 0 {
		return false
	}
	var request struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(requestBody, &request) != nil || len(request.Messages) != 2 ||
		request.Messages[1].Role != "user" {
		return false
	}
	return jsonSemanticallyEqual(selected, []byte(request.Messages[1].Content))
}

func pairedRequestBodiesMatch(primaryBody, comparisonBody json.RawMessage) bool {
	var primary, comparison map[string]any
	if json.Unmarshal(primaryBody, &primary) != nil || json.Unmarshal(comparisonBody, &comparison) != nil {
		return false
	}
	primaryThinking, primaryOK := primary["thinking"].(map[string]any)
	comparisonThinking, comparisonOK := comparison["thinking"].(map[string]any)
	if !primaryOK || !comparisonOK ||
		!oneOfString(primaryThinking["type"], "enabled", "disabled") ||
		!oneOfString(comparisonThinking["type"], "enabled", "disabled") ||
		primaryThinking["type"] == comparisonThinking["type"] {
		return false
	}
	comparisonThinking["type"] = primaryThinking["type"]
	primaryJSON, primaryErr := json.Marshal(primary)
	comparisonJSON, comparisonErr := json.Marshal(comparison)
	defer clear(primaryJSON)
	defer clear(comparisonJSON)
	return primaryErr == nil && comparisonErr == nil && bytes.Equal(primaryJSON, comparisonJSON)
}

func oneOfString(value any, allowed ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if text == candidate {
			return true
		}
	}
	return false
}

func policyHashMatches(value manifest, requestBody json.RawMessage) bool {
	var request struct {
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	if json.Unmarshal(requestBody, &request) != nil || len(request.Messages) != 2 || request.Messages[0].Role != "system" {
		return false
	}
	digest := sha256.Sum256([]byte(request.Messages[0].Content))
	return hex.EncodeToString(digest[:]) == value.PolicySHA256
}

func providerDecisionMatches(response modelResponseAuditRecord, gatekeeperVersion string, responseRedacted bool) bool {
	var provider struct {
		Choices []struct {
			FinishReason string `json:"finish_reason"`
			Message      struct {
				Content          string `json:"content"`
				ReasoningContent string `json:"reasoning_content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			CompletionTokensDetails struct {
				ReasoningTokens int `json:"reasoning_tokens"`
			} `json:"completion_tokens_details"`
		} `json:"usage"`
	}
	if json.Unmarshal(response.Body, &provider) != nil || len(provider.Choices) != 1 {
		return false
	}
	var decision struct {
		Decision        string          `json:"decision"`
		Reason          string          `json:"reason"`
		ScopeResolution json.RawMessage `json:"scope_resolution"`
		EvidenceRefs    json.RawMessage `json:"evidence_refs"`
	}
	choice := provider.Choices[0]
	if json.Unmarshal([]byte(choice.Message.Content), &decision) != nil {
		return false
	}
	// Gatekeeper treats both diagnostics as optional. A syntactically valid
	// final decision remains usable when either diagnostic is outside its
	// allowlist; the parser deliberately drops that field from the summary.
	// Mirror that exact normalization so historical raw provider evidence is
	// compared with what the decision component actually accepted.
	scopeResolution := ""
	var candidateScopeResolution string
	if json.Unmarshal(decision.ScopeResolution, &candidateScopeResolution) == nil &&
		validProviderScopeResolution(candidateScopeResolution, gatekeeperVersion) {
		scopeResolution = candidateScopeResolution
	}
	var evidenceRefs []string
	if json.Unmarshal(decision.EvidenceRefs, &evidenceRefs) != nil ||
		!validProviderEvidenceRefs(evidenceRefs, gatekeeperVersion) {
		evidenceRefs = nil
	}
	if decision.Decision != response.Decision || decision.Reason != response.Reason ||
		scopeResolution != response.ScopeResolution ||
		!equalStrings(evidenceRefs, response.EvidenceRefs) ||
		(strings.TrimSpace(choice.Message.ReasoningContent) != "") != response.ReasoningPresent ||
		provider.Usage.CompletionTokensDetails.ReasoningTokens != response.ReasoningTokens {
		return false
	}
	// A declared evidence redaction can change the byte length of free-form
	// reasoning while leaving the parsed decision and its diagnostics intact.
	// The manifest and raw-body verifier already authenticate that redacted
	// representation. Keep all semantic comparisons, but only demand the
	// original reasoning byte count when the response stage was not redacted.
	if !responseRedacted && len(choice.Message.ReasoningContent) != response.ReasoningBytes {
		return false
	}
	return true
}

func validProviderScopeResolution(value, gatekeeperVersion string) bool {
	if value == "" {
		return false
	}
	allowedValues := []string{
		"task-consistent",
		"relationship-unclear",
		"active-human-constraint-conflict",
		"context-injection-concern",
		"significant-goal-drift",
		"authority-or-effect-mismatch",
		"integrity-or-attribution-failure",
	}
	if legacyR4EvidenceContract(gatekeeperVersion) {
		allowedValues = []string{
			"current-prompt-authorizes",
			"current-prompt-does-not-authorize",
			"persistent-prior-conflict",
			"expired-prior-ignored",
			"scope-ambiguous",
			"not-applicable",
		}
	}
	for _, allowed := range allowedValues {
		if value == allowed {
			return true
		}
	}
	return false
}

func validProviderEvidenceRefs(values []string, gatekeeperVersion string) bool {
	maximum := 8
	if threeDomainEvidenceContract(gatekeeperVersion) {
		maximum = 3
	}
	if len(values) < 1 || len(values) > maximum {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if seen[value] || !validProviderEvidenceRef(value, gatekeeperVersion) {
			return false
		}
		seen[value] = true
	}
	return true
}

func validProviderEvidenceRef(value, gatekeeperVersion string) bool {
	roots := []string{
		"human_intent.current_prompt",
		"human_intent.prior_messages",
		"agent_context.prior_task_trajectory",
		"agent_context.current_execution_trajectory",
		"tool_call",
		"completed_tool_activity",
		"environment",
		"requester_context",
		"core_evidence",
		"actual_request",
	}
	if threeDomainEvidenceContract(gatekeeperVersion) {
		roots = []string{"user_messages", "assistant_messages", "core_verified_facts"}
	} else if legacyR4EvidenceContract(gatekeeperVersion) {
		roots = []string{
			"human_intent.current_prompt",
			"human_intent.active_prior_constraints",
			"agent_context.stated_plan_and_completed_steps",
			"tool_call",
			"recent_relevant_tool_results",
			"environment",
			"evidence",
			"actual_request",
		}
	}
	for _, root := range roots {
		if value == root {
			return true
		}
		if threeDomainEvidenceContract(gatekeeperVersion) {
			continue
		}
		if root != "human_intent.current_prompt" && root != "tool_call" &&
			root != "environment" && root != "requester_context" && root != "core_evidence" && root != "actual_request" &&
			strings.HasPrefix(value, root+"[") && strings.HasSuffix(value, "]") {
			index := strings.TrimSuffix(strings.TrimPrefix(value, root+"["), "]")
			parsed, err := strconv.Atoi(index)
			return err == nil && parsed >= 0 && (legacyR4EvidenceContract(gatekeeperVersion) || parsed < 12)
		}
	}
	return false
}

func threeDomainEvidenceContract(gatekeeperVersion string) bool {
	return gatekeeperVersion == "e2-r8-provenance-focused-benchmark-v19" ||
		gatekeeperVersion == "e2-r9-corrected-focused-benchmark-v20" ||
		gatekeeperVersion == "e2-r10-luna-focused-benchmark-v21" ||
		authoritativeDogfoodVersion(gatekeeperVersion)
}

func legacyR4EvidenceContract(gatekeeperVersion string) bool {
	return gatekeeperVersion == "e2-observability-v7" || gatekeeperVersion == "e2-observability-async-v8"
}

func requesterExecutableProven(raw json.RawMessage) bool {
	var value struct {
		Executable       string `json:"executable"`
		ExecutableSHA256 string `json:"executable_sha256"`
		Arguments        []any  `json:"arguments"`
	}
	return json.Unmarshal(raw, &value) == nil && value.Executable != "" &&
		validSHA256(value.ExecutableSHA256) && value.Arguments != nil
}

func inspectIndex(
	bundle string,
	manifestValue manifest,
	response modelResponseAuditRecord,
	comparison modelResponseAuditRecord,
	outcome humanOutcomeAuditRecord,
	all []indexRecord,
	result *bundleInspection,
) {
	matching := make([]indexRecord, 0, 2)
	for _, entry := range all {
		if entry.EvidenceID == result.EvidenceID {
			matching = append(matching, entry)
		}
	}
	modelEvents, comparisonEvents, outcomeEvents := 0, 0, 0
	for _, entry := range matching {
		if entry.SchemaVersion != 1 || entry.RecordType != "beholder_evidence_index_event" ||
			entry.BundlePath != bundle || !validSHA256(entry.ManifestSHA256) {
			result.Errors = append(result.Errors, "index-event-invalid")
			continue
		}
		switch entry.Phase {
		case "model-decision":
			modelEvents++
			if (dualShadowVersion(manifestValue.GatekeeperVersion) &&
				entry.Variant != primaryVariantForVersion(manifestValue.GatekeeperVersion)) ||
				entry.Decision != response.Decision || entry.Reason != response.Reason ||
				entry.ResponseShape != response.ResponseShape || entry.ModelCalled == nil ||
				*entry.ModelCalled != response.ModelCalled || entry.ModelUsed == nil ||
				*entry.ModelUsed != response.ModelUsed {
				result.Errors = append(result.Errors, "model-index-summary-mismatch")
			}
		case "model-comparison":
			comparisonEvents++
			if entry.Variant != comparisonVariantForVersion(manifestValue.GatekeeperVersion) ||
				entry.Decision != comparison.Decision ||
				entry.Reason != comparison.Reason || entry.ResponseShape != comparison.ResponseShape ||
				entry.ModelCalled == nil || *entry.ModelCalled != comparison.ModelCalled ||
				entry.ModelUsed == nil || *entry.ModelUsed != comparison.ModelUsed {
				result.Errors = append(result.Errors, "comparison-index-summary-mismatch")
			}
		case "human-outcome":
			outcomeEvents++
			if entry.HumanDecision != outcome.Decision || entry.AuthorizationSource != outcome.AuthorizationSource {
				result.Errors = append(result.Errors, "human-index-summary-mismatch")
			}
		default:
			result.Errors = append(result.Errors, "index-phase-invalid")
		}
	}
	if manifestValue.Files["03-model-response.json"] != nil && modelEvents != 1 {
		result.Errors = append(result.Errors, "model-index-event-count")
	}
	_, comparisonResponseName := comparisonStageNames(manifestValue.GatekeeperVersion)
	if dualShadowVersion(manifestValue.GatekeeperVersion) &&
		manifestValue.Files[comparisonResponseName] != nil && comparisonEvents != 1 {
		result.Errors = append(result.Errors, "comparison-index-event-count")
	}
	if manifestValue.Files["04-human-outcome.json"] != nil && outcomeEvents != 1 {
		result.Errors = append(result.Errors, "human-index-event-count")
	}
	if len(matching) > 0 {
		latest := matching[len(matching)-1]
		manifestDigest, err := digestPrivateFile(filepath.Join(bundle, "manifest.json"))
		if err != nil || latest.ManifestSHA256 != manifestDigest || latest.State != manifestValue.State {
			result.Errors = append(result.Errors, "latest-index-manifest-mismatch")
		}
	} else if manifestValue.Files["03-model-response.json"] != nil ||
		(dualShadowVersion(manifestValue.GatekeeperVersion) &&
			manifestValue.Files[comparisonResponseName] != nil) ||
		manifestValue.Files["04-human-outcome.json"] != nil {
		result.Errors = append(result.Errors, "index-events-missing")
	}
}

func loadIndex(root string) ([]indexRecord, error) {
	contents, err := readPrivateFile(filepath.Join(root, "index.jsonl"), 64*1024*1024)
	if err != nil {
		return nil, err
	}
	defer clear(contents)
	records := make([]indexRecord, 0)
	for _, line := range splitLines(contents) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var record indexRecord
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil {
			return nil, errors.New("evidence index contains invalid records")
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("evidence index contains trailing data")
		}
		records = append(records, record)
	}
	return records, nil
}

func strictAuditableVersion(version string) bool {
	return version == "e2-auditable-dogfood-v10" || version == "e2-auditable-dogfood-v11" ||
		version == "e2-auditable-dogfood-v12" || version == "e2-auditable-dogfood-v13" ||
		version == "e2-auditable-dogfood-v14" || version == "e2-auditable-dogfood-v15" ||
		dualShadowVersion(version)
}

func dualShadowVersion(version string) bool {
	return version == "e2-dual-shadow-dogfood-v17" ||
		version == "e2-dual-shadow-r7-benchmark-v18" ||
		version == "e2-r8-provenance-focused-benchmark-v19" ||
		version == "e2-r9-corrected-focused-benchmark-v20" ||
		version == "e2-r10-luna-focused-benchmark-v21" ||
		authoritativeDogfoodVersion(version)
}

func authoritativeDogfoodVersion(version string) bool {
	return version == "e2-authoritative-dogfood-v22" ||
		version == "e2-authoritative-dogfood-v23" ||
		version == "e2-authoritative-dogfood-v24" ||
		version == "e2-authoritative-dogfood-v26" ||
		version == "e2-authoritative-dogfood-v27" ||
		version == "e2-authoritative-dogfood-v30" ||
		version == "e2-authoritative-dogfood-v31" ||
		version == "e2-authoritative-dogfood-v32"
}

func primaryVariantForVersion(version string) string {
	if authoritativeDogfoodVersion(version) {
		return "thinking-disabled"
	}
	return "thinking-enabled"
}

func comparisonVariantForVersion(version string) string {
	if authoritativeDogfoodVersion(version) {
		return "thinking-enabled"
	}
	return "thinking-disabled"
}

func comparisonStageNames(version string) (string, string) {
	variant := comparisonVariantForVersion(version)
	return "05-model-request-" + variant + ".json", "06-model-response-" + variant + ".json"
}

func modelContextProvenanceValid(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return false
	}
	if header.SchemaVersion == 2 {
		return threeDomainModelContextProvenanceValid(raw)
	}
	if header.SchemaVersion == 3 || header.SchemaVersion == 4 || header.SchemaVersion == 5 {
		return chronologicalThreeDomainModelContextProvenanceValid(raw)
	}
	if header.SchemaVersion != 0 && header.SchemaVersion != 1 {
		return false
	}
	var input struct {
		HumanIntent struct {
			PriorMessages []struct {
				Source     string `json:"source"`
				TrustClass string `json:"trust_class"`
			} `json:"prior_messages"`
		} `json:"human_intent"`
		AgentContext struct {
			AmbientContext []struct {
				Source     string `json:"source"`
				TrustClass string `json:"trust_class"`
			} `json:"ambient_context"`
		} `json:"agent_context"`
	}
	if json.Unmarshal(raw, &input) != nil {
		return false
	}
	for _, message := range input.HumanIntent.PriorMessages {
		if message.Source != "human-message" || message.TrustClass != "human-authored" {
			return false
		}
	}
	for _, context := range input.AgentContext.AmbientContext {
		if context.Source == "" || context.TrustClass == "" || context.TrustClass == "human-authored" {
			return false
		}
	}
	return true
}

func threeDomainModelContextProvenanceValid(raw json.RawMessage) bool {
	type message struct {
		Source     string `json:"source"`
		TrustClass string `json:"trust_class"`
	}
	var input struct {
		UserMessages struct {
			Current message   `json:"current"`
			Prior   []message `json:"prior"`
		} `json:"user_messages"`
		AssistantMessages struct {
			Prior            []message `json:"prior"`
			Current          []message `json:"current"`
			RequestRationale *struct {
				Source     string `json:"source"`
				TrustClass string `json:"trust_class"`
			} `json:"request_rationale"`
		} `json:"assistant_messages"`
		CoreVerifiedFacts struct {
			ActualRequest struct {
				VerificationScope string `json:"verification_scope"`
			} `json:"actual_request"`
			CapturedContext struct {
				CurrentToolCall message   `json:"current_tool_call"`
				AmbientContext  []message `json:"ambient_context"`
			} `json:"captured_context"`
		} `json:"core_verified_facts"`
	}
	if json.Unmarshal(raw, &input) != nil ||
		input.UserMessages.Current.Source != "managed-current-user-prompt" ||
		input.UserMessages.Current.TrustClass != "human-authored" ||
		input.CoreVerifiedFacts.ActualRequest.VerificationScope != "operation-and-target-bound-by-core" ||
		input.CoreVerifiedFacts.CapturedContext.CurrentToolCall.Source != "managed-pre-tool-use" ||
		input.CoreVerifiedFacts.CapturedContext.CurrentToolCall.TrustClass != "core-captured" {
		return false
	}
	for _, value := range input.UserMessages.Prior {
		if value.Source != "human-message" || value.TrustClass != "human-authored" {
			return false
		}
	}
	for _, values := range [][]message{
		input.AssistantMessages.Prior,
		input.AssistantMessages.Current,
		input.CoreVerifiedFacts.CapturedContext.AmbientContext,
	} {
		for _, value := range values {
			if value.Source == "" || value.TrustClass == "" || value.TrustClass == "human-authored" {
				return false
			}
		}
	}
	if rationale := input.AssistantMessages.RequestRationale; rationale != nil &&
		(rationale.Source != "bound-request-context" || rationale.TrustClass != "assistant-assertion") {
		return false
	}
	return true
}

func chronologicalThreeDomainModelContextProvenanceValid(raw json.RawMessage) bool {
	return modelcontract.ValidateChronology(raw) == nil
}

func loadDecisionRecords(root string) ([]decisionRecordAudit, error) {
	if root == "" {
		return []decisionRecordAudit{}, nil
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || verifyDirectory(root) != nil {
		return nil, errors.New("decision record root is not a private directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	records := []decisionRecordAudit{}
	for _, entry := range entries {
		if (!strings.HasPrefix(entry.Name(), "e2-shadow") &&
			!strings.HasPrefix(entry.Name(), "e2-authoritative")) ||
			!strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		if entry.IsDir() {
			return nil, errors.New("decision record path is a directory")
		}
		contents, readErr := readPrivateFile(filepath.Join(root, entry.Name()), 256*1024*1024)
		if readErr != nil {
			return nil, readErr
		}
		for _, line := range splitLines(contents) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var record decisionRecordAudit
			if json.Unmarshal(line, &record) != nil || record.SchemaVersion != 1 ||
				record.RecordType != "e2_shadow_decision" || record.ObservedAt.IsZero() {
				clear(contents)
				return nil, errors.New("decision record contains invalid records")
			}
			records = append(records, record)
		}
		clear(contents)
	}
	return records, nil
}

func listBundleIDs(root string) ([]string, error) {
	months, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, month := range months {
		if !month.IsDir() {
			if month.Name() != "index.jsonl" && month.Name() != "outcome-delivery.jsonl" {
				return nil, errors.New("unexpected evidence root entry")
			}
			continue
		}
		monthPath := filepath.Join(root, month.Name())
		if verifyDirectory(monthPath) != nil {
			return nil, errors.New("unsafe evidence month")
		}
		bundles, err := os.ReadDir(monthPath)
		if err != nil {
			return nil, err
		}
		for _, bundle := range bundles {
			if !bundle.IsDir() || !evidenceIDPattern.MatchString(bundle.Name()) {
				return nil, errors.New("unexpected evidence bundle entry")
			}
			ids = append(ids, bundle.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func auditEvidence(root string, output io.Writer) error {
	return auditEvidenceWithRecordRoot(root, "", output)
}

func auditEvidenceWithRecordRoot(root, recordRoot string, output io.Writer) error {
	index, indexErr := loadIndex(root)
	ids, idsErr := listBundleIDs(root)
	records, recordsErr := loadDecisionRecords(recordRoot)
	summary := auditSummary{
		SchemaVersion: 1, RecordType: "beholder_evidence_audit", ObservedAt: time.Now().UTC(),
		EvidenceRoot: root, DecisionRecordRoot: recordRoot,
		Valid:  indexErr == nil && idsErr == nil && recordsErr == nil,
		Totals: map[string]int{}, Bundles: []bundleInspection{}, Findings: []string{}, Observations: []string{},
	}
	if indexErr != nil {
		summary.Findings = append(summary.Findings, "index-invalid:"+indexErr.Error())
	}
	if idsErr != nil {
		summary.Findings = append(summary.Findings, "bundle-inventory-invalid:"+idsErr.Error())
	}
	if recordsErr != nil {
		summary.Findings = append(summary.Findings, "decision-record-inventory-invalid:"+recordsErr.Error())
	}
	requestDecisions := map[string]map[string]bool{}
	requestVersions := map[string]map[string]bool{}
	bundleIDs := map[string]bool{}
	strictBundleDecisions := map[string]bool{}
	for _, evidenceID := range ids {
		bundleIDs[evidenceID] = true
		inspection := inspectBundle(root, evidenceID, index)
		summary.Bundles = append(summary.Bundles, inspection)
		summary.Totals["bundles"]++
		if inspection.Valid {
			summary.Totals["valid_bundles"]++
		} else {
			summary.Totals["invalid_bundles"]++
			summary.Valid = false
		}
		summary.Totals["errors"] += len(inspection.Errors)
		for _, issue := range inspection.Errors {
			if issue == "human-outcome-overdue" {
				summary.Totals["overdue_human_outcomes"]++
			}
		}
		if inspection.State == "partial" {
			summary.Totals["partial_bundles"]++
		}
		if inspection.Facts.ModelDecision != "" {
			summary.Totals["model_decisions"]++
			if strictAuditableVersion(inspection.GatekeeperVersion) {
				strictBundleDecisions[evidenceID] = true
			}
		}
		if inspection.Facts.HumanDecision != "" {
			summary.Totals["human_outcomes"]++
		}
		if inspection.Facts.RequesterExecutableProven {
			summary.Totals["requester_executable_proven"]++
		}
		if inspection.Facts.CompletedTools > 0 {
			summary.Totals["bundles_with_completed_tools"]++
		}
		for _, warning := range inspection.Warnings {
			summary.Totals["warnings"]++
			if warning == "human-outcome-overdue" {
				summary.Totals["overdue_human_outcomes"]++
			}
			if warning == "model-human-decision-disagreement" {
				summary.Totals["model_human_disagreements"]++
			}
		}
		if inspection.Facts.ModelRequestSHA256 != "" && inspection.Facts.ModelDecision != "" {
			if requestDecisions[inspection.Facts.ModelRequestSHA256] == nil {
				requestDecisions[inspection.Facts.ModelRequestSHA256] = map[string]bool{}
				requestVersions[inspection.Facts.ModelRequestSHA256] = map[string]bool{}
			}
			requestDecisions[inspection.Facts.ModelRequestSHA256][inspection.Facts.ModelDecision] = true
			requestVersions[inspection.Facts.ModelRequestSHA256][inspection.GatekeeperVersion] = true
		}
	}
	decisionRecordsByRequest := map[string]int{}
	if recordsErr == nil && recordRoot != "" {
		for _, record := range records {
			summary.Totals["decision_records"]++
			if !strictAuditableVersion(record.GatekeeperVersion) {
				summary.Totals["legacy_decision_records"]++
				continue
			}
			summary.Totals["auditable_decision_records"]++
			decisionRecordsByRequest[record.RequestID]++
			switch {
			case !evidenceIDPattern.MatchString(record.RequestID):
				summary.Findings = append(summary.Findings, "decision-record-request-id-invalid")
			case record.EvidenceID == "":
				summary.Totals["orphan_decision_records"]++
				summary.Findings = append(summary.Findings, "decision-record-without-evidence:"+record.RequestID)
			case record.EvidenceID != record.RequestID:
				summary.Findings = append(summary.Findings, "decision-record-evidence-id-mismatch:"+record.RequestID)
			case !bundleIDs[record.EvidenceID]:
				summary.Totals["orphan_decision_records"]++
				summary.Findings = append(summary.Findings, "decision-record-bundle-missing:"+record.RequestID)
			default:
				summary.Totals["decision_records_with_bundle"]++
			}
		}
		for requestID, count := range decisionRecordsByRequest {
			if count != 1 {
				summary.Findings = append(summary.Findings, "decision-record-count:"+requestID)
			}
		}
		for evidenceID := range strictBundleDecisions {
			if decisionRecordsByRequest[evidenceID] == 0 {
				summary.Findings = append(summary.Findings, "bundle-without-decision-record:"+evidenceID)
			}
		}
	}
	for digest, decisions := range requestDecisions {
		if len(decisions) > 1 {
			value := "identical-model-request-diverged:" + digest
			if repeatedDecisionBenchmarkVersions(requestVersions[digest]) {
				summary.Observations = append(summary.Observations, value)
				summary.Totals["identical_model_request_divergences"]++
			} else {
				summary.Findings = append(summary.Findings, value)
			}
		}
	}
	summary.Findings = uniqueSorted(summary.Findings)
	summary.Observations = uniqueSorted(summary.Observations)
	if len(summary.Findings) > 0 {
		summary.Valid = false
	}
	if err := writeJSON(output, summary); err != nil {
		return err
	}
	if !summary.Valid {
		return errors.New("evidence audit found inconsistencies")
	}
	return nil
}

func repeatedDecisionBenchmarkVersions(versions map[string]bool) bool {
	return len(versions) == 1 &&
		(versions["e2-dual-shadow-r7-benchmark-v18"] ||
			versions["e2-r8-provenance-focused-benchmark-v19"] ||
			versions["e2-r9-corrected-focused-benchmark-v20"] ||
			versions["e2-r10-luna-focused-benchmark-v21"])
}

func semanticFacts(root, evidenceID string) (bundleFacts, error) {
	index, _ := loadIndex(root)
	inspection := inspectBundle(root, evidenceID, index)
	if !inspection.Valid {
		return inspection.Facts, fmt.Errorf("%s is not semantically valid", evidenceID)
	}
	return inspection.Facts, nil
}

func semanticComparisons(left, right bundleFacts) []map[string]any {
	values := []struct {
		name        string
		left, right any
	}{
		{"surface", left.Surface, right.Surface},
		{"operation", left.Operation, right.Operation},
		{"payload_digest", left.PayloadDigest, right.PayloadDigest},
		{"operation_target_sha256", left.OperationTargetSHA256, right.OperationTargetSHA256},
		{"model_request_sha256", left.ModelRequestSHA256, right.ModelRequestSHA256},
		{"model_decision", left.ModelDecision, right.ModelDecision},
		{"model_reason", left.ModelReason, right.ModelReason},
		{"human_decision", left.HumanDecision, right.HumanDecision},
		{"authorization_source", left.AuthorizationSource, right.AuthorizationSource},
		{"completed_tools", left.CompletedTools, right.CompletedTools},
		{"codex_task_id", left.CodexTaskID, right.CodexTaskID},
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, map[string]any{
			"field": value.name, "left": value.left, "right": value.right,
			"equal": fmt.Sprint(value.left) == fmt.Sprint(value.right),
		})
	}
	return result
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
