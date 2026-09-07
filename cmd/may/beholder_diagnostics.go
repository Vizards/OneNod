package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const beholderDiagnosticExtensionName = "beholder-diagnostic@github.com/Vizards/OneNod"

// Diagnostics are requester-reported context, never an authorization capability.
// They carry only bounded identifiers and status codes, not task text or keys.
type beholderDiagnostic struct {
	SchemaVersion int    `json:"schema_version"`
	TraceID       string `json:"trace_id"`
	Stage         string `json:"stage"`
	Code          string `json:"code"`
	ModelCalled   *bool  `json:"model_called,omitempty"`
	EvidenceID    string `json:"evidence_id,omitempty"`
}

type beholderStageError struct{ diagnostic *beholderDiagnostic }

func (failure beholderStageError) Error() string {
	return "Beholder " + failure.diagnostic.Stage + ": " + failure.diagnostic.Code
}

func newBeholderDiagnostic(stage, code string, modelCalled *bool) *beholderDiagnostic {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil
	}
	return &beholderDiagnostic{SchemaVersion: 1, TraceID: hex.EncodeToString(nonce[:]), Stage: stage,
		Code: code, ModelCalled: modelCalled}
}

func validBeholderDiagnostic(value *beholderDiagnostic) bool {
	if value == nil || value.SchemaVersion != 1 || len(value.TraceID) != 32 ||
		!beholderOneOf(value.Stage, "lease", "proxy", "binding", "core", "model") ||
		!beholderDiagnosticCode(value.Code) ||
		(value.EvidenceID != "" && !safeBeholderToken(value.EvidenceID, 8, 96)) {
		return false
	}
	trace, err := hex.DecodeString(value.TraceID)
	return err == nil && len(trace) == 16 && hex.EncodeToString(trace) == value.TraceID
}

func beholderDiagnosticCode(value string) bool {
	if len(value) == 0 || len(value) > 96 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.' {
			return false
		}
	}
	return true
}

func diagnosticFromError(err error) *beholderDiagnostic {
	var stageError beholderStageError
	if errors.As(err, &stageError) && validBeholderDiagnostic(stageError.diagnostic) {
		return stageError.diagnostic
	}
	return nil
}

func failBeholderStage(diagnostic *beholderDiagnostic, stage, code string) error {
	if diagnostic == nil {
		return errors.New("Beholder diagnostic unavailable")
	}
	diagnostic.Stage = stage
	diagnostic.Code = code
	if !validBeholderDiagnostic(diagnostic) {
		diagnostic.Code = "invalid-diagnostic-code"
	}
	return beholderStageError{diagnostic: diagnostic}
}

func logBeholderDiagnostic(writer io.Writer, diagnostic *beholderDiagnostic, requestID string) {
	if writer == nil || !validBeholderDiagnostic(diagnostic) {
		return
	}
	if requestID != "" && !safeBeholderToken(requestID, 8, 128) {
		return
	}
	_ = json.NewEncoder(writer).Encode(struct {
		Event      string              `json:"event"`
		ObservedAt time.Time           `json:"observed_at"`
		RequestID  string              `json:"onenod_request_id,omitempty"`
		Diagnostic *beholderDiagnostic `json:"beholder_diagnostic"`
	}{"beholder-request-diagnostic", time.Now().UTC(), requestID, diagnostic})
}

func diagnosticForDecision(response beholderWireResponse, traceID string) *beholderDiagnostic {
	diagnostic := newBeholderDiagnostic("core", "decision-unavailable", response.ModelCalled)
	if diagnostic == nil {
		return nil
	}
	if len(traceID) == 32 {
		diagnostic.TraceID = traceID
	}
	if safeBeholderToken(response.EvidenceID, 8, 96) {
		diagnostic.EvidenceID = response.EvidenceID
	}
	if response.ModelCalled != nil {
		diagnostic.Stage = "model"
		if *response.ModelCalled {
			diagnostic.Code = "model-escalated"
		} else {
			diagnostic.Code = "model-not-called"
		}
	}
	for _, code := range []*string{response.DecisionErrorCode, response.ErrorCode} {
		if code != nil && beholderDiagnosticCode(*code) {
			diagnostic.Code = *code
		}
	}
	return diagnostic
}

func requestClient(body any) *clientObservation {
	switch request := body.(type) {
	case *createRequest:
		return &request.Client
	case *credentialUseRequest:
		return &request.Client
	case *itemCreateRequest:
		return &request.Client
	case *itemPatchRequest:
		return &request.Client
	case *itemArchiveRequest:
		return &request.Client
	case *sshSignRequest:
		return &request.Client
	}
	return nil
}
