package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
)

func validDiagnosticTraceID(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == value
}

type coreTransportCompletion struct {
	ConnectionID        string
	ResponseWriteResult string
	HandlerErrorCode    string
}

func logCoreDiagnostic(kind, traceID, threadID string, response wireResponse, completions ...coreTransportCompletion) {
	writeCoreDiagnostic(os.Stderr, kind, traceID, threadID, response, completions...)
}

func writeCoreDiagnostic(writer io.Writer, kind, traceID, threadID string, response wireResponse, completions ...coreTransportCompletion) {
	var completion coreTransportCompletion
	if len(completions) == 1 {
		completion = completions[0]
	}
	if !validDiagnosticTraceID(traceID) {
		traceID = ""
	}
	if response.ErrorCode == nil && traceID == "" && completion.HandlerErrorCode == "" {
		return
	}
	switch kind {
	case "execution-lifecycle", "prompt-observation", "host-observation", "execution-root", "request-observation", "ssh-proxy-lease", "ssh-client-lease", "agent-binding-consume", "agent-operation", "direct-operation", "human-outcome":
	default:
		kind = "unknown-request"
	}
	threadDigest := ""
	if safeJoinKey(threadID) {
		digest := sha256.Sum256([]byte(threadID))
		threadDigest = hex.EncodeToString(digest[:])
	}
	attempt := response.BindingAttempt
	if attempt == nil && response.Envelope != nil {
		attempt = response.Envelope.Attribution.BindingAttempt
	}
	_ = json.NewEncoder(writer).Encode(struct {
		Event                 string                   `json:"event"`
		ObservedAt            time.Time                `json:"observed_at"`
		Kind                  string                   `json:"kind"`
		TraceID               string                   `json:"trace_id,omitempty"`
		ThreadSHA256          string                   `json:"thread_sha256,omitempty"`
		Accepted              bool                     `json:"accepted"`
		ErrorCode             *string                  `json:"error_code,omitempty"`
		DecisionErrorCode     *string                  `json:"decision_error_code,omitempty"`
		EvidenceID            string                   `json:"evidence_id,omitempty"`
		ModelCalled           *bool                    `json:"model_called,omitempty"`
		BindingAttempt        *executionBindingAttempt `json:"binding_attempt,omitempty"`
		TransportConnectionID string                   `json:"transport_connection_id,omitempty"`
		ResponseWriteResult   string                   `json:"response_write_result,omitempty"`
		HandlerErrorCode      string                   `json:"handler_error_code,omitempty"`
	}{"beholder-core-request", time.Now().UTC(), kind, traceID, threadDigest,
		response.Accepted, response.ErrorCode, response.DecisionErrorCode, response.EvidenceID, response.ModelCalled, attempt,
		completion.ConnectionID, completion.ResponseWriteResult, completion.HandlerErrorCode})
}
