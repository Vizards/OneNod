package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	beholderProtocolSchemaVersion = 1
	beholderCoreSocketPath        = "/Library/Application Support/Beholder/run/core.sock"
	beholderBindingExtensionName  = "beholder-bind@github.com/Vizards/OneNod"
	beholderBindingVersion        = 1
	beholderMaximumWireSize       = 2 * 1024 * 1024
	beholderRoundTripTimeout      = 35 * time.Second
	beholderLeasePurposeSSH       = "ssh"
	beholderLeasePurposeGit       = "git-sign"
	beholderSSHShimBinaryName     = "ssh"
)

var (
	beholderExecutableHashOnce sync.Once
	beholderExecutableHash     string
)

type beholderRoundTripFunc func(beholderWireRequest) (beholderWireResponse, error)

type beholderOperationTarget struct {
	SchemaVersion      int    `json:"schema_version"`
	Surface            string `json:"surface"`
	Operation          string `json:"operation"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id,omitempty"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	RemoteUser         string `json:"remote_user,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	RequestContext     string `json:"request_context,omitempty"`
	RequesterContext   string `json:"requester_context,omitempty"`
	PayloadDigest      string `json:"payload_digest"`
}

type beholderWireRequest struct {
	observation       *transportObservation    // Local only; never encoded on the wire.
	TraceID           string                   `json:"trace_id,omitempty"`
	SchemaVersion     int                      `json:"schema_version"`
	Kind              string                   `json:"kind"`
	ThreadID          string                   `json:"thread_id,omitempty"`
	Purpose           string                   `json:"purpose,omitempty"`
	Nonce             string                   `json:"nonce,omitempty"`
	Binding           string                   `json:"binding,omitempty"`
	Operation         *beholderOperationTarget `json:"operation_target,omitempty"`
	EvidenceID        string                   `json:"evidence_id,omitempty"`
	HumanOutcome      *beholderHumanOutcome    `json:"human_outcome,omitempty"`
	RequesterDeviceID string                   `json:"requester_device_id,omitempty"`
}

type beholderAuthorization struct {
	SchemaVersion         int    `json:"schema_version"`
	Decision              string `json:"decision"`
	EvidenceID            string `json:"evidence_id"`
	ExpiresAt             int64  `json:"expires_at"`
	IssuedAt              int64  `json:"issued_at"`
	KeyID                 string `json:"key_id"`
	OperationTargetSHA256 string `json:"operation_target_sha256"`
	RequesterDeviceID     string `json:"requester_device_id"`
	Signature             string `json:"signature"`
}

type beholderWireResponse struct {
	ModelCalled       *bool                  `json:"model_called,omitempty"`
	DecisionErrorCode *string                `json:"decision_error_code,omitempty"`
	SchemaVersion     int                    `json:"schema_version"`
	Accepted          bool                   `json:"accepted"`
	Disposition       string                 `json:"disposition,omitempty"`
	AgentSocket       string                 `json:"agent_socket,omitempty"`
	Binding           string                 `json:"binding,omitempty"`
	ErrorCode         *string                `json:"error_code"`
	EvidenceID        string                 `json:"evidence_id,omitempty"`
	Authorization     *beholderAuthorization `json:"authorization,omitempty"`
}

type beholderOutcomeStatus struct {
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
}

type beholderHumanOutcome struct {
	SchemaVersion         int                     `json:"schema_version"`
	RecordType            string                  `json:"record_type"`
	EvidenceID            string                  `json:"evidence_id"`
	OperationTargetSHA256 string                  `json:"operation_target_sha256"`
	OneNodRequestID       *string                 `json:"onenod_request_id"`
	AuthorizationSource   string                  `json:"authorization_source"`
	Decision              string                  `json:"decision"`
	StatusTimeline        []beholderOutcomeStatus `json:"status_timeline"`
	OperationCompleted    bool                    `json:"operation_completed"`
	CredentialDelivered   bool                    `json:"credential_delivered"`
	FailureStage          string                  `json:"failure_stage,omitempty"`
	ObservedAt            time.Time               `json:"observed_at"`
}

type beholderObservation struct {
	Diagnostic    *beholderDiagnostic
	EvidenceID    string
	Target        beholderOperationTarget
	Authorization *beholderAuthorization
}

type beholderOutcomeRecordStatus string

const (
	beholderOutcomeDelivered      beholderOutcomeRecordStatus = "delivered"
	beholderOutcomeQueued         beholderOutcomeRecordStatus = "durably-queued"
	beholderOutcomeInvalid        beholderOutcomeRecordStatus = "invalid"
	beholderOutcomeDeliveryFailed beholderOutcomeRecordStatus = "delivery-failed"
)

type beholderSSHLease struct {
	Diagnostic *beholderDiagnostic
	Nonce      []byte
}

func (lease *beholderSSHLease) clear() {
	if lease == nil {
		return
	}
	clear(lease.Nonce)
	lease.Nonce = nil
}

func defaultBeholderRoundTrip(request beholderWireRequest) (beholderWireResponse, error) {
	dial := request.observation.begin("core-dial", beholderRoundTripTimeout)
	connection, err := net.DialTimeout("unix", beholderCoreSocketPath, beholderRoundTripTimeout)
	dial.finish(err)
	if err != nil {
		return beholderWireResponse{}, &transportFailure{message: "Beholder Core is unavailable", class: transportErrorClass(err), cause: err}
	}
	defer connection.Close()
	deadline := time.Now().Add(beholderRoundTripTimeout)
	_ = connection.SetDeadline(deadline)
	write := request.observation.begin("core-request-write", beholderRoundTripTimeout, deadline)
	err = json.NewEncoder(connection).Encode(request)
	write.finish(err)
	if err != nil {
		return beholderWireResponse{}, &transportFailure{message: "send Beholder request failed", class: transportErrorClass(err), cause: err}
	}
	var response beholderWireResponse
	decoder := json.NewDecoder(io.LimitReader(connection, beholderMaximumWireSize+1))
	read := request.observation.begin("core-response-read", beholderRoundTripTimeout, deadline)
	err = decoder.Decode(&response)
	if err != nil || response.SchemaVersion != beholderProtocolSchemaVersion {
		class := "malformed-response"
		if err != nil {
			class = transportErrorClass(err)
		}
		read.finishResult(class, nil)
		return beholderWireResponse{}, &transportFailure{message: "Beholder Core returned an invalid response", class: class, cause: err}
	}
	read.finishResult("ok", &response.Accepted)
	return response, nil
}

func requestBeholderSSHLease(deps dependencies, purpose string) (beholderSSHLease, error) {
	if purpose != beholderLeasePurposeSSH && purpose != beholderLeasePurposeGit {
		return beholderSSHLease{}, errors.New("invalid Beholder SSH lease purpose")
	}
	threadID := os.Getenv("CODEX_THREAD_ID")
	if !safeBeholderToken(threadID, 8, 128) {
		return beholderSSHLease{}, errors.New("Beholder task binding is unavailable")
	}
	called := false
	diagnostic := newBeholderDiagnostic("lease", "lease-unavailable", &called)
	fail := func(code string) (beholderSSHLease, error) {
		return beholderSSHLease{}, failBeholderStage(diagnostic, "lease", code)
	}
	if deps.beholder == nil || diagnostic == nil {
		return fail("core-unavailable")
	}
	response, err := deps.beholder(beholderWireRequest{SchemaVersion: beholderProtocolSchemaVersion,
		Kind: "ssh-client-lease", ThreadID: threadID, Purpose: purpose, TraceID: diagnostic.TraceID})
	if err != nil {
		return fail("core-transport-error")
	}
	if response.ErrorCode != nil {
		if beholderDiagnosticCode(*response.ErrorCode) {
			return fail(*response.ErrorCode)
		}
		return fail("lease-response-invalid")
	}
	if !response.Accepted || !safeBeholderToken(response.Binding, 32, 256) {
		return fail("lease-response-invalid")
	}
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(response.Binding)
	response.Binding = ""
	if err != nil || len(nonce) < 16 || len(nonce) > 128 {
		clear(nonce)
		return fail("lease-response-invalid")
	}
	diagnostic.Stage, diagnostic.Code = "binding", "binding-pending"
	return beholderSSHLease{Nonce: nonce, Diagnostic: diagnostic}, nil
}

func consumeBeholderAgentBinding(deps dependencies, nonce []byte, diagnostics ...*beholderDiagnostic) (string, error) {
	var diagnostic *beholderDiagnostic
	if len(diagnostics) == 1 {
		diagnostic = diagnostics[0]
	}
	return consumeBeholderAgentBindingObserved(deps, nonce, diagnostic, nil)
}

func consumeBeholderAgentBindingObserved(deps dependencies, nonce []byte, diagnostic *beholderDiagnostic, observation *transportObservation) (string, error) {
	if deps.beholder == nil || len(nonce) < 16 || len(nonce) > 128 {
		return "", errors.New("Beholder Agent binding is unavailable")
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	traceID := ""
	if validBeholderDiagnostic(diagnostic) {
		traceID = diagnostic.TraceID
	}
	span := observation.begin("core-binding-round-trip", 0)
	response, err := deps.beholder(beholderWireRequest{TraceID: traceID, observation: observation,
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "agent-binding-consume",
		Nonce:         encodedNonce,
	})
	if err != nil {
		span.finish(err)
		return "", &transportFailure{message: "Beholder Agent binding was rejected", class: transportErrorClass(err), cause: err}
	}
	if !response.Accepted || response.ErrorCode != nil || !safeBeholderToken(response.Binding, 32, 256) {
		class := "rejected"
		if response.Accepted && response.ErrorCode == nil {
			class = "malformed-response"
		}
		span.finishResult(class, &response.Accepted)
		return "", &transportFailure{message: "Beholder Agent binding was rejected", class: class}
	}
	span.finishResult("ok", &response.Accepted)
	return response.Binding, nil
}

func observeBeholderAgentOperation(
	deps dependencies,
	binding string,
	target beholderOperationTarget,
) (string, error) {
	disposition, _, err := observeBeholderAgentOperationWithEvidence(deps, binding, target, "", "")
	return disposition, err
}

func observeBeholderAgentOperationWithEvidence(
	deps dependencies,
	binding string,
	target beholderOperationTarget,
	requesterDeviceID, traceID string,
) (string, beholderObservation, error) {
	if deps.beholder == nil || !safeBeholderToken(binding, 32, 256) || !validBeholderOperationTarget(target) {
		return "escalate", beholderObservation{}, errors.New("Beholder Agent operation binding is unavailable")
	}
	response, err := deps.beholder(beholderWireRequest{
		TraceID:           traceID,
		SchemaVersion:     beholderProtocolSchemaVersion,
		Kind:              "agent-operation",
		Binding:           binding,
		Operation:         &target,
		RequesterDeviceID: requesterDeviceID,
	})
	if err != nil || !response.Accepted || response.ErrorCode != nil ||
		(response.Disposition != "allow" && response.Disposition != "escalate") {
		return "escalate", decisionObservation(response, target, requesterDeviceID, traceID), errors.New("Beholder Agent operation was not decided")
	}
	return response.Disposition, decisionObservation(response, target, requesterDeviceID, traceID), nil
}

// observeBeholderDirectRequest sends only structured identifiers and a digest
// of the exact canonical outbound body. Credential values remain in the may
// process and never cross the local Beholder boundary.
func observeBeholderDirectRequest(
	deps dependencies,
	body any,
	requesterDeviceID string,
	configurations ...cliConfig,
) beholderObservation {
	threadID := os.Getenv("CODEX_THREAD_ID")
	if deps.beholder == nil || !safeBeholderToken(threadID, 8, 128) {
		return beholderObservation{}
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return beholderObservation{}
	}
	target, ok := directBeholderOperationTarget(body, canonical, configurations...)
	clear(canonical)
	if !ok {
		return beholderObservation{}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return beholderObservation{}
	}
	encodedNonce := hex.EncodeToString(nonce)
	clear(nonce)
	diagnostic := newBeholderDiagnostic("core", "decision-unavailable", nil)
	if diagnostic == nil {
		return beholderObservation{}
	}
	response, _ := deps.beholder(beholderWireRequest{
		TraceID:           diagnostic.TraceID,
		SchemaVersion:     beholderProtocolSchemaVersion,
		Kind:              "direct-operation",
		ThreadID:          threadID,
		Nonce:             encodedNonce,
		Operation:         &target,
		RequesterDeviceID: requesterDeviceID,
	})
	threadID = ""
	return decisionObservation(response, target, requesterDeviceID, diagnostic.TraceID)
}

func observationFromResponse(
	response beholderWireResponse,
	target beholderOperationTarget,
	requesterDeviceID string,
) beholderObservation {
	if !safeBeholderToken(response.EvidenceID, 8, 96) {
		return beholderObservation{}
	}
	observation := beholderObservation{EvidenceID: response.EvidenceID, Target: target}
	if response.Authorization != nil && validBeholderAuthorization(
		response.Authorization,
		response.EvidenceID,
		target.PayloadDigest,
		requesterDeviceID,
	) {
		copy := *response.Authorization
		observation.Authorization = &copy
	}
	return observation
}

func validBeholderAuthorization(
	authorization *beholderAuthorization,
	evidenceID string,
	payloadDigest string,
	requesterDeviceID string,
) bool {
	if authorization == nil {
		return false
	}
	return authorization.SchemaVersion == 1 && authorization.Decision == "allow" &&
		authorization.EvidenceID == evidenceID && safeBeholderToken(evidenceID, 8, 96) &&
		requesterDeviceID != "" && authorization.RequesterDeviceID == requesterDeviceID &&
		safeBeholderField(authorization.RequesterDeviceID, 128, false) &&
		validBeholderSHA256(authorization.OperationTargetSHA256) &&
		authorization.OperationTargetSHA256 == payloadDigest &&
		safeBeholderToken(authorization.KeyID, 43, 43) &&
		safeBeholderToken(authorization.Signature, 86, 86) &&
		authorization.IssuedAt > 0 && authorization.ExpiresAt > authorization.IssuedAt &&
		authorization.ExpiresAt-authorization.IssuedAt <= 30
}

func attachBeholderAuthorization(body any, observation beholderObservation) {
	if observation.Authorization == nil {
		if client := requestClient(body); client != nil && validBeholderDiagnostic(observation.Diagnostic) {
			client.BeholderDiagnostic = observation.Diagnostic
		}
		return
	}
	switch request := body.(type) {
	case *createRequest:
		request.BeholderAuthorization = observation.Authorization
	case *credentialUseRequest:
		request.BeholderAuthorization = observation.Authorization
	case *itemCreateRequest:
		request.BeholderAuthorization = observation.Authorization
	case *itemPatchRequest:
		request.BeholderAuthorization = observation.Authorization
	case *itemArchiveRequest:
		request.BeholderAuthorization = observation.Authorization
	case *sshSignRequest:
		request.BeholderAuthorization = observation.Authorization
	}
}

func recordBeholderHumanOutcome(
	deps dependencies,
	observation beholderObservation,
	outcome beholderHumanOutcome,
) beholderOutcomeRecordStatus {
	if deps.beholder == nil || observation.EvidenceID == "" ||
		observation.EvidenceID != outcome.EvidenceID || !validBeholderOperationTarget(observation.Target) ||
		!validBeholderHumanOutcome(outcome) {
		return beholderOutcomeInvalid
	}
	pending := beholderPendingOutcome{
		SchemaVersion: beholderOutcomeSpoolSchema,
		RecordType:    "beholder_pending_human_outcome", EvidenceID: observation.EvidenceID,
		Target: observation.Target, HumanOutcome: outcome,
	}
	if deps.beholderOutcomeRoot == nil {
		acknowledged, _ := sendPendingBeholderOutcome(deps, pending)
		if acknowledged {
			return beholderOutcomeDelivered
		}
		return beholderOutcomeDeliveryFailed
	}
	root, err := deps.beholderOutcomeRoot()
	if err != nil || ensureBeholderOutcomeRoot(root) != nil ||
		persistPendingBeholderOutcome(root, pending) != nil {
		// Evidence recording remains observational: a spool failure must never
		// alter the existing authorization or credential-delivery result.
		acknowledged, _ := sendPendingBeholderOutcome(deps, pending)
		if acknowledged {
			return beholderOutcomeDelivered
		}
		return beholderOutcomeDeliveryFailed
	}
	flushPendingBeholderOutcomes(deps)
	_, err = os.Lstat(pendingBeholderOutcomePath(root, pending.EvidenceID))
	if errors.Is(err, os.ErrNotExist) {
		return beholderOutcomeDelivered
	}
	if err != nil {
		return beholderOutcomeDeliveryFailed
	}
	return beholderOutcomeQueued
}

func validBeholderHumanOutcome(outcome beholderHumanOutcome) bool {
	if outcome.SchemaVersion != 1 || outcome.RecordType != "beholder_human_outcome" ||
		!safeBeholderToken(outcome.EvidenceID, 8, 96) || outcome.ObservedAt.IsZero() ||
		!validBeholderSHA256(outcome.OperationTargetSHA256) ||
		!beholderOneOf(outcome.AuthorizationSource, "beholder-authoritative", "pwa-interactive", "remembered-grant", "local-fallback", "not-requested", "unknown") ||
		!beholderOneOf(outcome.Decision, "approved", "rejected", "timed_out", "expired", "error", "not_requested", "unknown") ||
		(outcome.OneNodRequestID != nil && !safeBeholderField(*outcome.OneNodRequestID, 256, false)) ||
		!safeBeholderField(outcome.FailureStage, 96, true) || len(outcome.StatusTimeline) > 256 {
		return false
	}
	for _, status := range outcome.StatusTimeline {
		if !safeBeholderField(status.Status, 96, false) || status.ObservedAt.IsZero() {
			return false
		}
	}
	return true
}

func validBeholderSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func beholderOperationTargetSHA256(target beholderOperationTarget) (string, bool) {
	encoded, err := json.Marshal(target)
	if err != nil {
		return "", false
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func beholderOneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func directBeholderOperationTarget(
	body any,
	canonical []byte,
	configurations ...cliConfig,
) (beholderOperationTarget, bool) {
	operation := ""
	targetKind := "onepassword-item"
	itemID := ""
	fieldIDs := []string{}
	expectedVersion := int64(0)
	var requestContext any
	switch request := body.(type) {
	case createRequest:
		operation = request.Action
		itemID = request.ItemID
		fieldIDs = []string{request.FieldID}
		expectedVersion = request.ExpectedVersion
		requestContext = struct {
			AuthorizationScope *applicationAuthorizationScope `json:"authorization_scope,omitempty"`
			Client             clientObservation              `json:"client"`
		}{request.AuthorizationScope, request.Client}
	case credentialUseRequest:
		operation = request.Action
		itemID = request.ItemID
		fieldIDs = append(fieldIDs, request.FieldIDs...)
		expectedVersion = request.ExpectedVersion
		requestContext = struct {
			AuthorizationScope *applicationAuthorizationScope `json:"authorization_scope,omitempty"`
			Client             clientObservation              `json:"client"`
		}{request.AuthorizationScope, request.Client}
	case itemCreateRequest:
		operation = request.Action
		targetKind = "onepassword-item-create"
		for _, field := range request.Fields {
			fieldIDs = append(fieldIDs, field.FieldID)
		}
		type fieldMetadata struct {
			FieldID   string `json:"field_id"`
			FieldType string `json:"field_type"`
			Label     string `json:"label"`
		}
		fields := make([]fieldMetadata, 0, len(request.Fields))
		for _, field := range request.Fields {
			fields = append(fields, fieldMetadata{field.FieldID, field.FieldType, field.Label})
		}
		requestContext = struct {
			Category string            `json:"category"`
			Client   clientObservation `json:"client"`
			Fields   []fieldMetadata   `json:"fields"`
			Title    string            `json:"title"`
		}{request.Category, request.Client, fields, request.Title}
	case itemPatchRequest:
		operation = request.Action
		itemID = request.ItemID
		expectedVersion = request.ExpectedVersion
		for _, mutation := range request.Operations {
			fieldIDs = append(fieldIDs, mutation.FieldID)
		}
		type patchMetadata struct {
			FieldID      string  `json:"field_id"`
			FieldType    *string `json:"field_type,omitempty"`
			Label        *string `json:"label,omitempty"`
			Op           string  `json:"op"`
			ValuePresent bool    `json:"value_present"`
		}
		operations := make([]patchMetadata, 0, len(request.Operations))
		for _, mutation := range request.Operations {
			operations = append(operations, patchMetadata{
				mutation.FieldID, mutation.FieldType, mutation.Label, mutation.Op, mutation.Value != nil,
			})
		}
		requestContext = struct {
			Client     clientObservation `json:"client"`
			Operations []patchMetadata   `json:"operations"`
		}{request.Client, operations}
	case itemArchiveRequest:
		operation = request.Action
		itemID = request.ItemID
		expectedVersion = request.ExpectedVersion
		requestContext = struct {
			Client clientObservation `json:"client"`
		}{request.Client}
	default:
		return beholderOperationTarget{}, false
	}
	if operation == "" || len(canonical) == 0 {
		return beholderOperationTarget{}, false
	}
	sort.Strings(fieldIDs)
	descriptor, err := json.Marshal(struct {
		ItemID          string   `json:"item_id,omitempty"`
		FieldIDs        []string `json:"field_ids,omitempty"`
		ExpectedVersion int64    `json:"expected_version,omitempty"`
	}{ItemID: itemID, FieldIDs: fieldIDs, ExpectedVersion: expectedVersion})
	if err != nil || len(descriptor) > 1024 {
		return beholderOperationTarget{}, false
	}
	digest := sha256.Sum256(canonical)
	contextJSON, err := json.Marshal(requestContext)
	if err != nil || len(contextJSON) > 16*1024 {
		clear(contextJSON)
		return beholderOperationTarget{}, false
	}
	target := beholderOperationTarget{
		SchemaVersion:    beholderProtocolSchemaVersion,
		Surface:          "direct-may",
		Operation:        operation,
		TargetKind:       targetKind,
		TargetID:         string(descriptor),
		RequestContext:   string(contextJSON),
		RequesterContext: beholderRequesterContext(configurations...),
		PayloadDigest:    hex.EncodeToString(digest[:]),
	}
	clear(contextJSON)
	return target, validBeholderOperationTarget(target)
}

func sshBeholderOperationTarget(
	operation sshOperation,
	identity servedSSHIdentity,
	client clientObservation,
	canonicalRequest []byte,
	configurations ...cliConfig,
) beholderOperationTarget {
	digest := sha256.Sum256(canonicalRequest)
	requestContext := struct {
		Client    clientObservation `json:"client"`
		Operation sshOperation      `json:"operation"`
	}{Client: client, Operation: operation}
	return beholderOperationTarget{
		SchemaVersion:      beholderProtocolSchemaVersion,
		Surface:            "ssh-agent",
		Operation:          operation.Kind,
		TargetKind:         "ssh-key",
		TargetID:           identity.catalog.ItemID,
		KeyFingerprint:     identity.catalog.Metadata.Fingerprint,
		RemoteUser:         operation.RemoteUsername,
		HostKeyFingerprint: operation.ServerHostKeyFingerprint,
		RequestContext:     mustSafeJSON(requestContext),
		RequesterContext:   beholderRequesterContext(configurations...),
		PayloadDigest:      hex.EncodeToString(digest[:]),
	}
}

func mustSafeJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 16*1024 {
		clear(encoded)
		return ""
	}
	result := string(encoded)
	clear(encoded)
	return result
}

func beholderRequesterContext(configurations ...cliConfig) string {
	type capturedValue struct {
		Name          string `json:"name,omitempty"`
		Index         int    `json:"index,omitempty"`
		Value         string `json:"value"`
		Redacted      bool   `json:"redacted"`
		OriginalBytes int    `json:"original_bytes,omitempty"`
		RedactionRule string `json:"redaction_rule,omitempty"`
	}
	type requesterContext struct {
		SchemaVersion     int             `json:"schema_version"`
		CapturedAt        time.Time       `json:"captured_at"`
		Executable        string          `json:"executable,omitempty"`
		ExecutableSHA256  string          `json:"executable_sha256,omitempty"`
		CWD               string          `json:"cwd,omitempty"`
		PID               int             `json:"pid"`
		ParentPID         int             `json:"parent_pid"`
		UID               int             `json:"uid"`
		EffectiveUID      int             `json:"effective_uid"`
		GatewayOrigin     string          `json:"gateway_origin,omitempty"`
		PollIntervalMS    int64           `json:"poll_interval_ms,omitempty"`
		ApprovalTimeoutMS int64           `json:"approval_timeout_ms,omitempty"`
		Arguments         []capturedValue `json:"arguments"`
		Environment       []capturedValue `json:"environment"`
	}
	executable, _ := os.Executable()
	cwd, _ := os.Getwd()
	context := requesterContext{
		SchemaVersion: 1, CapturedAt: time.Now().UTC(), Executable: executable, CWD: cwd,
		ExecutableSHA256: beholderFileSHA256(executable),
		PID:              os.Getpid(), ParentPID: os.Getppid(), UID: os.Getuid(), EffectiveUID: os.Geteuid(),
		Arguments: []capturedValue{}, Environment: []capturedValue{},
	}
	if len(configurations) == 1 {
		context.GatewayOrigin = safeBeholderOrigin(configurations[0].origin)
		context.PollIntervalMS = configurations[0].pollInterval.Milliseconds()
		context.ApprovalTimeoutMS = configurations[0].timeout.Milliseconds()
	}
	for _, pair := range os.Environ() {
		name, value, found := strings.Cut(pair, "=")
		if !found || name == "" {
			continue
		}
		entry := capturedValue{Name: name, Value: value}
		if !beholderEnvironmentValueCollected(name) {
			entry.Value = ""
			entry.Redacted = true
			entry.OriginalBytes = len(value)
			entry.RedactionRule = "environment-value-not-collected"
		}
		context.Environment = append(context.Environment, entry)
	}
	sort.Slice(context.Environment, func(left, right int) bool {
		return context.Environment[left].Name < context.Environment[right].Name
	})
	encoded, err := json.Marshal(context)
	if err != nil || len(encoded) > 1024*1024 {
		clear(encoded)
		return ""
	}
	result := string(encoded)
	clear(encoded)
	return result
}

func safeBeholderOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func beholderFileSHA256(path string) string {
	beholderExecutableHashOnce.Do(func() {
		file, err := os.Open(path)
		if err != nil {
			return
		}
		defer file.Close()
		hash := sha256.New()
		written, err := io.Copy(hash, io.LimitReader(file, 256*1024*1024+1))
		if err != nil || written > 256*1024*1024 {
			return
		}
		beholderExecutableHash = hex.EncodeToString(hash.Sum(nil))
	})
	return beholderExecutableHash
}

// Capture process metadata by source. Arbitrary environment and argv values
// are omitted; the exact operation comes from the managed tool observation.
func beholderEnvironmentValueCollected(name string) bool {
	return beholderOneOf(name, "HOME", "USER", "LOGNAME", "PATH", "PWD", "SHELL", "TMPDIR", "LANG", "LC_ALL", "TERM", "SSH_AUTH_SOCK", "CODEX_THREAD_ID", "CODEX_SESSION_ID", "CODEX_CI", "CODEX_PERMISSION_PROFILE", "BEHOLDER_CORE_SOCKET")
}

func parseBeholderBindingExtension(contents []byte) ([]byte, error) {
	reader := wireReader{value: contents}
	version, err := reader.uint32()
	if err != nil || version != beholderBindingVersion {
		return nil, errors.New("invalid Beholder binding extension version")
	}
	nonce, err := reader.string()
	if err != nil || len(nonce) < 16 || len(nonce) > 128 || !reader.done() {
		return nil, errors.New("invalid Beholder binding extension nonce")
	}
	return append([]byte(nil), nonce...), nil
}

func validBeholderAgentSocket(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0
}

func validBeholderOperationTarget(target beholderOperationTarget) bool {
	if target.SchemaVersion != beholderProtocolSchemaVersion ||
		!safeBeholderField(target.Surface, 96, false) ||
		!safeBeholderField(target.Operation, 96, false) ||
		!safeBeholderField(target.TargetKind, 96, false) ||
		!safeBeholderField(target.TargetID, 1024, true) ||
		!safeBeholderField(target.KeyFingerprint, 256, true) ||
		!safeBeholderField(target.RemoteUser, 256, true) ||
		!safeBeholderField(target.HostKeyFingerprint, 256, true) ||
		!safeBeholderField(target.RequestContext, 16*1024, true) ||
		!safeBeholderField(target.RequesterContext, 1024*1024, true) ||
		len(target.PayloadDigest) != sha256.Size*2 {
		return false
	}
	if target.RequestContext != "" && !json.Valid([]byte(target.RequestContext)) {
		return false
	}
	if target.RequesterContext != "" && !json.Valid([]byte(target.RequesterContext)) {
		return false
	}
	_, err := hex.DecodeString(target.PayloadDigest)
	return err == nil
}

func safeBeholderField(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeBeholderToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func decisionObservation(response beholderWireResponse, target beholderOperationTarget, deviceID, traceID string) beholderObservation {
	observation := observationFromResponse(response, target, deviceID)
	if observation.Authorization == nil {
		observation.Diagnostic = diagnosticForDecision(response, traceID)
	}
	return observation
}
