package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	gatekeeperWireSchemaVersion      = 1
	maximumShadowGatekeeperRoundTrip = 12 * time.Minute
	humanOutcomeRoundTripTimeout     = 2 * time.Second
)

type shadowGatekeeperClient struct {
	socketPath       string
	timeout          time.Duration
	allowedUID       uint32
	trustedProcess   trustedExecutableIdentity
	coreBinarySHA256 string
}

type gatekeeperLocalRequest struct {
	SchemaVersion    int                   `json:"schema_version"`
	RequestID        string                `json:"request_id"`
	Mode             string                `json:"mode"`
	Prompt           []byte                `json:"prompt"`
	ToolName         string                `json:"tool_name"`
	ToolInput        json.RawMessage       `json:"tool_input,omitempty"`
	TranscriptPath   string                `json:"transcript_path"`
	CWD              string                `json:"cwd"`
	Evidence         json.RawMessage       `json:"evidence"`
	ActualRequest    gatekeeperLocalTarget `json:"actual_request"`
	CoreBinarySHA256 string                `json:"core_binary_sha256,omitempty"`
	HumanOutcome     *humanOutcome         `json:"human_outcome,omitempty"`
}

type gatekeeperLocalTarget struct {
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

type gatekeeperLocalResponse struct {
	SchemaVersion   int     `json:"schema_version"`
	RequestID       string  `json:"request_id"`
	Decision        string  `json:"decision"`
	Reason          string  `json:"reason"`
	ErrorCode       *string `json:"error_code"`
	ModelUsed       bool    `json:"model_used"`
	ModelCalled     bool    `json:"model_called"`
	LatencyMS       int64   `json:"latency_ms"`
	EvidenceID      string  `json:"evidence_id,omitempty"`
	OutcomeRecorded bool    `json:"outcome_recorded,omitempty"`
}

type gatekeeperOutcomeError struct {
	code string
}

func (failure gatekeeperOutcomeError) Error() string {
	return failure.code
}

func gatekeeperOutcomeFailureCode(err error) string {
	var failure gatekeeperOutcomeError
	if errors.As(err, &failure) && safeDecisionField(failure.code, 128, false) {
		return failure.code
	}
	return "human-outcome-gatekeeper-unavailable"
}

func newShadowGatekeeperClient(
	socketPath, trustedPath, trustedSHA256 string,
	allowedUID uint32,
	timeout time.Duration,
) (*shadowGatekeeperClient, error) {
	if !filepath.IsAbs(socketPath) || !filepath.IsAbs(trustedPath) || trustedSHA256 == "" ||
		allowedUID == 0 || !validShadowGatekeeperTimeout(timeout) {
		return nil, errors.New("invalid shadow Gatekeeper configuration")
	}
	identity, err := captureTrustedExecutable(trustedPath, trustedSHA256, true)
	if err != nil {
		return nil, err
	}
	coreBinarySHA256, err := currentCoreExecutableSHA256()
	if err != nil {
		return nil, errors.New("Beholder Core executable identity unavailable")
	}
	return &shadowGatekeeperClient{
		socketPath: filepath.Clean(socketPath), timeout: timeout,
		allowedUID: allowedUID, trustedProcess: identity, coreBinarySHA256: coreBinarySHA256,
	}, nil
}

func validShadowGatekeeperTimeout(timeout time.Duration) bool {
	return timeout > 0 && timeout <= maximumShadowGatekeeperRoundTrip
}

func currentCoreExecutableSHA256() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, _, digest, err := inspectTrustedExecutable(executable, false)
	if file != nil {
		_ = file.Close()
	}
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(digest[:]), nil
}

func validCoreBinarySHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (client *shadowGatekeeperClient) decide(request gatekeeperLocalRequest) (gatekeeperLocalResponse, error) {
	if client != nil {
		request.CoreBinarySHA256 = client.coreBinarySHA256
	}
	if client == nil || request.SchemaVersion != gatekeeperWireSchemaVersion ||
		(request.Mode != "shadow" && request.Mode != "authoritative") ||
		request.RequestID == "" || len(request.Prompt) == 0 || len(request.ToolInput) == 0 ||
		!json.Valid(request.ToolInput) || len(request.Evidence) == 0 || !json.Valid(request.Evidence) ||
		!validGatekeeperLocalTarget(request.ActualRequest) || !validCoreBinarySHA256(request.CoreBinarySHA256) ||
		request.HumanOutcome != nil {
		clearGatekeeperLocalRequest(&request)
		return gatekeeperLocalResponse{}, errors.New("invalid Gatekeeper decision input")
	}
	expectedRequestID := request.RequestID
	response, err := client.exchange(&request)
	if err != nil || response.EvidenceID != expectedRequestID ||
		(response.Decision == "allow" && (response.ErrorCode != nil || !response.ModelUsed)) {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper response invalid")
	}
	return response, nil
}

// submit durably stages the source context before returning, then lets the
// Gatekeeper finish the model decision asynchronously. The returned
// disposition is deliberately fail-closed and observation-only; EvidenceID is
// the handle used to correlate the unchanged human authorization path.
func (client *shadowGatekeeperClient) submit(request gatekeeperLocalRequest) (gatekeeperLocalResponse, error) {
	if client != nil {
		request.CoreBinarySHA256 = client.coreBinarySHA256
	}
	if client == nil || request.SchemaVersion != gatekeeperWireSchemaVersion || request.Mode != "shadow-submit" ||
		request.RequestID == "" || len(request.Prompt) == 0 || len(request.ToolInput) == 0 ||
		!json.Valid(request.ToolInput) || len(request.Evidence) == 0 || !json.Valid(request.Evidence) ||
		!validGatekeeperLocalTarget(request.ActualRequest) || !validCoreBinarySHA256(request.CoreBinarySHA256) ||
		request.HumanOutcome != nil {
		clearGatekeeperLocalRequest(&request)
		return gatekeeperLocalResponse{}, errors.New("invalid Gatekeeper submission input")
	}
	response, err := client.exchange(&request)
	if err != nil || response.Decision != "escalate" || response.ModelUsed ||
		response.EvidenceID == "" || response.EvidenceID != response.RequestID {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper submission response invalid")
	}
	if response.ErrorCode != nil && !safeDecisionField(*response.ErrorCode, 128, false) {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper submission error invalid")
	}
	return response, nil
}

func (client *shadowGatekeeperClient) observe(request gatekeeperLocalRequest) (gatekeeperLocalResponse, error) {
	if client != nil {
		request.CoreBinarySHA256 = client.coreBinarySHA256
	}
	if client == nil || request.SchemaVersion != gatekeeperWireSchemaVersion || request.Mode != "telemetry" ||
		request.RequestID == "" || len(request.Prompt) != 0 || len(request.ToolInput) != 0 ||
		request.TranscriptPath != "" || request.CWD != "" || len(request.Evidence) == 0 ||
		!json.Valid(request.Evidence) || !validGatekeeperLocalTarget(request.ActualRequest) ||
		!validCoreBinarySHA256(request.CoreBinarySHA256) || request.HumanOutcome != nil {
		clearGatekeeperLocalRequest(&request)
		return gatekeeperLocalResponse{}, errors.New("invalid Gatekeeper telemetry input")
	}
	response, err := client.exchange(&request)
	if err != nil || response.Decision != "escalate" || response.ModelUsed || response.ErrorCode == nil {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper telemetry response invalid")
	}
	return response, nil
}

func (client *shadowGatekeeperClient) recordOutcome(outcome humanOutcome) error {
	if client == nil || !validHumanOutcome(outcome) {
		return gatekeeperOutcomeError{code: "human-outcome-gatekeeper-input-invalid"}
	}
	response, err := client.exchangeWithin(&gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: outcome.EvidenceID,
		Mode: "outcome", CoreBinarySHA256: client.coreBinarySHA256, HumanOutcome: &outcome,
	}, humanOutcomeRoundTripTimeout)
	if err != nil {
		return gatekeeperOutcomeError{code: "human-outcome-gatekeeper-unavailable"}
	}
	if response.ErrorCode != nil {
		return gatekeeperOutcomeError{code: *response.ErrorCode}
	}
	if !response.OutcomeRecorded || response.EvidenceID != outcome.EvidenceID {
		return gatekeeperOutcomeError{code: "human-outcome-gatekeeper-response-invalid"}
	}
	return nil
}

func (client *shadowGatekeeperClient) exchange(
	request *gatekeeperLocalRequest,
) (gatekeeperLocalResponse, error) {
	if client == nil {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper client unavailable")
	}
	return client.exchangeWithin(request, client.timeout)
}

func (client *shadowGatekeeperClient) exchangeWithin(
	request *gatekeeperLocalRequest,
	timeout time.Duration,
) (gatekeeperLocalResponse, error) {
	if client == nil || request == nil {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper client unavailable")
	}
	defer clearGatekeeperLocalRequest(request)
	info, err := os.Lstat(client.socketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper socket identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != client.allowedUID {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper socket owner mismatch")
	}
	connection, err := net.DialTimeout("unix", client.socketPath, 500*time.Millisecond)
	if err != nil {
		return gatekeeperLocalResponse{}, err
	}
	defer connection.Close()
	if timeout <= 0 || timeout > maximumShadowGatekeeperRoundTrip {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper client timeout invalid")
	}
	_ = connection.SetDeadline(time.Now().Add(timeout))
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper transport identity mismatch")
	}
	peerPID, err := unixPeerPID(unixConnection)
	if err != nil {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper peer unavailable")
	}
	peer, err := captureProcessChain(peerPID)
	if err != nil || len(peer.Nodes) == 0 || peer.Nodes[0].UID != client.allowedUID ||
		peer.Nodes[0].RealUID != client.allowedUID || !client.trustedProcess.matches(peer.Nodes[0].Path) {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper executable identity mismatch")
	}
	if err := json.NewEncoder(connection).Encode(*request); err != nil {
		return gatekeeperLocalResponse{}, err
	}
	expectedRequestID := request.RequestID
	var response gatekeeperLocalResponse
	if json.NewDecoder(io.LimitReader(connection, maximumWireSize+1)).Decode(&response) != nil ||
		response.SchemaVersion != gatekeeperWireSchemaVersion ||
		(response.Decision != "allow" && response.Decision != "escalate") || response.Reason == "" ||
		response.RequestID != expectedRequestID ||
		(response.EvidenceID != "" && response.EvidenceID != expectedRequestID) ||
		(response.ErrorCode != nil && !safeDecisionField(*response.ErrorCode, 128, false)) ||
		(response.Decision == "allow" && response.ErrorCode != nil) {
		return gatekeeperLocalResponse{}, errors.New("Gatekeeper response invalid")
	}
	return response, nil
}

func validGatekeeperLocalTarget(target gatekeeperLocalTarget) bool {
	return target.SchemaVersion == decisionBindingSchemaVersion &&
		safeDecisionField(target.Surface, 96, false) &&
		safeDecisionField(target.Operation, 96, false) &&
		safeDecisionField(target.TargetKind, 96, false) &&
		safeDecisionField(target.TargetID, 1024, true) &&
		safeDecisionField(target.KeyFingerprint, 256, true) &&
		safeDecisionField(target.RemoteUser, 256, true) &&
		safeDecisionField(target.HostKeyFingerprint, 256, true) &&
		safeDecisionField(target.RequestContext, 16*1024, true) &&
		safeDecisionField(target.RequesterContext, 1024*1024, true) &&
		validCoreBinarySHA256(target.PayloadDigest) &&
		(target.RequestContext == "" || json.Valid([]byte(target.RequestContext))) &&
		(target.RequesterContext == "" || json.Valid([]byte(target.RequesterContext)))
}

func (broker *broker) configureShadowGatekeeper(client *shadowGatekeeperClient) error {
	if broker == nil || broker.trustMode != "production" || client == nil || broker.gatekeeper != nil {
		return errors.New("invalid shadow Gatekeeper registration")
	}
	broker.gatekeeper = client
	return nil
}

func (broker *broker) configureAuthority(authority *beholderAuthority) error {
	if broker == nil || broker.trustMode != "production" || authority == nil || broker.authority != nil {
		return errors.New("invalid Beholder authority registration")
	}
	broker.authority = authority
	return nil
}

func (broker *broker) runShadowGatekeeper(response *wireResponse, target operationTarget) string {
	disposition, _ := broker.runShadowGatekeeperWithEvidence(response, target)
	return disposition
}

func (broker *broker) runShadowGatekeeperWithEvidence(
	response *wireResponse,
	target operationTarget,
) (string, string) {
	if response == nil || !response.Accepted || response.Envelope == nil || response.decisionContext == nil ||
		!validOperationTarget(target) {
		if response != nil {
			response.clearTransient()
		}
		return "escalate", ""
	}
	if broker.gatekeeper == nil {
		response.Envelope.Gatekeeper = gatekeeperEvidence{
			Disposition: "escalate", ErrorCode: stringPointer("gatekeeper-not-configured"),
			Executed: false, ProductionAuthoritative: false, ModelUsed: false,
		}
		response.clearTransient()
		return "escalate", ""
	}
	evidence, err := json.Marshal(response.Envelope)
	if err != nil {
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("gatekeeper-input-build-failed")
		response.clearTransient()
		return "escalate", ""
	}
	requestID, err := newGatekeeperRequestID("shadow")
	if err != nil {
		clear(evidence)
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("gatekeeper-request-id-unavailable")
		response.clearTransient()
		return "escalate", ""
	}
	submission, err := broker.gatekeeper.submit(gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: requestID, Mode: "shadow-submit",
		Prompt:         append([]byte(nil), response.decisionContext.Prompt...),
		ToolName:       response.Envelope.Host.ToolName,
		ToolInput:      append(json.RawMessage(nil), response.decisionContext.ToolInput...),
		TranscriptPath: response.decisionTranscriptPath, CWD: response.decisionCWD,
		Evidence:      evidence,
		ActualRequest: localGatekeeperTarget(target),
	})
	clear(evidence)
	response.clearTransient()
	if err != nil {
		response.Envelope.Gatekeeper = gatekeeperEvidence{
			Disposition: "escalate", ErrorCode: stringPointer("gatekeeper-unavailable"),
			Executed: false, ProductionAuthoritative: false, ModelUsed: false,
		}
		return "escalate", ""
	}
	response.Envelope.Gatekeeper = gatekeeperEvidence{
		Disposition: "escalate", ErrorCode: submission.ErrorCode, Executed: false,
		ProductionAuthoritative: false, ModelUsed: false,
	}
	return "escalate", submission.EvidenceID
}

func (broker *broker) runGatekeeperWithEvidence(
	response *wireResponse,
	target operationTarget,
	requesterDeviceID string,
) (string, string, *beholderAuthorization) {
	defer func() {
		if response != nil && response.Envelope != nil {
			response.DecisionErrorCode = response.Envelope.Gatekeeper.ErrorCode
		}
	}()
	if broker == nil {
		if response != nil {
			response.clearTransient()
		}
		return "escalate", "", nil
	}
	if broker.authority == nil {
		disposition, evidenceID := broker.runShadowGatekeeperWithEvidence(response, target)
		return disposition, evidenceID, nil
	}
	if response == nil || !response.Accepted || response.Envelope == nil || response.decisionContext == nil ||
		!validOperationTarget(target) || !safeDecisionField(requesterDeviceID, 128, false) {
		if response != nil {
			response.clearTransient()
		}
		return "escalate", "", nil
	}
	if broker.gatekeeper == nil {
		response.Envelope.Gatekeeper = gatekeeperEvidence{
			Disposition: "escalate", ErrorCode: stringPointer("gatekeeper-not-configured"),
			Executed: false, ProductionAuthoritative: true, ModelUsed: false,
		}
		response.clearTransient()
		return "escalate", "", nil
	}
	evidence, err := json.Marshal(response.Envelope)
	if err != nil {
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("gatekeeper-input-build-failed")
		response.Envelope.Gatekeeper.ProductionAuthoritative = true
		response.clearTransient()
		return "escalate", "", nil
	}
	requestID, err := newGatekeeperRequestID("authority")
	if err != nil {
		clear(evidence)
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("gatekeeper-request-id-unavailable")
		response.Envelope.Gatekeeper.ProductionAuthoritative = true
		response.clearTransient()
		return "escalate", "", nil
	}
	decision, err := broker.gatekeeper.decide(gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: requestID, Mode: "authoritative",
		Prompt:         append([]byte(nil), response.decisionContext.Prompt...),
		ToolName:       response.Envelope.Host.ToolName,
		ToolInput:      append(json.RawMessage(nil), response.decisionContext.ToolInput...),
		TranscriptPath: response.decisionTranscriptPath, CWD: response.decisionCWD,
		Evidence: evidence, ActualRequest: localGatekeeperTarget(target),
	})
	clear(evidence)
	response.clearTransient()
	if err != nil {
		response.Envelope.Gatekeeper = gatekeeperEvidence{
			Disposition: "escalate", ErrorCode: stringPointer("gatekeeper-unavailable"),
			Executed: false, ProductionAuthoritative: true, ModelUsed: false,
		}
		return "escalate", "", nil
	}
	called := decision.ModelCalled
	response.ModelCalled = &called
	response.Envelope.Gatekeeper = gatekeeperEvidence{
		Disposition: decision.Decision, ErrorCode: decision.ErrorCode,
		Executed: decision.ModelCalled, ProductionAuthoritative: true, ModelUsed: decision.ModelUsed,
	}
	if decision.Decision != "allow" {
		return "escalate", decision.EvidenceID, nil
	}
	// A human interrupt or kernel exit during the model call invalidates the
	// associated observation before any new authority can be signed.
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.expireLocked(broker.now().UTC())
	liveRef := broker.claimRefByTool[response.contextToolUseRef]
	live := broker.claimsByToolRef[liveRef]
	if live == nil || live.contextTurnRef != response.contextTurnRef || live.conflictCode != "" || live.executionRootRef == "" {
		response.Envelope.Gatekeeper.Disposition = "escalate"
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("execution-context-ended")
		return "escalate", decision.EvidenceID, nil
	}
	authorization, err := broker.authority.authorize(
		decision.EvidenceID,
		requesterDeviceID,
		target.PayloadDigest,
	)
	if err != nil {
		response.Envelope.Gatekeeper.Disposition = "escalate"
		response.Envelope.Gatekeeper.ErrorCode = stringPointer("authority-signing-failed")
		return "escalate", decision.EvidenceID, nil
	}
	return "allow", decision.EvidenceID, authorization
}

func (broker *broker) recordShadowEscalation(response *wireResponse, target operationTarget) {
	_ = broker.recordShadowEscalationWithEvidence(response, target)
}

func (broker *broker) recordShadowEscalationWithEvidence(
	response *wireResponse,
	target operationTarget,
) string {
	if response == nil {
		return ""
	}
	defer response.clearTransient()
	if broker == nil || broker.gatekeeper == nil || response.Accepted || response.Envelope == nil ||
		!validOperationTarget(target) {
		return ""
	}
	evidence, err := json.Marshal(response.Envelope)
	if err != nil {
		return ""
	}
	defer clear(evidence)
	requestID, err := newGatekeeperRequestID("telemetry")
	if err != nil {
		return ""
	}
	observed, err := broker.gatekeeper.observe(gatekeeperLocalRequest{
		SchemaVersion: gatekeeperWireSchemaVersion, RequestID: requestID, Mode: "telemetry",
		ToolName: response.Envelope.Host.ToolName, Evidence: evidence,
		ActualRequest: localGatekeeperTarget(target),
	})
	if err != nil {
		return ""
	}
	return observed.EvidenceID
}

func newGatekeeperRequestID(prefix string) (string, error) {
	requestIDBytes := make([]byte, 16)
	if _, err := rand.Read(requestIDBytes); err != nil {
		return "", err
	}
	requestID := prefix + "-" + hex.EncodeToString(requestIDBytes)
	clear(requestIDBytes)
	return requestID, nil
}

func localGatekeeperTarget(target operationTarget) gatekeeperLocalTarget {
	return gatekeeperLocalTarget{
		SchemaVersion: target.SchemaVersion, Surface: target.Surface, Operation: target.Operation,
		TargetKind: target.TargetKind, TargetID: target.TargetID,
		KeyFingerprint: target.KeyFingerprint, RemoteUser: target.RemoteUser,
		HostKeyFingerprint: target.HostKeyFingerprint,
		RequestContext:     target.RequestContext,
		RequesterContext:   target.RequesterContext,
		PayloadDigest:      target.PayloadDigest,
	}
}

func clearGatekeeperLocalRequest(request *gatekeeperLocalRequest) {
	if request == nil {
		return
	}
	clear(request.Prompt)
	request.Prompt = nil
	clear(request.ToolInput)
	request.ToolInput = nil
	clear(request.Evidence)
	request.Evidence = nil
	request.CoreBinarySHA256 = ""
	request.TranscriptPath = ""
	request.CWD = ""
	request.ActualRequest.TargetID = ""
	request.ActualRequest.KeyFingerprint = ""
	request.ActualRequest.RemoteUser = ""
	request.ActualRequest.HostKeyFingerprint = ""
	request.ActualRequest.RequestContext = ""
	request.ActualRequest.RequesterContext = ""
	request.ActualRequest.PayloadDigest = ""
	request.HumanOutcome = nil
}

func validHumanOutcome(outcome humanOutcome) bool {
	if outcome.SchemaVersion != 1 || outcome.RecordType != "beholder_human_outcome" ||
		!safeDecisionField(outcome.EvidenceID, 96, false) || outcome.ObservedAt.IsZero() ||
		!validCoreBinarySHA256(outcome.OperationTargetSHA256) ||
		!oneOfOutcome(outcome.AuthorizationSource, "beholder-authoritative", "pwa-interactive", "remembered-grant", "local-fallback", "not-requested", "unknown") ||
		!oneOfOutcome(outcome.Decision, "approved", "rejected", "timed_out", "expired", "error", "not_requested", "unknown") ||
		(outcome.OneNodRequestID != nil && !safeDecisionField(*outcome.OneNodRequestID, 256, false)) ||
		!safeDecisionField(outcome.FailureStage, 96, true) || len(outcome.StatusTimeline) > 256 {
		return false
	}
	for _, status := range outcome.StatusTimeline {
		if !safeDecisionField(status.Status, 96, false) || status.ObservedAt.IsZero() {
			return false
		}
	}
	return true
}

func oneOfOutcome(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
