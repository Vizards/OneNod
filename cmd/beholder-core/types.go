package main

import (
	"encoding/json"
	"os"
	"time"
)

const (
	protocolSchemaVersion = 1
	featureSchemaVersion  = 1
	maximumWireSize       = 2 * 1024 * 1024
)

type toolInputFeatures struct {
	SchemaVersion           int      `json:"schema_version"`
	Observed                bool     `json:"observed"`
	CommandLengthBucket     string   `json:"command_length_bucket"`
	TokenCountBucket        string   `json:"token_count_bucket"`
	PathTokenCountBucket    string   `json:"path_token_count_bucket"`
	URLTokenCountBucket     string   `json:"url_token_count_bucket"`
	FlagTokenCountBucket    string   `json:"flag_token_count_bucket"`
	Families                []string `json:"families"`
	HasPipe                 bool     `json:"has_pipe"`
	HasRedirection          bool     `json:"has_redirection"`
	HasChaining             bool     `json:"has_chaining"`
	HasBackground           bool     `json:"has_background"`
	HasSubshell             bool     `json:"has_subshell"`
	HasEnvironmentExpansion bool     `json:"has_environment_expansion"`
	HasCommandSubstitution  bool     `json:"has_command_substitution"`
	RawCommandStored        bool     `json:"raw_command_stored"`
	RawTokensStored         bool     `json:"raw_tokens_stored"`
}

type hostObservation struct {
	SessionID         string            `json:"session_id"`
	TurnID            string            `json:"turn_id"`
	ToolUseID         string            `json:"tool_use_id"`
	TranscriptPath    string            `json:"transcript_path"`
	CWD               string            `json:"cwd"`
	HookEventName     string            `json:"hook_event_name"`
	ToolName          string            `json:"tool_name"`
	Model             string            `json:"model"`
	PermissionMode    string            `json:"permission_mode"`
	ObservedAt        string            `json:"observed_at"`
	ToolInput         json.RawMessage   `json:"tool_input"`
	ToolInputFeatures toolInputFeatures `json:"tool_input_features"`
}

type promptObservation struct {
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	HookEventName  string `json:"hook_event_name"`
	Model          string `json:"model"`
	PermissionMode string `json:"permission_mode"`
	ObservedAt     string `json:"observed_at"`
	Prompt         []byte `json:"prompt"`
}

type environmentPresence struct {
	CodexThreadID      bool `json:"codex_thread_id"`
	CodexSessionID     bool `json:"codex_session_id"`
	ThreadSessionEqual bool `json:"thread_session_equal"`
	SSHAuthSock        bool `json:"ssh_auth_sock"`
	GitEnvironment     bool `json:"git_environment"`
	PermissionProfile  bool `json:"codex_permission_profile"`
}

type requestObservation struct {
	ThreadID            string              `json:"thread_id"`
	Nonce               string              `json:"nonce"`
	Surface             string              `json:"surface"`
	Operation           string              `json:"operation"`
	TargetKind          string              `json:"target_kind"`
	TargetID            string              `json:"target_id,omitempty"`
	ObservedAt          string              `json:"observed_at"`
	EnvironmentPresence environmentPresence `json:"environment_presence"`
}

type wireRequest struct {
	Lifecycle         *lifecycleObservation `json:"lifecycle,omitempty"`
	TraceID           string                `json:"trace_id,omitempty"`
	SchemaVersion     int                   `json:"schema_version"`
	Kind              string                `json:"kind"`
	ThreadID          string                `json:"thread_id,omitempty"`
	ToolRef           string                `json:"tool_ref,omitempty"`
	Purpose           string                `json:"purpose,omitempty"`
	Nonce             string                `json:"nonce,omitempty"`
	Binding           string                `json:"binding,omitempty"`
	Operation         *operationTarget      `json:"operation_target,omitempty"`
	EvidenceID        string                `json:"evidence_id,omitempty"`
	HumanOutcome      *humanOutcome         `json:"human_outcome,omitempty"`
	Host              *hostObservation      `json:"host,omitempty"`
	Prompt            *promptObservation    `json:"prompt,omitempty"`
	Request           *requestObservation   `json:"request,omitempty"`
	RequesterDeviceID string                `json:"requester_device_id,omitempty"`
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

type wireResponse struct {
	ModelCalled            *bool                     `json:"model_called,omitempty"`
	DecisionErrorCode      *string                   `json:"decision_error_code,omitempty"`
	SchemaVersion          int                       `json:"schema_version"`
	Accepted               bool                      `json:"accepted"`
	Disposition            string                    `json:"disposition,omitempty"`
	AgentSocket            string                    `json:"agent_socket,omitempty"`
	ToolRef                string                    `json:"tool_ref,omitempty"`
	Binding                string                    `json:"binding,omitempty"`
	ErrorCode              *string                   `json:"error_code"`
	EvidenceID             string                    `json:"evidence_id,omitempty"`
	Authorization          *beholderAuthorization    `json:"authorization,omitempty"`
	Envelope               *evidenceEnvelope         `json:"envelope,omitempty"`
	contextTurnRef         string                    `json:"-"`
	contextToolUseRef      string                    `json:"-"`
	decisionContext        *transientDecisionContext `json:"-"`
	decisionTranscriptPath string                    `json:"-"`
	decisionCWD            string                    `json:"-"`
}

type outcomeStatus struct {
	Status     string    `json:"status"`
	ObservedAt time.Time `json:"observed_at"`
}

type humanOutcome struct {
	SchemaVersion         int             `json:"schema_version"`
	RecordType            string          `json:"record_type"`
	EvidenceID            string          `json:"evidence_id"`
	OperationTargetSHA256 string          `json:"operation_target_sha256"`
	OneNodRequestID       *string         `json:"onenod_request_id"`
	AuthorizationSource   string          `json:"authorization_source"`
	Decision              string          `json:"decision"`
	StatusTimeline        []outcomeStatus `json:"status_timeline"`
	OperationCompleted    bool            `json:"operation_completed"`
	CredentialDelivered   bool            `json:"credential_delivered"`
	FailureStage          string          `json:"failure_stage,omitempty"`
	ObservedAt            time.Time       `json:"observed_at"`
}

func (response *wireResponse) clearTransient() {
	if response == nil {
		return
	}
	if response.decisionContext != nil {
		response.decisionContext.clear()
	}
	response.decisionContext = nil
	response.decisionTranscriptPath = ""
	response.decisionCWD = ""
}

type featureDescriptor struct {
	Name         string `json:"name"`
	Source       string `json:"source"`
	TrustClass   string `json:"trust_class"`
	PrivacyClass string `json:"privacy_class"`
	Observed     bool   `json:"observed"`
}

type evidenceEnvelope struct {
	SchemaVersion        int                    `json:"schema_version"`
	FeatureSchemaVersion int                    `json:"feature_schema_version"`
	Collector            string                 `json:"collector"`
	DecisionComponent    string                 `json:"decision_component"`
	Collection           collectionEvidence     `json:"collection"`
	Gatekeeper           gatekeeperEvidence     `json:"gatekeeper"`
	Attribution          attributionEvidence    `json:"attribution"`
	Host                 hostEvidence           `json:"host"`
	RequestProcess       requestProcessEvidence `json:"request_process"`
	Request              requestEvidence        `json:"request"`
	Workspace            workspaceEvidence      `json:"workspace"`
	Temporal             temporalEvidence       `json:"temporal"`
	EnvironmentPresence  environmentPresence    `json:"environment_presence"`
	RecentOpKinds        []string               `json:"recent_op_kinds"`
	Features             []featureDescriptor    `json:"features"`
	Privacy              envelopePrivacy        `json:"privacy"`
}

type collectionEvidence struct {
	Status         string  `json:"status"`
	ErrorCode      *string `json:"error_code"`
	BrokerEpochRef string  `json:"broker_epoch_ref"`
	StateStorage   string  `json:"state_storage"`
}

type gatekeeperEvidence struct {
	Disposition             string  `json:"disposition"`
	ErrorCode               *string `json:"error_code"`
	Executed                bool    `json:"executed"`
	ProductionAuthoritative bool    `json:"production_authoritative"`
	ModelUsed               bool    `json:"model_used"`
}

type attributionEvidence struct {
	Result                    string   `json:"result"`
	BindingMethod             string   `json:"binding_method,omitempty"`
	LateBindingCandidateCount int      `json:"late_binding_candidate_count"`
	ThreadRef                 string   `json:"thread_ref,omitempty"`
	TurnRef                   string   `json:"turn_ref,omitempty"`
	ToolUseRef                string   `json:"tool_use_ref,omitempty"`
	SessionCandidateCount     int      `json:"session_candidate_count"`
	SessionMetadataMatched    bool     `json:"session_metadata_matched"`
	ToolRefMatched            bool     `json:"tool_ref_matched"`
	RequestThreadMatched      bool     `json:"request_thread_matched"`
	ExecutionRootMatched      bool     `json:"execution_root_matched"`
	ExecutionRootRequestIndex int      `json:"execution_root_request_index"`
	RuntimeBindingCount       int      `json:"runtime_binding_count"`
	PendingInvocationCount    int      `json:"pending_invocation_count"`
	RequestNonceFresh         bool     `json:"request_nonce_fresh"`
	EvidenceKinds             []string `json:"evidence_kinds"`
	Conflicts                 []string `json:"conflicts"`
}

type hostEvidence struct {
	HookEventName          string            `json:"hook_event_name"`
	ToolName               string            `json:"tool_name"`
	Model                  string            `json:"model"`
	PermissionMode         string            `json:"permission_mode"`
	CWDRelation            string            `json:"cwd_relation"`
	PeerAncestryDepth      int               `json:"peer_ancestry_depth"`
	PeerAncestryRoles      []string          `json:"peer_ancestry_roles"`
	ExecutableOwnerClass   string            `json:"executable_owner_class"`
	ExecutableUserWritable bool              `json:"executable_user_writable"`
	CodeIdentityVerified   bool              `json:"code_identity_verified"`
	ToolInputFeatures      toolInputFeatures `json:"tool_input_features"`
}

type requestProcessEvidence struct {
	PIDStartObserved       bool     `json:"pid_start_observed"`
	UIDMatchedBroker       bool     `json:"uid_matched_broker"`
	AncestryDepth          int      `json:"ancestry_depth"`
	AncestryRoles          []string `json:"ancestry_roles"`
	ExecutableOwnerClass   string   `json:"executable_owner_class"`
	ExecutableUserWritable bool     `json:"executable_user_writable"`
	CodexRuntimeObserved   bool     `json:"codex_runtime_observed"`
	DesktopHostObserved    bool     `json:"desktop_host_observed"`
	RawPIDsStored          bool     `json:"raw_pids_stored"`
	ExecutablePathsStored  bool     `json:"executable_paths_stored"`
}

type requestEvidence struct {
	Surface                 string `json:"surface"`
	Operation               string `json:"operation"`
	TargetKind              string `json:"target_kind"`
	TargetRef               string `json:"target_ref,omitempty"`
	ReadLike                bool   `json:"read_like"`
	MutationLike            bool   `json:"mutation_like"`
	SignatureLike           bool   `json:"signature_like"`
	NetworkLike             bool   `json:"network_like"`
	RequesterReasonAccepted bool   `json:"requester_reason_accepted"`
}

type workspaceEvidence struct {
	CWDRelation        string `json:"cwd_relation"`
	RepositoryObserved bool   `json:"repository_observed"`
	RepositoryRef      string `json:"repository_ref,omitempty"`
	RepositoryKind     string `json:"repository_kind"`
	HeadState          string `json:"head_state"`
	HeadRef            string `json:"head_ref,omitempty"`
	CWDUserWritable    bool   `json:"cwd_user_writable"`
	RawPathsStored     bool   `json:"raw_paths_stored"`
}

type temporalEvidence struct {
	HostObservationAgeMS int64  `json:"host_observation_age_ms"`
	AgeBucket            string `json:"age_bucket"`
	ObservationLifetime  string `json:"observation_lifetime"`
	ReplayRetention      string `json:"replay_retention"`
}

type envelopePrivacy struct {
	RawPromptStored        bool `json:"raw_prompt_stored"`
	RawToolInputStored     bool `json:"raw_tool_input_stored"`
	RawToolOutputStored    bool `json:"raw_tool_output_stored"`
	RawTranscriptStored    bool `json:"raw_transcript_stored"`
	RawEnvironmentStored   bool `json:"raw_environment_stored"`
	RawIDsStored           bool `json:"raw_ids_stored"`
	CredentialMaterialSeen bool `json:"credential_material_seen"`
}

type brokerSummary struct {
	SchemaVersion          int            `json:"schema_version"`
	Connections            int            `json:"connections"`
	HostRegistrations      int            `json:"host_registrations"`
	ExecutionRegistrations int            `json:"execution_registrations"`
	PromptRegistrations    int            `json:"prompt_registrations"`
	RequestChecks          int            `json:"request_checks"`
	ConnectionErrors       map[string]int `json:"connection_errors,omitempty"`
	StatePersisted         bool           `json:"state_persisted"`
	RawContentStored       bool           `json:"raw_content_stored"`
	ErrorCode              *string        `json:"error_code"`
}

type hostClaim struct {
	runtimeIdentity       processIdentity
	executionIdentity     processIdentity
	transcriptInfo        os.FileInfo
	threadRef             string
	turnRef               string
	toolUseRef            string
	hookAnchorRef         string
	executionRootRef      string
	runtimeBindingRef     string
	registeredAt          time.Time
	returnedAt            time.Time
	sessionCandidateCount int
	metadataMatched       bool
	hostCWD               string
	transcriptPath        string
	recentOps             []string
	host                  hostEvidence
	contextTurnRef        string
	contextToolUseRef     string
	toolRef               string
	bindingMethod         string
	lateBindingCandidates int
	conflictCode          string
}
