package main

import (
	"encoding/json"
	"time"
)

const (
	gatekeeperWireSchemaVersion = 1
	maximumLocalWireSize        = 4 * 1024 * 1024
	maximumModelResponseSize    = 8 * 1024 * 1024
)

type confirmedConfig struct {
	Retrieval struct {
		Enabled              bool   `json:"enabled"`
		MaximumRounds        int    `json:"maximum_rounds"`
		MaximumParallelTools int    `json:"maximum_parallel_tools"`
		MaximumCallsPerRound int    `json:"maximum_calls_per_round"`
		PageCharacters       int    `json:"page_characters"`
		MaximumSnapshotBytes int    `json:"maximum_snapshot_bytes"`
		MaximumRequestBytes  int    `json:"maximum_request_bytes"`
		PrefetchHistory      bool   `json:"prefetch_history"`
		GeneratedSummary     bool   `json:"generated_summary"`
		ToolChoice           string `json:"tool_choice"`
		PersistEveryRound    bool   `json:"persist_every_round"`
	} `json:"retrieval"`
	SchemaVersion int    `json:"schema_version"`
	RecordType    string `json:"record_type"`
	ConfirmedAt   string `json:"confirmed_at"`
	Revision      struct {
		ID                            string `json:"id"`
		SupersedesConfigSHA256        string `json:"supersedes_config_sha256"`
		ContextTreatmentExpanded      bool   `json:"context_treatment_expanded"`
		AllUnlistedAI0FieldsUnchanged bool   `json:"all_unlisted_e2_ai0_fields_unchanged"`
	} `json:"revision"`
	Provider struct {
		Name                           string `json:"name"`
		Route                          string `json:"route"`
		CallerOrigin                   string `json:"caller_origin"`
		BaseURL                        string `json:"base_url"`
		APIRoute                       string `json:"api_route"`
		UpstreamOrigin                 string `json:"upstream_origin"`
		UpstreamMappingFixedForE2      bool   `json:"upstream_mapping_fixed_for_e2"`
		RequestResponseBodyPersistence bool   `json:"request_response_body_persistence"`
	} `json:"provider"`
	Model struct {
		PrimaryID         string   `json:"primary_id"`
		DisabledModels    []string `json:"also_available_but_disabled"`
		AutomaticFallback bool     `json:"automatic_fallback"`
	} `json:"model"`
	Authentication struct {
		Scheme          string `json:"scheme"`
		OneNodReference string `json:"onenod_reference"`
		SecretStorage   string `json:"secret_storage"`
	} `json:"authentication"`
	Invocation struct {
		Protocol           string `json:"protocol"`
		IndependentHTTPS   bool   `json:"independent_stateless_https"`
		ContentType        string `json:"content_type"`
		Stream             bool   `json:"stream"`
		TemperatureOmitted bool   `json:"temperature_omitted"`
		MaxTokensOmitted   bool   `json:"max_tokens_omitted"`
		TimeoutMS          int    `json:"timeout_ms"`
		AutomaticRetries   int    `json:"automatic_retries"`
		MaximumConcurrency int    `json:"maximum_concurrency"`
		Thinking           struct {
			Type string `json:"type"`
		} `json:"thinking"`
		ReasoningEffortOmitted bool `json:"reasoning_effort_omitted"`
		ResponseFormat         struct {
			Type string `json:"type"`
		} `json:"response_format"`
	} `json:"invocation"`
	Comparison struct {
		Enabled  bool   `json:"enabled"`
		Variant  string `json:"variant"`
		ModelID  string `json:"model_id"`
		Thinking struct {
			Type string `json:"type"`
		} `json:"thinking"`
		ParallelWithPrimary      bool   `json:"parallel_with_primary"`
		AsynchronousAfterPrimary bool   `json:"asynchronous_after_primary"`
		TimeoutMS                int    `json:"timeout_ms"`
		SameContextAndPrompt     bool   `json:"same_context_and_prompt"`
		ObservabilityOnly        bool   `json:"observability_only"`
		CanAffectHumanApproval   bool   `json:"can_affect_human_approval"`
		CanAffectCredentialFlow  bool   `json:"can_affect_credential_release"`
		MaximumParallelPairs     int    `json:"maximum_parallel_pairs"`
		SaturationBehavior       string `json:"saturation_behavior,omitempty"`
	} `json:"comparison"`
	Authority struct {
		Mode                         string `json:"mode"`
		PrimaryCanReleaseCredential  bool   `json:"primary_can_release_credential"`
		AllowBehavior                string `json:"allow_behavior"`
		EscalateBehavior             string `json:"escalate_behavior"`
		FailureBehavior              string `json:"failure_behavior"`
		AttestationLifetimeSeconds   int    `json:"attestation_lifetime_seconds"`
		ComparisonCanAffectAuthority bool   `json:"comparison_can_affect_authority"`
	} `json:"authority"`
	Messages struct {
		ModelInputSchemaVersion             int      `json:"model_input_schema_version"`
		TopLevelProvenanceDomains           []string `json:"top_level_provenance_domains"`
		UserMessageOrder                    string   `json:"user_message_order"`
		LatestMessageIndexPointsToLast      bool     `json:"latest_message_index_points_to_last"`
		SessionOrdinalAuthoritativeForOrder bool     `json:"session_ordinal_authoritative_for_order"`
		ComparisonRule                      string   `json:"comparison_rule"`
	} `json:"messages"`
	Response struct {
		ContentPath                  string   `json:"content_path"`
		ReasoningContentPath         string   `json:"reasoning_content_path"`
		AllowedDecisions             []string `json:"allowed_decisions"`
		RequiredKeys                 []string `json:"required_keys"`
		OptionalDiagnosticKeys       []string `json:"optional_diagnostic_keys"`
		AcceptUnknownKeys            bool     `json:"accept_unknown_keys"`
		AllowedScopeResolutions      []string `json:"allowed_scope_resolutions"`
		AllowedEvidenceRefRoots      []string `json:"allowed_evidence_ref_roots"`
		ReasoningContentRequired     bool     `json:"reasoning_content_required"`
		AcceptValidDecisionOnNonStop bool     `json:"accept_valid_decision_on_non_stop_finish_reason"`
		InvalidBehavior              string   `json:"invalid_or_timeout_behavior"`
		RawResponsePersisted         bool     `json:"raw_response_persisted"`
		RawReasoningContentExposed   bool     `json:"raw_reasoning_content_exposed"`
		RawReasoningContentPersisted bool     `json:"raw_reasoning_content_persisted"`
		SafeReasoningTelemetry       []string `json:"safe_reasoning_telemetry"`
	} `json:"response"`
	Observability struct {
		Contract                            string `json:"contract"`
		SchemaVersion                       int    `json:"schema_version"`
		EvidenceRoot                        string `json:"evidence_root"`
		DirectoryMode                       string `json:"directory_mode"`
		FileMode                            string `json:"file_mode"`
		LocalOnly                           bool   `json:"local_only"`
		AutomaticRetentionOrSampling        bool   `json:"automatic_retention_or_sampling"`
		SourceContextPersisted              bool   `json:"source_context_persisted"`
		ContextSelectionTracePersisted      bool   `json:"context_selection_trace_persisted"`
		ExactModelRequestBodyPersisted      bool   `json:"exact_model_request_body_persisted"`
		CompleteProviderResponsePersisted   bool   `json:"complete_bounded_provider_response_persisted"`
		HumanOutcomeAutomaticallyCorrelated bool   `json:"human_outcome_automatically_correlated"`
		EvidenceIDIsAuthority               bool   `json:"evidence_id_is_authority"`
		IndexAppendOnly                     bool   `json:"index_append_only"`
		ActualCredentialMaterialPersisted   bool   `json:"actual_credential_material_persisted"`
		AuthorizationHeaderPersisted        bool   `json:"authorization_header_persisted"`
		PollOrDecisionCapabilityPersisted   bool   `json:"poll_or_decision_capability_persisted"`
		RawSigningMaterialPersisted         bool   `json:"raw_signing_payload_or_signature_blob_persisted"`
		ComparisonRequestResponsePersisted  bool   `json:"comparison_request_response_persisted"`
	} `json:"observability"`
}

// localDecisionRequest is the private Core -> Gatekeeper wire contract. Raw
// prompt and tool input stay inside these two local processes and are cleared
// after one decision. TranscriptPath is a local context source and is never
// copied into the external model request. Telemetry mode contains only the
// already privacy-safe evidence and target and never calls the model.
type localDecisionRequest struct {
	decisionDeadline time.Time
	SchemaVersion    int             `json:"schema_version"`
	RequestID        string          `json:"request_id"`
	Mode             string          `json:"mode"`
	Prompt           []byte          `json:"prompt"`
	ToolName         string          `json:"tool_name"`
	ToolInput        json.RawMessage `json:"tool_input,omitempty"`
	TranscriptPath   string          `json:"transcript_path"`
	CWD              string          `json:"cwd"`
	Evidence         json.RawMessage `json:"evidence"`
	ActualRequest    operationTarget `json:"actual_request"`
	CoreBinarySHA256 string          `json:"core_binary_sha256,omitempty"`
	HumanOutcome     *humanOutcome   `json:"human_outcome,omitempty"`
}

type operationTarget struct {
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

type localDecisionResponse struct {
	ModelRounds            int      `json:"-"`
	EvidenceRefDiagnostics []string `json:"-"`
	ToolCalls              int      `json:"-"`
	ToolLatencyMS          float64  `json:"-"`
	SchemaVersion          int      `json:"schema_version"`
	RequestID              string   `json:"request_id"`
	Decision               string   `json:"decision"`
	Reason                 string   `json:"reason"`
	ErrorCode              *string  `json:"error_code"`
	ModelUsed              bool     `json:"model_used"`
	ModelCalled            bool     `json:"model_called"`
	ModelTransport         string   `json:"model_transport,omitempty"`
	TransportDetail        *string  `json:"transport_error_detail,omitempty"`
	ResponseShape          string   `json:"response_shape,omitempty"`
	ScopeResolution        string   `json:"scope_resolution,omitempty"`
	EvidenceRefs           []string `json:"evidence_refs,omitempty"`
	ReasoningPresent       bool     `json:"reasoning_present"`
	ReasoningBytes         int      `json:"reasoning_bytes"`
	ReasoningTokens        int      `json:"reasoning_tokens"`
	FinishReason           string   `json:"finish_reason,omitempty"`
	LatencyMS              int64    `json:"latency_ms"`
	EvidenceID             string   `json:"evidence_id,omitempty"`
	OutcomeRecorded        bool     `json:"outcome_recorded,omitempty"`
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

type sourceText struct {
	Source     string `json:"source"`
	TrustClass string `json:"trust_class"`
	Ordinal    int    `json:"session_ordinal"`
	Relation   string `json:"temporal_relation"`
	Text       string `json:"text"`
}

type recentToolContext struct {
	CallID        string `json:"-"`
	Source        string `json:"source"`
	TrustClass    string `json:"trust_class"`
	CallOrdinal   int    `json:"call_session_ordinal"`
	ResultOrdinal int    `json:"result_session_ordinal"`
	Relation      string `json:"temporal_relation"`
	Name          string `json:"name"`
	Input         string `json:"input,omitempty"`
	Output        string `json:"output,omitempty"`
}

type requesterArgument struct {
	Index         int    `json:"index,omitempty"`
	Value         string `json:"value"`
	Redacted      bool   `json:"redacted"`
	RedactionRule string `json:"redaction_rule,omitempty"`
}

type requesterEnvironmentValue struct {
	Name          string `json:"name"`
	Value         string `json:"value,omitempty"`
	Redacted      bool   `json:"redacted"`
	RedactionRule string `json:"redaction_rule,omitempty"`
}

type requesterExecutionContext struct {
	Source              string                      `json:"source"`
	TrustClass          string                      `json:"trust_class"`
	Executable          string                      `json:"executable,omitempty"`
	ExecutableSHA256    string                      `json:"executable_sha256,omitempty"`
	Arguments           []requesterArgument         `json:"arguments"`
	CWD                 string                      `json:"cwd,omitempty"`
	GatewayOrigin       string                      `json:"gateway_origin,omitempty"`
	ApprovalTimeoutMS   int                         `json:"approval_timeout_ms,omitempty"`
	PollIntervalMS      int                         `json:"poll_interval_ms,omitempty"`
	RelevantEnvironment []requesterEnvironmentValue `json:"relevant_environment"`
	ThreadIDPresent     bool                        `json:"codex_thread_id_present"`
	SessionIDPresent    bool                        `json:"codex_session_id_present"`
	ThreadSessionEqual  bool                        `json:"codex_thread_session_equal"`
}

type contextCoverage struct {
	Selection      string                    `json:"selection"`
	BoundaryFound  bool                      `json:"turn_anchor_found"`
	ByteBudget     int                       `json:"retained_text_byte_budget"`
	HumanBytes     int                       `json:"human_text_bytes"`
	OtherBytes     int                       `json:"other_text_bytes"`
	OmittedRecords int                       `json:"omitted_for_budget"`
	Summary        []contextCandidateSummary `json:"event_selection_summary"`
	ModelDelivery  *modelContextDelivery     `json:"model_delivery,omitempty"`
}

// Capture accounting remains intact for local evidence. ModelDelivery records
// the separate projection actually sent to the provider.
type modelContextDelivery struct {
	Profile                     string `json:"profile"`
	CompletedToolRecordsOmitted int    `json:"completed_tool_records_omitted"`
}

type workspaceContext struct {
	CWDSource           string            `json:"cwd_source,omitempty"`
	SessionCWD          string            `json:"session_cwd,omitempty"`
	WorkspaceRoots      []string          `json:"session_declared_workspace_roots,omitempty"`
	RepositoryScope     string            `json:"repository_scope,omitempty"`
	CWD                 string            `json:"cwd"`
	RepositoryRoot      string            `json:"repository_root,omitempty"`
	Branch              string            `json:"branch,omitempty"`
	Head                string            `json:"head,omitempty"`
	Remote              string            `json:"remote,omitempty"`
	ResolvedExecutables map[string]string `json:"resolved_executables,omitempty"`
}

type externalDecisionInput struct {
	retrieval     *retrievalInput
	SchemaVersion int `json:"schema_version"`
	HumanIntent   struct {
		CurrentPrompt        string       `json:"current_prompt"`
		CurrentPromptOrdinal int          `json:"current_prompt_session_ordinal,omitempty"`
		PriorMessages        []sourceText `json:"prior_messages"`
	} `json:"human_intent"`
	AgentContext struct {
		PriorTaskTrajectory        []sourceText `json:"prior_task_trajectory"`
		CurrentExecutionTrajectory []sourceText `json:"current_execution_trajectory"`
		AmbientContext             []sourceText `json:"ambient_context"`
	} `json:"agent_context"`
	ToolCall struct {
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"tool_call"`
	CompletedToolActivity []recentToolContext       `json:"completed_tool_activity"`
	Coverage              contextCoverage           `json:"context_coverage"`
	Environment           workspaceContext          `json:"environment"`
	RequesterContext      requesterExecutionContext `json:"requester_context"`
	CoreEvidence          json.RawMessage           `json:"core_evidence"`
	ActualRequest         externalTarget            `json:"actual_request"`
}

type externalTarget struct {
	Surface            string          `json:"surface"`
	Operation          string          `json:"operation"`
	TargetKind         string          `json:"target_kind"`
	TargetID           json.RawMessage `json:"target_id,omitempty"`
	TargetAlias        string          `json:"target_alias,omitempty"`
	KeyFingerprint     string          `json:"key_fingerprint,omitempty"`
	RemoteUser         string          `json:"remote_user,omitempty"`
	HostKeyFingerprint string          `json:"host_key_fingerprint,omitempty"`
	RequestContext     json.RawMessage `json:"request_context,omitempty"`
}

type contextMetrics struct {
	PriorHumanMessages   int `json:"prior_human_messages"`
	PriorAgentMessages   int `json:"prior_agent_messages"`
	CurrentAgentMessages int `json:"current_agent_messages"`
	AmbientContext       int `json:"ambient_context"`
	CompletedTools       int `json:"completed_tools"`
	InputBytes           int `json:"input_bytes"`
	OmittedUnsafe        int `json:"omitted_unsafe_context"`
}

type contextCandidate struct {
	Ordinal        int             `json:"ordinal"`
	Type           string          `json:"type"`
	Source         string          `json:"source"`
	Role           string          `json:"role,omitempty"`
	Phase          string          `json:"phase,omitempty"`
	CallID         string          `json:"call_id,omitempty"`
	Name           string          `json:"name,omitempty"`
	Content        string          `json:"content,omitempty"`
	Input          string          `json:"input,omitempty"`
	Output         string          `json:"output,omitempty"`
	Disposition    string          `json:"disposition"`
	Reason         string          `json:"reason"`
	RawEventBytes  int             `json:"raw_event_bytes,omitempty"`
	RawEventSHA256 string          `json:"raw_event_sha256,omitempty"`
	RawEvent       json.RawMessage `json:"raw_event,omitempty"`
	RawEventText   string          `json:"raw_event_text,omitempty"`
}

type contextCandidateSummary struct {
	Type         string `json:"type"`
	Role         string `json:"role,omitempty"`
	Phase        string `json:"phase,omitempty"`
	Disposition  string `json:"disposition"`
	Reason       string `json:"reason"`
	Count        int    `json:"count"`
	FirstOrdinal int    `json:"first_ordinal"`
	LastOrdinal  int    `json:"last_ordinal"`
}

type transcriptSnapshot struct {
	Source               string    `json:"source"`
	TaskID               string    `json:"codex_task_id,omitempty"`
	CaptureBoundary      string    `json:"capture_boundary,omitempty"`
	FileBytesAtOpen      int64     `json:"file_bytes_at_open"`
	FileModifiedAtOpen   time.Time `json:"file_modified_at_open"`
	ScannedBytes         int64     `json:"scanned_bytes"`
	ScannedEvents        int       `json:"scanned_events"`
	ScannedContentSHA256 string    `json:"scanned_content_sha256"`
	ObservedCandidates   int       `json:"observed_candidates"`
	RetainedCandidates   int       `json:"retained_candidates"`
}

type evidenceEnvironmentEntry struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Redacted bool   `json:"redacted"`
}

type evidenceProcessContext struct {
	Executable       string   `json:"executable"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	Arguments        []string `json:"arguments"`
	CWD              string   `json:"cwd"`
	PID              int      `json:"pid"`
	ParentPID        int      `json:"parent_pid"`
	UID              int      `json:"uid"`
	EffectiveUID     int      `json:"effective_uid"`
}

type sourceContextEvidence struct {
	Retrieval             *retrievalSourceEvidence     `json:"retrieval,omitempty"`
	SchemaVersion         int                          `json:"schema_version"`
	RecordType            string                       `json:"record_type"`
	EvidenceID            string                       `json:"evidence_id"`
	CapturedAt            time.Time                    `json:"captured_at"`
	TargetAlias           string                       `json:"target_alias,omitempty"`
	OperationTargetSHA256 string                       `json:"operation_target_sha256,omitempty"`
	LocalRequest          localDecisionRequestEvidence `json:"core_local_decision_request"`
	TranscriptSnapshot    transcriptSnapshot           `json:"transcript_snapshot"`
	Candidates            []contextCandidate           `json:"session_context_candidates"`
	CandidateSummary      []contextCandidateSummary    `json:"session_context_summary"`
	SelectionMetrics      contextMetrics               `json:"selection_metrics"`
	SelectedModelInput    *externalDecisionInput       `json:"selected_model_input,omitempty"`
	RequesterContext      json.RawMessage              `json:"onenod_requester_context,omitempty"`
	GatekeeperProcess     evidenceProcessContext       `json:"gatekeeper_process"`
	ProcessEnvironment    []evidenceEnvironmentEntry   `json:"gatekeeper_process_environment"`
	CollectorError        *string                      `json:"collector_error"`
}

type localDecisionRequestEvidence struct {
	SchemaVersion    int             `json:"schema_version"`
	RequestID        string          `json:"request_id"`
	Mode             string          `json:"mode"`
	Prompt           string          `json:"prompt"`
	ToolName         string          `json:"tool_name"`
	ToolInput        string          `json:"tool_input"`
	TranscriptPath   string          `json:"transcript_path"`
	CWD              string          `json:"cwd"`
	Evidence         string          `json:"evidence"`
	ActualRequest    operationTarget `json:"actual_request"`
	CoreBinarySHA256 string          `json:"core_binary_sha256,omitempty"`
}

type decisionRecord struct {
	ModelRounds               int                       `json:"model_rounds,omitempty"`
	EvidenceRefDiagnostics    []string                  `json:"evidence_ref_diagnostics,omitempty"`
	ToolCalls                 int                       `json:"tool_calls,omitempty"`
	ToolLatencyMS             float64                   `json:"tool_latency_ms,omitempty"`
	SchemaVersion             int                       `json:"schema_version"`
	RecordType                string                    `json:"record_type"`
	ObservedAt                time.Time                 `json:"observed_at"`
	RequestID                 string                    `json:"request_id"`
	Dataset                   string                    `json:"dataset"`
	Scenario                  string                    `json:"scenario"`
	Mode                      string                    `json:"mode"`
	ConfigSHA256              string                    `json:"config_sha256"`
	Provider                  string                    `json:"provider"`
	Model                     string                    `json:"model"`
	GatekeeperVersion         string                    `json:"gatekeeper_version"`
	GatekeeperBinarySHA256    string                    `json:"gatekeeper_binary_sha256"`
	PolicySHA256              string                    `json:"policy_sha256"`
	TargetAlias               string                    `json:"target_alias"`
	Surface                   string                    `json:"surface"`
	Operation                 string                    `json:"operation"`
	Decision                  string                    `json:"decision"`
	Reason                    string                    `json:"reason"`
	ErrorCode                 *string                   `json:"error_code"`
	ModelUsed                 bool                      `json:"model_used"`
	ModelCalled               bool                      `json:"model_called"`
	ModelTransport            string                    `json:"model_transport,omitempty"`
	TransportDetail           *string                   `json:"transport_error_detail,omitempty"`
	ResponseShape             string                    `json:"response_shape"`
	ScopeResolution           string                    `json:"scope_resolution"`
	EvidenceRefs              []string                  `json:"evidence_refs"`
	ReasoningPresent          bool                      `json:"reasoning_present"`
	ReasoningBytes            int                       `json:"reasoning_bytes"`
	ReasoningTokens           int                       `json:"reasoning_tokens"`
	FinishReason              string                    `json:"finish_reason"`
	LatencyMS                 int64                     `json:"latency_ms"`
	HTTPStatus                int                       `json:"http_status,omitempty"`
	Metrics                   contextMetrics            `json:"context_metrics"`
	CollectionStatus          string                    `json:"collection_status"`
	CollectionErrorCode       *string                   `json:"collection_error_code"`
	AttributionResult         string                    `json:"attribution_result"`
	AttributionCandidateCount int                       `json:"attribution_candidate_count"`
	AttributionConflicts      []string                  `json:"attribution_conflicts"`
	ObservedFeatureGroups     []string                  `json:"observed_feature_groups"`
	RawPromptStored           bool                      `json:"raw_prompt_stored"`
	RawToolInputStored        bool                      `json:"raw_tool_input_stored"`
	RawModelResponseStored    bool                      `json:"raw_model_response_stored"`
	RawReasoningContentStored bool                      `json:"raw_reasoning_content_stored"`
	ComparisonRequestStored   bool                      `json:"comparison_request_stored"`
	ComparisonResponseStored  bool                      `json:"comparison_response_stored"`
	CredentialMaterialStored  bool                      `json:"credential_material_stored"`
	EvidenceID                string                    `json:"evidence_id"`
	EvidenceState             string                    `json:"evidence_state"`
	PrimaryVariant            string                    `json:"primary_variant,omitempty"`
	Comparison                *comparisonDecisionRecord `json:"comparison,omitempty"`
}

type comparisonDecisionRecord struct {
	ModelRounds            int      `json:"model_rounds,omitempty"`
	EvidenceRefDiagnostics []string `json:"evidence_ref_diagnostics,omitempty"`
	ToolCalls              int      `json:"tool_calls,omitempty"`
	ToolLatencyMS          float64  `json:"tool_latency_ms,omitempty"`
	Variant                string   `json:"variant"`
	ThinkingType           string   `json:"thinking_type"`
	Decision               string   `json:"decision"`
	Reason                 string   `json:"reason"`
	ErrorCode              *string  `json:"error_code"`
	ModelUsed              bool     `json:"model_used"`
	ModelCalled            bool     `json:"model_called"`
	ModelTransport         string   `json:"model_transport,omitempty"`
	TransportDetail        *string  `json:"transport_error_detail,omitempty"`
	ResponseShape          string   `json:"response_shape"`
	ScopeResolution        string   `json:"scope_resolution"`
	EvidenceRefs           []string `json:"evidence_refs"`
	ReasoningPresent       bool     `json:"reasoning_present"`
	ReasoningBytes         int      `json:"reasoning_bytes"`
	ReasoningTokens        int      `json:"reasoning_tokens"`
	FinishReason           string   `json:"finish_reason"`
	LatencyMS              int64    `json:"latency_ms"`
	HTTPStatus             int      `json:"http_status,omitempty"`
}

func stringPointer(value string) *string { return &value }
