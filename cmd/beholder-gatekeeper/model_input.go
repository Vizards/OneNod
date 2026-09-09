package main

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
)

const (
	externalDecisionInputSchemaVersion         = 5
	previousTurnAnchorInputSchemaVersion       = 4
	frozenChronologicalInputSchemaVersion      = 3
	previousExternalDecisionInputSchemaVersion = 2
	userMessageOrder                           = "oldest-to-newest"
)

const (
	currentUserSource           = "managed-current-user-prompt"
	currentUserTrustClass       = "human-authored"
	currentUserTemporalRelation = "current-human-direction"
	requestRationaleSource      = "bound-request-context"
	requestRationaleTrustClass  = "assistant-assertion"
	requestRationaleRelation    = "current-request"
	currentToolCallSource       = "managed-pre-tool-use"
	currentToolCallTrustClass   = "core-captured"
	currentToolCallRelation     = "caused-current-request"
	actualRequestVerification   = "operation-and-target-bound-by-core"
)

// externalDecisionInput remains the in-process representation used by the
// collector. Its JSON representation is deliberately projected into exactly
// three provenance domains so the oversight model cannot mistake an Agent
// assertion for either a human message or a Core-verified request fact.
type modelDecisionInputWire struct {
	SchemaVersion int `json:"schema_version"`
	UserMessages  struct {
		Order              string              `json:"order"`
		Messages           []modelInputMessage `json:"messages"`
		LatestMessageIndex int                 `json:"latest_message_index"`
		TurnAnchorIndex    *int                `json:"turn_anchor_index,omitempty"`
	} `json:"user_messages"`
	AssistantMessages modelAssistantMessageDomain  `json:"assistant_messages"`
	CoreVerifiedFacts modelCoreVerifiedFactsDomain `json:"core_verified_facts"`
}

// The v2 shape remains decodable so a future candidate viewer can still read
// already-frozen R8 evidence. New requests are always encoded as v3.
type previousModelDecisionInputWire struct {
	SchemaVersion int `json:"schema_version"`
	UserMessages  struct {
		Current modelInputMessage   `json:"current"`
		Prior   []modelInputMessage `json:"prior"`
	} `json:"user_messages"`
	AssistantMessages modelAssistantMessageDomain  `json:"assistant_messages"`
	CoreVerifiedFacts modelCoreVerifiedFactsDomain `json:"core_verified_facts"`
}

type modelAssistantMessageDomain struct {
	Prior            []modelInputMessage  `json:"prior"`
	Current          []modelInputMessage  `json:"current"`
	RequestRationale *modelInputAssertion `json:"request_rationale,omitempty"`
}

type modelCoreVerifiedFactsDomain struct {
	Evidence        json.RawMessage        `json:"evidence"`
	ActualRequest   verifiedExternalTarget `json:"actual_request"`
	CapturedContext struct {
		CurrentToolCall       modelInputToolCall        `json:"current_tool_call"`
		CompletedToolActivity []recentToolContext       `json:"completed_tool_activity"`
		AmbientContext        []modelInputMessage       `json:"ambient_context"`
		Environment           workspaceContext          `json:"environment"`
		Coverage              contextCoverage           `json:"coverage,omitempty"`
		RequesterContext      requesterExecutionContext `json:"requester_context"`
	} `json:"captured_context"`
}

type modelInputMessage struct {
	Source           string `json:"source"`
	TrustClass       string `json:"trust_class"`
	SessionOrdinal   *int   `json:"session_ordinal,omitempty"`
	TemporalRelation string `json:"temporal_relation"`
	IsLatest         bool   `json:"is_latest,omitempty"`
	Text             string `json:"text"`
}

type modelInputAssertion struct {
	Source           string          `json:"source"`
	TrustClass       string          `json:"trust_class"`
	TemporalRelation string          `json:"temporal_relation"`
	Content          json.RawMessage `json:"content"`
}

type modelInputToolCall struct {
	Source           string          `json:"source"`
	TrustClass       string          `json:"trust_class"`
	TemporalRelation string          `json:"temporal_relation"`
	Name             string          `json:"name"`
	Input            json.RawMessage `json:"input"`
}

type verifiedExternalTarget struct {
	VerificationScope  string          `json:"verification_scope"`
	Surface            string          `json:"surface"`
	Operation          string          `json:"operation"`
	TargetKind         string          `json:"target_kind"`
	TargetID           json.RawMessage `json:"target_id,omitempty"`
	TargetAlias        string          `json:"target_alias,omitempty"`
	KeyFingerprint     string          `json:"key_fingerprint,omitempty"`
	RemoteUser         string          `json:"remote_user,omitempty"`
	HostKeyFingerprint string          `json:"host_key_fingerprint,omitempty"`
}

func modelMessageFromSource(value sourceText) modelInputMessage {
	ordinal := value.Ordinal
	return modelInputMessage{
		Source: value.Source, TrustClass: value.TrustClass, SessionOrdinal: &ordinal,
		TemporalRelation: value.Relation, Text: value.Text,
	}
}

func sourceFromModelMessage(value modelInputMessage) sourceText {
	ordinal := 0
	if value.SessionOrdinal != nil {
		ordinal = *value.SessionOrdinal
	}
	return sourceText{
		Source: value.Source, TrustClass: value.TrustClass, Ordinal: ordinal,
		Relation: value.TemporalRelation, Text: value.Text,
	}
}

func modelMessagesFromSources(values []sourceText) []modelInputMessage {
	result := make([]modelInputMessage, 0, len(values))
	for _, value := range values {
		result = append(result, modelMessageFromSource(value))
	}
	return result
}

func sourcesFromModelMessages(values []modelInputMessage) []sourceText {
	result := make([]sourceText, 0, len(values))
	for _, value := range values {
		result = append(result, sourceFromModelMessage(value))
	}
	return result
}

func (input externalDecisionInput) MarshalJSON() ([]byte, error) {
	if input.SchemaVersion == previousExternalDecisionInputSchemaVersion {
		return marshalPreviousModelDecisionInput(input)
	}
	if input.SchemaVersion != externalDecisionInputSchemaVersion && input.SchemaVersion != previousTurnAnchorInputSchemaVersion && input.SchemaVersion != frozenChronologicalInputSchemaVersion {
		return nil, errors.New("unsupported external decision input schema")
	}
	var wire modelDecisionInputWire
	wire.SchemaVersion = input.SchemaVersion
	wire.UserMessages.Order = userMessageOrder
	wire.UserMessages.Messages = modelMessagesFromSources(input.HumanIntent.PriorMessages)
	sort.SliceStable(wire.UserMessages.Messages, func(left, right int) bool {
		return messageOrdinal(wire.UserMessages.Messages[left]) < messageOrdinal(wire.UserMessages.Messages[right])
	})
	current := modelInputMessage{
		Source: currentUserSource, TrustClass: currentUserTrustClass,
		TemporalRelation: currentUserTemporalRelation, Text: input.HumanIntent.CurrentPrompt,
	}
	if input.HumanIntent.CurrentPromptOrdinal > 0 {
		ordinal := input.HumanIntent.CurrentPromptOrdinal
		current.SessionOrdinal = &ordinal
	}
	if input.SchemaVersion >= previousTurnAnchorInputSchemaVersion {
		current.TemporalRelation = "turn-binding-anchor"
	}
	wire.UserMessages.Messages = append(wire.UserMessages.Messages, current)
	if input.SchemaVersion >= previousTurnAnchorInputSchemaVersion {
		sort.SliceStable(wire.UserMessages.Messages, func(i, j int) bool {
			return messageOrdinal(wire.UserMessages.Messages[i]) < messageOrdinal(wire.UserMessages.Messages[j])
		})
		for i, message := range wire.UserMessages.Messages {
			if message.Source == currentUserSource {
				anchor := i
				wire.UserMessages.TurnAnchorIndex = &anchor
			}
		}
	}
	wire.UserMessages.LatestMessageIndex = len(wire.UserMessages.Messages) - 1
	wire.UserMessages.Messages[wire.UserMessages.LatestMessageIndex].IsLatest = true
	wire.AssistantMessages.Prior = modelMessagesFromSources(input.AgentContext.PriorTaskTrajectory)
	wire.AssistantMessages.Current = modelMessagesFromSources(input.AgentContext.CurrentExecutionTrajectory)
	if len(input.ActualRequest.RequestContext) != 0 {
		wire.AssistantMessages.RequestRationale = &modelInputAssertion{
			Source: requestRationaleSource, TrustClass: requestRationaleTrustClass,
			TemporalRelation: requestRationaleRelation,
			Content:          append(json.RawMessage(nil), input.ActualRequest.RequestContext...),
		}
	}
	wire.CoreVerifiedFacts.Evidence = append(json.RawMessage(nil), input.CoreEvidence...)
	wire.CoreVerifiedFacts.ActualRequest = verifiedExternalTarget{
		VerificationScope: actualRequestVerification,
		Surface:           input.ActualRequest.Surface, Operation: input.ActualRequest.Operation,
		TargetKind:  input.ActualRequest.TargetKind,
		TargetID:    append(json.RawMessage(nil), input.ActualRequest.TargetID...),
		TargetAlias: input.ActualRequest.TargetAlias, KeyFingerprint: input.ActualRequest.KeyFingerprint,
		RemoteUser: input.ActualRequest.RemoteUser, HostKeyFingerprint: input.ActualRequest.HostKeyFingerprint,
	}
	wire.CoreVerifiedFacts.CapturedContext.CurrentToolCall = modelInputToolCall{
		Source: currentToolCallSource, TrustClass: currentToolCallTrustClass,
		TemporalRelation: toolCallRelation(input.SchemaVersion), Name: input.ToolCall.Name,
		Input: append(json.RawMessage(nil), input.ToolCall.Input...),
	}
	wire.CoreVerifiedFacts.CapturedContext.CompletedToolActivity = input.CompletedToolActivity
	wire.CoreVerifiedFacts.CapturedContext.AmbientContext = modelMessagesFromSources(input.AgentContext.AmbientContext)
	wire.CoreVerifiedFacts.CapturedContext.Environment = input.Environment
	wire.CoreVerifiedFacts.CapturedContext.Coverage = input.Coverage
	wire.CoreVerifiedFacts.CapturedContext.RequesterContext = input.RequesterContext
	encoded, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	if err := modelcontract.ValidateChronology(encoded); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

func (input *externalDecisionInput) UnmarshalJSON(value []byte) error {
	if input == nil {
		return errors.New("nil external decision input")
	}
	var header struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(value, &header); err != nil {
		return err
	}
	if header.SchemaVersion == previousExternalDecisionInputSchemaVersion {
		return unmarshalPreviousModelDecisionInput(input, value)
	}
	if header.SchemaVersion != externalDecisionInputSchemaVersion && header.SchemaVersion != previousTurnAnchorInputSchemaVersion && header.SchemaVersion != frozenChronologicalInputSchemaVersion {
		return errors.New("unsupported external decision input schema")
	}
	var wire modelDecisionInputWire
	if err := json.Unmarshal(value, &wire); err != nil {
		return err
	}
	if err := modelcontract.ValidateChronology(value); err != nil {
		return err
	}
	anchorIndex := wire.UserMessages.LatestMessageIndex
	if wire.SchemaVersion >= previousTurnAnchorInputSchemaVersion {
		anchorIndex = *wire.UserMessages.TurnAnchorIndex
	}
	anchor := wire.UserMessages.Messages[anchorIndex]
	otherHumans := make([]modelInputMessage, 0, len(wire.UserMessages.Messages)-1)
	for i, message := range wire.UserMessages.Messages {
		if i != anchorIndex {
			otherHumans = append(otherHumans, message)
		}
	}
	var result externalDecisionInput
	result.SchemaVersion = wire.SchemaVersion
	result.HumanIntent.CurrentPrompt = anchor.Text
	if anchor.SessionOrdinal != nil {
		result.HumanIntent.CurrentPromptOrdinal = *anchor.SessionOrdinal
	}
	result.HumanIntent.PriorMessages = sourcesFromModelMessages(otherHumans)
	result.AgentContext.PriorTaskTrajectory = sourcesFromModelMessages(wire.AssistantMessages.Prior)
	result.AgentContext.CurrentExecutionTrajectory = sourcesFromModelMessages(wire.AssistantMessages.Current)
	result.AgentContext.AmbientContext = sourcesFromModelMessages(wire.CoreVerifiedFacts.CapturedContext.AmbientContext)
	result.ToolCall.Name = wire.CoreVerifiedFacts.CapturedContext.CurrentToolCall.Name
	result.ToolCall.Input = append(json.RawMessage(nil), wire.CoreVerifiedFacts.CapturedContext.CurrentToolCall.Input...)
	result.CompletedToolActivity = wire.CoreVerifiedFacts.CapturedContext.CompletedToolActivity
	result.Environment = wire.CoreVerifiedFacts.CapturedContext.Environment
	result.Coverage = wire.CoreVerifiedFacts.CapturedContext.Coverage
	result.RequesterContext = wire.CoreVerifiedFacts.CapturedContext.RequesterContext
	result.CoreEvidence = append(json.RawMessage(nil), wire.CoreVerifiedFacts.Evidence...)
	result.ActualRequest = externalTarget{
		Surface:            wire.CoreVerifiedFacts.ActualRequest.Surface,
		Operation:          wire.CoreVerifiedFacts.ActualRequest.Operation,
		TargetKind:         wire.CoreVerifiedFacts.ActualRequest.TargetKind,
		TargetID:           append(json.RawMessage(nil), wire.CoreVerifiedFacts.ActualRequest.TargetID...),
		TargetAlias:        wire.CoreVerifiedFacts.ActualRequest.TargetAlias,
		KeyFingerprint:     wire.CoreVerifiedFacts.ActualRequest.KeyFingerprint,
		RemoteUser:         wire.CoreVerifiedFacts.ActualRequest.RemoteUser,
		HostKeyFingerprint: wire.CoreVerifiedFacts.ActualRequest.HostKeyFingerprint,
	}
	if wire.AssistantMessages.RequestRationale != nil {
		result.ActualRequest.RequestContext = append(
			json.RawMessage(nil), wire.AssistantMessages.RequestRationale.Content...,
		)
	}
	*input = result
	return nil
}

func marshalPreviousModelDecisionInput(input externalDecisionInput) ([]byte, error) {
	var wire previousModelDecisionInputWire
	wire.SchemaVersion = input.SchemaVersion
	wire.UserMessages.Current = modelInputMessage{
		Source: currentUserSource, TrustClass: currentUserTrustClass,
		TemporalRelation: currentUserTemporalRelation, Text: input.HumanIntent.CurrentPrompt,
	}
	wire.UserMessages.Prior = modelMessagesFromSources(input.HumanIntent.PriorMessages)
	populateSharedModelDomains(
		&wire.AssistantMessages, &wire.CoreVerifiedFacts, input,
	)
	return json.Marshal(wire)
}

func unmarshalPreviousModelDecisionInput(input *externalDecisionInput, value []byte) error {
	var wire previousModelDecisionInputWire
	if err := json.Unmarshal(value, &wire); err != nil {
		return err
	}
	if wire.SchemaVersion != previousExternalDecisionInputSchemaVersion ||
		wire.UserMessages.Current.Source != currentUserSource ||
		wire.UserMessages.Current.TrustClass != currentUserTrustClass ||
		wire.UserMessages.Current.TemporalRelation != currentUserTemporalRelation {
		return errors.New("previous external decision input provenance mismatch")
	}
	var result externalDecisionInput
	result.SchemaVersion = wire.SchemaVersion
	result.HumanIntent.CurrentPrompt = wire.UserMessages.Current.Text
	result.HumanIntent.PriorMessages = sourcesFromModelMessages(wire.UserMessages.Prior)
	if err := populateExternalInputFromSharedDomains(
		&result, wire.AssistantMessages, wire.CoreVerifiedFacts,
	); err != nil {
		return err
	}
	*input = result
	return nil
}

func populateSharedModelDomains(
	assistant *modelAssistantMessageDomain,
	core *modelCoreVerifiedFactsDomain,
	input externalDecisionInput,
) {
	assistant.Prior = modelMessagesFromSources(input.AgentContext.PriorTaskTrajectory)
	assistant.Current = modelMessagesFromSources(input.AgentContext.CurrentExecutionTrajectory)
	if len(input.ActualRequest.RequestContext) != 0 {
		assistant.RequestRationale = &modelInputAssertion{
			Source: requestRationaleSource, TrustClass: requestRationaleTrustClass,
			TemporalRelation: requestRationaleRelation,
			Content:          append(json.RawMessage(nil), input.ActualRequest.RequestContext...),
		}
	}
	core.Evidence = append(json.RawMessage(nil), input.CoreEvidence...)
	core.ActualRequest = verifiedExternalTarget{
		VerificationScope: actualRequestVerification,
		Surface:           input.ActualRequest.Surface, Operation: input.ActualRequest.Operation,
		TargetKind: input.ActualRequest.TargetKind, TargetID: append(json.RawMessage(nil), input.ActualRequest.TargetID...),
		TargetAlias: input.ActualRequest.TargetAlias, KeyFingerprint: input.ActualRequest.KeyFingerprint,
		RemoteUser: input.ActualRequest.RemoteUser, HostKeyFingerprint: input.ActualRequest.HostKeyFingerprint,
	}
	core.CapturedContext.CurrentToolCall = modelInputToolCall{
		Source: currentToolCallSource, TrustClass: currentToolCallTrustClass,
		TemporalRelation: toolCallRelation(input.SchemaVersion), Name: input.ToolCall.Name,
		Input: append(json.RawMessage(nil), input.ToolCall.Input...),
	}
	core.CapturedContext.CompletedToolActivity = input.CompletedToolActivity
	core.CapturedContext.AmbientContext = modelMessagesFromSources(input.AgentContext.AmbientContext)
	core.CapturedContext.Environment = input.Environment
	core.CapturedContext.RequesterContext = input.RequesterContext
}

func populateExternalInputFromSharedDomains(
	result *externalDecisionInput,
	assistant modelAssistantMessageDomain,
	core modelCoreVerifiedFactsDomain,
) error {
	if core.ActualRequest.VerificationScope != actualRequestVerification ||
		core.CapturedContext.CurrentToolCall.Source != currentToolCallSource ||
		core.CapturedContext.CurrentToolCall.TrustClass != currentToolCallTrustClass ||
		core.CapturedContext.CurrentToolCall.TemporalRelation != currentToolCallRelation {
		return errors.New("external decision input provenance contract mismatch")
	}
	if assistant.RequestRationale != nil &&
		(assistant.RequestRationale.Source != requestRationaleSource ||
			assistant.RequestRationale.TrustClass != requestRationaleTrustClass ||
			assistant.RequestRationale.TemporalRelation != requestRationaleRelation) {
		return errors.New("external decision input assertion provenance mismatch")
	}
	result.AgentContext.PriorTaskTrajectory = sourcesFromModelMessages(assistant.Prior)
	result.AgentContext.CurrentExecutionTrajectory = sourcesFromModelMessages(assistant.Current)
	result.AgentContext.AmbientContext = sourcesFromModelMessages(core.CapturedContext.AmbientContext)
	result.ToolCall.Name = core.CapturedContext.CurrentToolCall.Name
	result.ToolCall.Input = append(json.RawMessage(nil), core.CapturedContext.CurrentToolCall.Input...)
	result.CompletedToolActivity = core.CapturedContext.CompletedToolActivity
	result.Environment = core.CapturedContext.Environment
	result.RequesterContext = core.CapturedContext.RequesterContext
	result.CoreEvidence = append(json.RawMessage(nil), core.Evidence...)
	result.ActualRequest = externalTarget{
		Surface: core.ActualRequest.Surface, Operation: core.ActualRequest.Operation,
		TargetKind: core.ActualRequest.TargetKind, TargetID: append(json.RawMessage(nil), core.ActualRequest.TargetID...),
		TargetAlias: core.ActualRequest.TargetAlias, KeyFingerprint: core.ActualRequest.KeyFingerprint,
		RemoteUser: core.ActualRequest.RemoteUser, HostKeyFingerprint: core.ActualRequest.HostKeyFingerprint,
	}
	if assistant.RequestRationale != nil {
		result.ActualRequest.RequestContext = append(json.RawMessage(nil), assistant.RequestRationale.Content...)
	}
	return nil
}

func messageOrdinal(message modelInputMessage) int {
	if message.SessionOrdinal == nil {
		return 0
	}
	return *message.SessionOrdinal
}

func toolCallRelation(version int) string {
	if version >= 5 {
		return "associated-execution-candidate"
	}
	return currentToolCallRelation
}
