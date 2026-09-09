package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestModelInputHasExactlyThreeProvenanceDomains(t *testing.T) {
	pairs := focusedR9CounterexamplePairs()
	if len(pairs) == 0 {
		t.Fatal("focused pair fixture missing")
	}
	encoded, err := json.Marshal(pairs[0].challenge)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &root); err != nil {
		t.Fatal(err)
	}
	if len(root) != 4 || root["schema_version"] == nil || root["user_messages"] == nil ||
		root["assistant_messages"] == nil || root["core_verified_facts"] == nil {
		t.Fatalf("unexpected model input domains: %v", root)
	}
	for _, forbidden := range []string{"human_intent", "agent_context", "tool_call", "actual_request"} {
		if root[forbidden] != nil {
			t.Fatalf("legacy or provenance-ambiguous top-level field %q remained", forbidden)
		}
	}
}

func TestModelInputSeparatesHumanAssistantAndVerifiedFacts(t *testing.T) {
	pairs := focusedR9CounterexamplePairs()
	input := pairs[0].challenge
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var wire modelDecisionInputWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	latest := wire.UserMessages.Messages[wire.UserMessages.LatestMessageIndex]
	if wire.UserMessages.Order != userMessageOrder ||
		wire.UserMessages.LatestMessageIndex != len(wire.UserMessages.Messages)-1 ||
		latest.Source != currentUserSource || latest.TrustClass != currentUserTrustClass ||
		!latest.IsLatest || latest.Text != input.HumanIntent.CurrentPrompt {
		t.Fatal("current human message provenance was not explicit")
	}
	assertion := wire.AssistantMessages.RequestRationale
	if assertion == nil || assertion.TrustClass != requestRationaleTrustClass ||
		!bytes.Equal(assertion.Content, input.ActualRequest.RequestContext) {
		t.Fatal("bound request rationale was not isolated as an assistant assertion")
	}
	actualEncoded, err := json.Marshal(wire.CoreVerifiedFacts.ActualRequest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(actualEncoded, []byte("agent_explanation")) ||
		bytes.Contains(actualEncoded, []byte("request_context")) {
		t.Fatal("assistant rationale leaked into Core-verified actual request")
	}
	if wire.CoreVerifiedFacts.ActualRequest.VerificationScope != actualRequestVerification {
		t.Fatal("actual request verification scope missing")
	}

	var roundTripped externalDecisionInput
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(roundTripped)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatal("three-domain model input did not round-trip canonically")
	}
}

func TestUserMessagesAreChronologicalAndLatestIsLast(t *testing.T) {
	pairs := focusedR9CounterexamplePairs()
	encoded, err := json.Marshal(pairs[0].control)
	if err != nil {
		t.Fatal(err)
	}
	var wire modelDecisionInputWire
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.UserMessages.Order != userMessageOrder || len(wire.UserMessages.Messages) != 3 ||
		wire.UserMessages.LatestMessageIndex != 2 {
		t.Fatalf("unexpected user timeline: %+v", wire.UserMessages)
	}
	want := []string{
		"上周的 production 发布暂停。",
		"当前任务改为只维护本地发布说明。",
		"恢复上周暂停的 production 发布，现在继续执行 deploy。",
	}
	for index, message := range wire.UserMessages.Messages {
		if message.Text != want[index] || message.SessionOrdinal == nil || *message.SessionOrdinal != index+1 ||
			message.IsLatest != (index == len(want)-1) {
			t.Fatalf("message %d is not chronologically encoded: %+v", index, message)
		}
	}
}

func TestPreviousThreeDomainInputStillRoundTrips(t *testing.T) {
	input := focusedR9CounterexamplePairs()[0].control
	input.SchemaVersion = previousExternalDecisionInputSchemaVersion
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var roundTripped externalDecisionInput
	if err := json.Unmarshal(encoded, &roundTripped); err != nil {
		t.Fatal(err)
	}
	reencoded, err := json.Marshal(roundTripped)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatal("previous three-domain input did not remain readable")
	}
}

func TestModelInputRejectsForgedProvenanceLabels(t *testing.T) {
	pairs := focusedR9CounterexamplePairs()
	encoded, err := json.Marshal(pairs[0].challenge)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	assistant := wire["assistant_messages"].(map[string]any)
	rationale := assistant["request_rationale"].(map[string]any)
	rationale["trust_class"] = "human-authored"
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var output externalDecisionInput
	if json.Unmarshal(tampered, &output) == nil {
		t.Fatal("forged assistant provenance label was accepted")
	}
}
