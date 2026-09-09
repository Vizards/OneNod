package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
)

func TestDirectModelInputPreservesDomainsAndLocalHistory(t *testing.T) {
	request := liveRequestFixture(writeSessionFixture(t, []map[string]any{
		messageFixture("user", "", "Earlier authorization: verify the fixture service."),
		messageFixture("assistant", "commentary", "I will check the fixture state."),
		toolCallFixture("history", "exec_command", `{"cmd":"read fixture status"}`),
		toolOutputFixture("history", `{"output":"`+strings.Repeat("historical-tool-output ", 16000)+`"}`),
		messageFixture("user", "", "Current human request: read the match fixture."),
		messageFixture("assistant", "commentary", "Continue the read-only verification."),
	}))
	input, _, source, err := buildExternalDecisionInputWithEvidence(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clearExternalInput(&input)
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	content, err := joinModelContent(input)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(content)
	var captured, delivered modelDecisionInputWire
	if json.Unmarshal(before, &captured) != nil || json.Unmarshal(content, &delivered) != nil {
		t.Fatal("invalid source or provider JSON")
	}
	old := captured.CoreVerifiedFacts.CapturedContext
	got := &delivered.CoreVerifiedFacts.CapturedContext
	if len(old.CompletedToolActivity) != 1 || len(got.CompletedToolActivity) != 0 ||
		got.Coverage.ModelDelivery == nil || got.Coverage.ModelDelivery.Profile != modelcontract.DirectInputProfile ||
		got.Coverage.ModelDelivery.CompletedToolRecordsOmitted != 1 ||
		bytes.Contains(content, []byte("historical-tool-output")) || len(content) >= len(before)/10 {
		t.Fatal("historical output was not removed with explicit delivery accounting")
	}
	got.CompletedToolActivity = old.CompletedToolActivity
	got.Coverage.ModelDelivery = nil
	if !reflect.DeepEqual(delivered, captured) {
		t.Fatal("direct projection changed another source domain or original capture coverage")
	}
	after, err := json.Marshal(input)
	if err != nil || !bytes.Equal(before, after) || source.SelectedModelInput == nil ||
		len(source.SelectedModelInput.CompletedToolActivity) != 1 || input.Coverage.ModelDelivery != nil {
		t.Fatal("model projection mutated local source evidence")
	}
}
