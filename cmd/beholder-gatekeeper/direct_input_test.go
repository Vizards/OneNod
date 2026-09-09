package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func TestDirectHistoryBudgetCannotEvictAgentExplanations(t *testing.T) {
	for _, toolCount := range []int{1, 3} {
		t.Run(fmt.Sprintf("tools-%d", toolCount), func(t *testing.T) {
			const explanation = "The selected credential mapping was verified; continue this read-only check."
			events := []map[string]any{
				messageFixture("user", "", "Verify the fixture service."),
				messageFixture("assistant", "commentary", explanation),
			}
			for i := 0; i < toolCount; i++ {
				id := fmt.Sprintf("large-history-%d", i)
				events = append(events, toolCallFixture(id, "exec_command", `{"cmd":"read fixture diagnostics"}`),
					toolOutputFixture(id, `{"output":"`+strings.Repeat("T", maximumRelatedContextBytes)+`TOOL SUFFIX"}`))
			}
			events = append(events,
				messageFixture("user", "", "Current human request: read the match fixture."),
				messageFixture("assistant", "commentary", "Continue the read-only verification."))
			input, _, source, err := buildExternalDecisionInputWithEvidence(liveRequestFixture(writeSessionFixture(t, events)), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer clearExternalInput(&input)
			if len(input.AgentContext.PriorTaskTrajectory) != 1 || input.AgentContext.PriorTaskTrajectory[0].Text != explanation ||
				len(input.AgentContext.CurrentExecutionTrajectory) != 1 {
				t.Fatal("historical tool bytes evicted a model-delivered Agent explanation")
			}
			if input.Coverage.HumanBytes+input.Coverage.OtherBytes > maximumRelatedContextBytes ||
				len(input.CompletedToolActivity) != 1 || !strings.Contains(input.CompletedToolActivity[0].Output, "TOOL SUFFIX") ||
				source.SelectedModelInput == nil {
				t.Fatal("bounded local tool evidence or its suffix was lost")
			}
			content, err := joinModelContent(input)
			if err != nil || !bytes.Contains(content, []byte(explanation)) || bytes.Contains(content, []byte("TOOL SUFFIX")) {
				t.Fatal("provider input did not preserve the explanation and omit historical tool output")
			}
			clear(content)
		})
	}
}
