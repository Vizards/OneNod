package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestImageMessagePromptBoundary(t *testing.T) {
	data, err := os.ReadFile("../testdata/beholder-prompt-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name    string
		Prompt  string
		Content json.RawMessage
		Accept  bool
		Wrapped bool
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, test := range cases {
		t.Run(test.Name, func(t *testing.T) {
			var original messagePayload
			if err := json.Unmarshal(test.Content, &original.Content); err != nil {
				t.Fatal(err)
			}
			kinds := make([]string, len(original.Content))
			for index, part := range original.Content {
				kinds[index] = "user.text"
				if part.Type == "input_image" {
					kinds[index] = "user.image"
				}
			}
			message := messageFixtureWithKinds("user", "", "", kinds...)
			message["content"] = test.Content
			request := liveRequestFixture(writeSessionFixture(t, []map[string]any{
				messageFixtureWithKinds("user", "", "Inspect the UI and preserve the approval boundary.", "user.text"),
				message,
				messageFixture("assistant", "commentary", "I will inspect the UI."),
			}))
			request.Prompt = []byte(test.Prompt)
			input, _, source, err := buildExternalDecisionInputWithEvidence(request, nil)
			defer clearExternalInput(&input)
			if !test.Accept {
				if err == nil || !strings.Contains(err.Error(), "model-input-provenance-invalid") {
					t.Fatalf("a different prompt was accepted: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if input.HumanIntent.CurrentPrompt != test.Prompt || input.HumanIntent.CurrentPromptOrdinal != 2 ||
				len(input.HumanIntent.PriorMessages) != 1 || len(input.AgentContext.CurrentExecutionTrajectory) != 1 {
				t.Fatalf("prompt text or trajectory was lost: %+v", input)
			}
			boundary := source.Candidates[1]
			if boundary.Content != messageText(original) {
				t.Fatal("boundary evidence must retain the original text including image wrappers")
			}
			if test.Wrapped && boundary.Reason != "current-prompt-from-core-with-image-wrappers" {
				t.Fatalf("attachment projection is not explained in evidence: %+v", boundary)
			}
			encoded, err := json.Marshal(input)
			if err != nil || bytes.Contains(encoded, []byte("data:image/")) {
				t.Fatalf("invalid model input or image payload leaked into text context: %v", err)
			}
		})
	}
}
