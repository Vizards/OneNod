// Package modelcontract defines the provenance rules shared by the sender and auditor.
package modelcontract

import (
	"encoding/json"
	"errors"
)

// ValidateChronology accepts the frozen v3 layout, v4 turn anchors, and v5
// execution-candidate attribution without a claim of a trusted spawn mapping.
// A turn anchor identifies the originating user event, independently of later
// human directions that arrived while its tools were running.
func ValidateChronology(raw []byte) error {
	type message struct {
		Source   string `json:"source"`
		Trust    string `json:"trust_class"`
		Ordinal  *int   `json:"session_ordinal"`
		Latest   bool   `json:"is_latest"`
		Relation string `json:"temporal_relation"`
	}
	var input struct {
		Version int `json:"schema_version"`
		Users   struct {
			Order    string    `json:"order"`
			Messages []message `json:"messages"`
			Latest   int       `json:"latest_message_index"`
			Anchor   *int      `json:"turn_anchor_index"`
		} `json:"user_messages"`
		Assistant struct {
			Prior     []message `json:"prior"`
			Current   []message `json:"current"`
			Rationale *message  `json:"request_rationale"`
		} `json:"assistant_messages"`
		Core struct {
			Actual struct {
				Scope string `json:"verification_scope"`
			} `json:"actual_request"`
			Captured struct {
				Tool    message   `json:"current_tool_call"`
				Ambient []message `json:"ambient_context"`
			} `json:"captured_context"`
		} `json:"core_verified_facts"`
	}
	fail := func() error { return errors.New("model-input-provenance-invalid") }
	if json.Unmarshal(raw, &input) != nil || (input.Version != 3 && input.Version != 4 && input.Version != 5) ||
		input.Users.Order != "oldest-to-newest" || len(input.Users.Messages) == 0 ||
		input.Users.Latest != len(input.Users.Messages)-1 ||
		input.Core.Actual.Scope != "operation-and-target-bound-by-core" ||
		input.Core.Captured.Tool.Source != "managed-pre-tool-use" ||
		input.Core.Captured.Tool.Trust != "core-captured" ||
		((input.Version < 5 && input.Core.Captured.Tool.Relation != "caused-current-request") || (input.Version >= 5 && input.Core.Captured.Tool.Relation != "associated-execution-candidate")) {
		return fail()
	}
	anchor := input.Users.Latest
	if input.Version >= 4 {
		if input.Users.Anchor == nil || *input.Users.Anchor < 0 || *input.Users.Anchor >= len(input.Users.Messages) {
			return fail()
		}
		anchor = *input.Users.Anchor
	} else if input.Users.Anchor != nil {
		return fail()
	}
	last := 0
	for i, m := range input.Users.Messages {
		if m.Trust != "human-authored" || m.Latest != (i == input.Users.Latest) {
			return fail()
		}
		if i == anchor {
			relation := "current-human-direction"
			if input.Version >= 4 {
				relation = "turn-binding-anchor"
			}
			if m.Source != "managed-current-user-prompt" || m.Relation != relation {
				return fail()
			}
		} else {
			if m.Source != "human-message" {
				return fail()
			}
			if input.Version >= 4 {
				relation := "before-current-prompt"
				if i > anchor {
					relation = "after-current-prompt"
				}
				if m.Relation != relation {
					return fail()
				}
			}
		}
		if m.Ordinal == nil {
			// Only the historical v3 anchor could lack a transcript ordinal.
			if input.Version != 3 || i != anchor {
				return fail()
			}
		} else {
			if *m.Ordinal <= last {
				return fail()
			}
			last = *m.Ordinal
		}
	}
	for _, list := range [][]message{input.Assistant.Prior, input.Assistant.Current, input.Core.Captured.Ambient} {
		for _, m := range list {
			if m.Source == "" || m.Trust == "" || m.Trust == "human-authored" {
				return fail()
			}
		}
	}
	if r := input.Assistant.Rationale; r != nil && (r.Source != "bound-request-context" ||
		r.Trust != "assistant-assertion" || r.Relation != "current-request") {
		return fail()
	}
	return nil
}
