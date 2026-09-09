package beholdercontext

import "encoding/json"

type hookLifecycleObservation struct {
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id,omitempty"`
	ToolUseID      string `json:"tool_use_id,omitempty"`
	TranscriptPath string `json:"transcript_path"`
	Event          string `json:"event"`
	Terminal       bool   `json:"terminal"`
}

// Only a structured exit with no continuing execution session is terminal.
// Text, missing fields, and unknown tool response formats cannot close a claim.
func terminalToolResponse(raw json.RawMessage) bool {
	var result struct {
		ExitCode       *int            `json:"exit_code"`
		SessionID      json.RawMessage `json:"session_id"`
		SessionIDCamel json.RawMessage `json:"sessionId"`
	}
	if json.Unmarshal(raw, &result) != nil || result.ExitCode == nil {
		return false
	}
	absent := func(value json.RawMessage) bool { return len(value) == 0 || string(value) == "null" }
	return absent(result.SessionID) && absent(result.SessionIDCamel)
}
