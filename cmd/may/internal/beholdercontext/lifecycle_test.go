package beholdercontext

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTerminalToolResponseRequiresStructuredExitWithoutLiveSession(t *testing.T) {
	for _, tt := range []struct {
		raw      string
		terminal bool
	}{
		{`{"exit_code":0}`, true}, {`{"exit_code":1,"session_id":null}`, true},
		{`{"exit_code":0,"session_id":42}`, false}, {`{"exit_code":0,"sessionId":"live"}`, false},
		{`{"output":"exit_code: 0"}`, false}, {`"process finished"`, false}, {`{`, false},
	} {
		if got := terminalToolResponse(json.RawMessage(tt.raw)); got != tt.terminal {
			t.Errorf("%s: %v", tt.raw, got)
		}
	}
}

func TestHookCrossDirectoryRemainsObservationOnly(t *testing.T) {
	for _, event := range []string{"UserPromptSubmit", "PreToolUse", "Stop", "Interrupt", "SessionEnd", "PostToolUse"} {
		t.Run(event, func(t *testing.T) {
			root := t.TempDir()
			transcript, result := filepath.Join(root, "session.jsonl"), filepath.Join(root, "result.json")
			writeTestSessionMetadata(t, transcript, "session-test-alpha", filepath.Join(root, "project-a"))
			input := hookInput{SessionID: "session-test-alpha", TurnID: "turn-test-alpha", TranscriptPath: transcript, CWD: filepath.Join(root, "project-b"), HookEventName: event}
			switch event {
			case "UserPromptSubmit":
				input.Prompt = "Continue the authorized task."
			case "PreToolUse":
				input.ToolName, input.ToolUseID, input.ToolInput = "Bash", "tool-test-alpha", json.RawMessage(`{"command":"true"}`)
			case "PostToolUse":
				input.ToolName, input.ToolUseID, input.ToolResponse = "Bash", "tool-test-alpha", json.RawMessage(`{"exit_code":0}`)
			case "SessionEnd":
				input.TurnID = ""
			}
			encoded, _ := json.Marshal(input)
			var output bytes.Buffer
			run([]string{"--result-path", result}, bytes.NewReader(encoded), &output)
			var record hookRecord
			stored, err := os.ReadFile(result)
			if err != nil || json.Unmarshal(stored, &record) != nil || record.ErrorCode != nil || record.CWDRelation != "different" {
				t.Fatalf("valid cross-directory %s was rejected: %s %v", event, stored, err)
			}
			if output.String() != "{}\n" || record.TransportInjected {
				t.Fatal("observer changed host behavior")
			}
		})
	}
}
