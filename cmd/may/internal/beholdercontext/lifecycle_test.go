package beholdercontext

import (
	"encoding/json"
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
