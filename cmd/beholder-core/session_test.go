package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadRecentEventContextReadsOnlyTheCurrentTurnTail(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	var content bytes.Buffer
	writeSessionEventLine(t, &content, map[string]any{
		"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-old"},
	})
	writeSessionEventLine(t, &content, map[string]any{
		"type": "response_item", "payload": map[string]any{"type": "custom_tool_call", "name": "old-operation"},
	})
	content.WriteString("this older complete record is deliberately malformed\n")
	writeSessionEventLine(t, &content, map[string]any{
		"type": "turn_context", "payload": map[string]any{"turn_id": "turn-current"},
	})
	writeSessionEventLine(t, &content, map[string]any{
		"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-current"},
	})
	for index := 0; index < maximumRecentOps+3; index++ {
		writeSessionEventLine(t, &content, map[string]any{
			"type": "response_item",
			"payload": map[string]any{
				"type": "custom_tool_call", "name": fmt.Sprintf("operation-%02d", index),
			},
		})
	}
	if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	operations, turnID, taskStartedTurnID, err := readRecentEventContext(path)
	if err != nil {
		t.Fatal(err)
	}
	wantOperations := make([]string, 0, maximumRecentOps)
	for index := 3; index < maximumRecentOps+3; index++ {
		wantOperations = append(wantOperations, fmt.Sprintf("operation-%02d", index))
	}
	if !reflect.DeepEqual(operations, wantOperations) {
		t.Fatalf("recent operations = %#v, want %#v", operations, wantOperations)
	}
	if turnID != "turn-current" || taskStartedTurnID != "turn-current" {
		t.Fatalf("turn evidence = (%q, %q), want current turn", turnID, taskStartedTurnID)
	}
}

func TestReadRecentEventContextReassemblesLinesAcrossReverseBlocks(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	var content bytes.Buffer
	writeSessionEventLine(t, &content, map[string]any{
		"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-large"},
	})
	writeSessionEventLine(t, &content, map[string]any{
		"type": "response_item",
		"payload": map[string]any{
			"type": "message", "padding": strings.Repeat("x", reverseSessionBlockSize+257),
		},
	})
	writeSessionEventLine(t, &content, map[string]any{
		"type": "response_item", "payload": map[string]any{"type": "custom_tool_call", "name": "functions.exec"},
	})
	if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	operations, turnID, taskStartedTurnID, err := readRecentEventContext(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operations, []string{"functions.exec"}) ||
		turnID != "turn-large" || taskStartedTurnID != "turn-large" {
		t.Fatalf("unexpected event context: %#v %q %q", operations, turnID, taskStartedTurnID)
	}
}

func TestReadRecentEventContextIgnoresAnIncompleteAppend(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	var content bytes.Buffer
	writeSessionEventLine(t, &content, map[string]any{
		"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-current"},
	})
	writeSessionEventLine(t, &content, map[string]any{
		"type": "response_item", "payload": map[string]any{"type": "custom_tool_call", "name": "functions.exec"},
	})
	content.WriteString(`{"type":"response_item","payload":`)
	if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	operations, turnID, taskStartedTurnID, err := readRecentEventContext(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(operations, []string{"functions.exec"}) ||
		turnID != "turn-current" || taskStartedTurnID != "turn-current" {
		t.Fatalf("unexpected event context: %#v %q %q", operations, turnID, taskStartedTurnID)
	}
}

func TestReadRecentEventContextRejectsMalformedCompleteTail(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "session.jsonl")
	var content bytes.Buffer
	writeSessionEventLine(t, &content, map[string]any{
		"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-current"},
	})
	content.WriteString("malformed complete record\n")
	if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := readRecentEventContext(path); err == nil || !strings.Contains(err.Error(), "invalid session event") {
		t.Fatalf("malformed complete tail error = %v", err)
	}
}

func TestReadRecentEventContextPreservesForwardTurnState(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		events          []map[string]any
		wantTurn        string
		wantTaskStarted string
	}{
		{
			name: "same turn context after task start",
			events: []map[string]any{
				{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-a"}},
				{"type": "turn_context", "payload": map[string]any{"turn_id": "turn-a"}},
			},
			wantTurn: "turn-a", wantTaskStarted: "turn-a",
		},
		{
			name: "different turn context clears task start",
			events: []map[string]any{
				{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-a"}},
				{"type": "turn_context", "payload": map[string]any{"turn_id": "turn-b"}},
			},
			wantTurn: "turn-b", wantTaskStarted: "",
		},
		{
			name: "switching away and back does not revive task start",
			events: []map[string]any{
				{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-a"}},
				{"type": "turn_context", "payload": map[string]any{"turn_id": "turn-b"}},
				{"type": "turn_context", "payload": map[string]any{"turn_id": "turn-a"}},
			},
			wantTurn: "turn-a", wantTaskStarted: "",
		},
		{
			name: "later task start becomes final state",
			events: []map[string]any{
				{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-a"}},
				{"type": "turn_context", "payload": map[string]any{"turn_id": "turn-b"}},
				{"type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": "turn-a"}},
			},
			wantTurn: "turn-a", wantTaskStarted: "turn-a",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "session.jsonl")
			var content bytes.Buffer
			for _, event := range test.events {
				writeSessionEventLine(t, &content, event)
			}
			if err := os.WriteFile(path, content.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			_, turnID, taskStartedTurnID, err := readRecentEventContext(path)
			if err != nil {
				t.Fatal(err)
			}
			if turnID != test.wantTurn || taskStartedTurnID != test.wantTaskStarted {
				t.Fatalf("turn state = (%q, %q), want (%q, %q)", turnID, taskStartedTurnID, test.wantTurn, test.wantTaskStarted)
			}
		})
	}
}

func writeSessionEventLine(t *testing.T, buffer *bytes.Buffer, event map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	buffer.Write(encoded)
	buffer.WriteByte('\n')
}
