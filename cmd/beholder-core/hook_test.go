package main

import (
	"encoding/json"
	"testing"
)

func TestHookToolCommandAcceptsBashObject(t *testing.T) {
	command, toolName, ok := hookToolCommand("Bash", json.RawMessage(`{"command":"ssh router.invalid"}`))
	if !ok || command != "ssh router.invalid" || toolName != "Bash" {
		t.Fatalf("Bash hook input was not normalized: command=%q tool=%q ok=%v", command, toolName, ok)
	}
}

func TestHookToolCommandAcceptsFreeformExecString(t *testing.T) {
	source := "const result = await tools.exec_command({cmd: `mac-peer macbook true`});"
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	command, toolName, ok := hookToolCommand("exec", encoded)
	if !ok || command != source || toolName != "functions.exec" {
		t.Fatalf("exec hook input was not normalized: command=%q tool=%q ok=%v", command, toolName, ok)
	}
}

func TestHookToolCommandAcceptsStructuredExecCode(t *testing.T) {
	command, toolName, ok := hookToolCommand(
		"functions.exec",
		json.RawMessage(`{"code":"await tools.exec_command({cmd: 'mac-peer macmini true'});"}`),
	)
	if !ok || command != "await tools.exec_command({cmd: 'mac-peer macmini true'});" || toolName != "functions.exec" {
		t.Fatalf("structured exec hook input was not normalized: command=%q tool=%q ok=%v", command, toolName, ok)
	}
}

func TestHookToolCommandRejectsUnsupportedOrEmptyInput(t *testing.T) {
	for _, test := range []struct {
		name     string
		toolName string
		input    json.RawMessage
	}{
		{name: "unsupported", toolName: "Read", input: json.RawMessage(`{"path":"fixture"}`)},
		{name: "empty-bash", toolName: "Bash", input: json.RawMessage(`{"command":""}`)},
		{name: "empty-exec", toolName: "exec", input: json.RawMessage(`""`)},
		{name: "invalid-exec", toolName: "functions.exec", input: json.RawMessage(`{"cmd":"true"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if command, toolName, ok := hookToolCommand(test.toolName, test.input); ok || command != "" || toolName != "" {
				t.Fatalf("invalid input was accepted: command=%q tool=%q ok=%v", command, toolName, ok)
			}
		})
	}
}
