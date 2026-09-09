//go:build darwin

package beholdercontext

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testToolRef = "tool-selector-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRunStoresOnlyAllowlistedDerivedEvidence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transcriptPath := filepath.Join(root, "transcript.jsonl")
	resultPath := filepath.Join(root, "result.json")
	sessionID := "session-test-alpha"
	turnID := "turn-test-alpha"
	toolUseID := "tool-use-test-alpha"
	sentinel := "E1_RAW_COMMAND_SENTINEL_MUST_NOT_PERSIST"
	writeTestSessionMetadata(t, transcriptPath, sessionID, root)

	input := map[string]any{
		"session_id":      sessionID,
		"transcript_path": transcriptPath,
		"cwd":             root,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-5.6-luna",
		"permission_mode": "dontAsk",
		"turn_id":         turnID,
		"tool_name":       "Bash",
		"tool_use_id":     toolUseID,
		"tool_input":      map[string]any{"command": sentinel},
	}
	encodedInput, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run([]string{"--result-path", resultPath}, bytes.NewReader(encodedInput), &stdout)
	if stdout.String() != "{}\n" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}

	encodedResult, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{sessionID, turnID, toolUseID, transcriptPath, root, sentinel} {
		if bytes.Contains(encodedResult, []byte(forbidden)) {
			t.Fatalf("result persisted forbidden raw content: %q", forbidden)
		}
	}
	var record hookRecord
	if err := json.Unmarshal(encodedResult, &record); err != nil {
		t.Fatal(err)
	}
	if record.ErrorCode != nil || !record.SessionMetadataMatched || record.CWDRelation != "exact" {
		t.Fatalf("unexpected record: %+v", record)
	}
	if record.RawContentStored || record.RawIDsStored || record.PathsStored {
		t.Fatalf("privacy flags must remain false: %+v", record)
	}
	if !record.Process.Observed || !record.Process.PIDStartObserved || len(record.Process.AncestryRefs) == 0 ||
		record.Process.RawPIDsStored || record.Process.ExecutablePathsStored {
		t.Fatalf("unexpected process evidence: %+v", record.Process)
	}
	if record.ToolInputFeatures.RawCommandStored || record.ToolInputFeatures.RawTokensStored {
		t.Fatalf("raw tool input flags must remain false: %+v", record.ToolInputFeatures)
	}
}

func TestRunRelaysUserPromptAndExactToolInputWithoutPersistingEither(t *testing.T) {
	tests := []struct {
		name       string
		event      map[string]any
		wantKind   string
		wantPrompt string
		wantInput  string
		wantTool   string
		wantFamily string
	}{
		{
			name: "current prompt",
			event: map[string]any{
				"hook_event_name": "UserPromptSubmit",
				"prompt":          "E1_PROMPT_RELAY_MEMORY_ONLY_SENTINEL",
			},
			wantKind:   "prompt-observation",
			wantPrompt: "E1_PROMPT_RELAY_MEMORY_ONLY_SENTINEL",
		},
		{
			name: "exact tool input",
			event: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "Bash",
				"tool_use_id":     "tool-use-test-alpha",
				"tool_input": map[string]any{
					"command":       "E1_TOOL_INPUT_RELAY_MEMORY_ONLY_SENTINEL",
					"yield_time_ms": 10000,
				},
			},
			wantKind:  "host-observation",
			wantInput: `{"command":"E1_TOOL_INPUT_RELAY_MEMORY_ONLY_SENTINEL","yield_time_ms":10000}`,
			wantTool:  "Bash",
		},
		{
			name: "freeform exec input",
			event: map[string]any{
				"hook_event_name": "PreToolUse",
				"tool_name":       "exec",
				"tool_use_id":     "tool-use-test-exec",
				"tool_input":      "await tools.exec_command({cmd: `mac-peer macbook true`});",
			},
			wantKind:   "host-observation",
			wantInput:  "\"await tools.exec_command({cmd: `mac-peer macbook true`});\"",
			wantTool:   "functions.exec",
			wantFamily: "ssh",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			transcriptPath := filepath.Join(root, "transcript.jsonl")
			resultPath := filepath.Join(root, "result.json")
			writeTestSessionMetadata(t, transcriptPath, "session-test-alpha", root)
			coreSocket, requests := startHookRelayServer(t)
			input := map[string]any{
				"session_id":      "session-test-alpha",
				"transcript_path": transcriptPath,
				"cwd":             root,
				"model":           "gpt-5.6-luna",
				"permission_mode": "dontAsk",
				"turn_id":         "turn-test-alpha",
			}
			for key, value := range test.event {
				input[key] = value
			}
			encodedInput, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			var stdout bytes.Buffer
			run(
				[]string{"--result-path", resultPath, "--core-socket", coreSocket},
				bytes.NewReader(encodedInput),
				&stdout,
			)
			if stdout.String() != "{}\n" {
				t.Fatalf("unexpected stdout: %q", stdout.String())
			}
			request := receiveHookRelayRequest(t, requests)
			if request.Kind != test.wantKind {
				t.Fatalf("relay kind=%q", request.Kind)
			}
			if test.wantPrompt != "" && (request.Prompt == nil || string(request.Prompt.Prompt) != test.wantPrompt) {
				t.Fatalf("prompt was not relayed exactly: %+v", request.Prompt)
			}
			if test.wantInput != "" && (request.Host == nil || string(request.Host.ToolInput) != test.wantInput) {
				t.Fatalf("tool input was not relayed exactly: %+v", request.Host)
			}
			if test.wantTool != "" && (request.Host == nil || request.Host.ToolName != test.wantTool) {
				t.Fatalf("tool name was not normalized: %+v", request.Host)
			}
			if test.wantFamily != "" && (request.Host == nil || !slices.Contains(request.Host.ToolInputFeatures.Families, test.wantFamily)) {
				t.Fatalf("tool purpose family was not derived: %+v", request.Host)
			}
			encodedResult, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{test.wantPrompt, "E1_TOOL_INPUT_RELAY_MEMORY_ONLY_SENTINEL"} {
				if forbidden != "" && bytes.Contains(encodedResult, []byte(forbidden)) {
					t.Fatalf("result persisted relayed content: %q", forbidden)
				}
			}
			var record hookRecord
			if json.Unmarshal(encodedResult, &record) != nil || record.ErrorCode != nil || !record.ContextRelayed {
				t.Fatalf("unexpected relay record: %+v", record)
			}
		})
	}
}

func TestRunCanRelayWithoutCreatingDiagnosticArtifact(t *testing.T) {
	root := t.TempDir()
	transcriptPath := filepath.Join(root, "transcript.jsonl")
	writeTestSessionMetadata(t, transcriptPath, "session-test-alpha", root)
	coreSocket, requests := startHookRelayServer(t)
	encodedInput, err := json.Marshal(map[string]any{
		"session_id":      "session-test-alpha",
		"transcript_path": transcriptPath,
		"cwd":             root,
		"hook_event_name": "UserPromptSubmit",
		"model":           "gpt-5.6-luna",
		"permission_mode": "dontAsk",
		"turn_id":         "turn-test-alpha",
		"prompt":          "memory-only prompt",
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run([]string{"--core-socket", coreSocket}, bytes.NewReader(encodedInput), &stdout)
	if stdout.String() != "{}\n" {
		t.Fatalf("unexpected stdout: %q", stdout.String())
	}
	if request := receiveHookRelayRequest(t, requests); request.Kind != "prompt-observation" {
		t.Fatalf("prompt relay failed: %+v", request)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(transcriptPath) {
		t.Fatalf("hook created an unexpected diagnostic artifact: %+v", entries)
	}
}

func TestRunRelaysOriginalToolInputWithoutRewritingVisibleCommand(t *testing.T) {
	root := t.TempDir()
	transcriptPath := filepath.Join(root, "transcript.jsonl")
	resultPath := filepath.Join(root, "result.json")
	writeTestSessionMetadata(t, transcriptPath, "session-test-alpha", root)
	coreSocket, requests := startHookRelayServer(t)
	originalCommand := "git commit -m reviewed && ssh git@example.invalid"
	encodedInput, err := json.Marshal(map[string]any{
		"session_id":      "session-test-alpha",
		"transcript_path": transcriptPath,
		"cwd":             root,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-5.6-luna",
		"permission_mode": "dontAsk",
		"turn_id":         "turn-test-alpha",
		"tool_name":       "Bash",
		"tool_use_id":     "tool-use-test-alpha",
		"tool_input": map[string]any{
			"command":       originalCommand,
			"yield_time_ms": 10000,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run(
		[]string{
			"--result-path", resultPath,
			"--core-socket", coreSocket,
		},
		bytes.NewReader(encodedInput),
		&stdout,
	)
	request := receiveHookRelayRequest(t, requests)
	var relayedToolInput struct {
		Command     string `json:"command"`
		YieldTimeMS int    `json:"yield_time_ms"`
	}
	if request.Host == nil || bytes.Contains(request.Host.ToolInput, []byte("export PATH=")) ||
		json.Unmarshal(request.Host.ToolInput, &relayedToolInput) != nil ||
		relayedToolInput.Command != originalCommand || relayedToolInput.YieldTimeMS != 10000 {
		t.Fatalf("Core did not receive the exact original tool input: %+v", request.Host)
	}
	if stdout.String() != "{}\n" || bytes.Contains(stdout.Bytes(), []byte("updatedInput")) ||
		bytes.Contains(stdout.Bytes(), []byte(originalCommand)) {
		t.Fatalf("observation-only hook changed or repeated the visible command: %q", stdout.String())
	}
	encodedResult, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encodedResult, []byte(originalCommand)) ||
		bytes.Contains(encodedResult, []byte(testToolRef)) {
		t.Fatal("privacy-safe hook record persisted transport input")
	}
	var record hookRecord
	if json.Unmarshal(encodedResult, &record) != nil || record.ErrorCode != nil ||
		!record.ContextRelayed || record.TransportInjected {
		t.Fatalf("unexpected hook record: %+v", record)
	}
}

func TestRunDoesNotRewriteCommandWhenCoreOmitsToolRef(t *testing.T) {
	root := t.TempDir()
	transcriptPath := filepath.Join(root, "transcript.jsonl")
	resultPath := filepath.Join(root, "result.json")
	writeTestSessionMetadata(t, transcriptPath, "session-test-alpha", root)
	coreSocket, requests := startHookRelayServerWithToolRef(t, "")
	encodedInput, err := json.Marshal(map[string]any{
		"session_id":      "session-test-alpha",
		"transcript_path": transcriptPath,
		"cwd":             root,
		"hook_event_name": "PreToolUse",
		"model":           "gpt-5.6-luna",
		"permission_mode": "dontAsk",
		"turn_id":         "turn-test-alpha",
		"tool_name":       "Bash",
		"tool_use_id":     "tool-use-test-alpha",
		"tool_input":      map[string]any{"command": "ssh example.invalid"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	run([]string{
		"--result-path", resultPath,
		"--core-socket", coreSocket,
	}, bytes.NewReader(encodedInput), &stdout)
	if request := receiveHookRelayRequest(t, requests); request.Kind != "host-observation" {
		t.Fatalf("host observation was not relayed: %+v", request)
	}
	if stdout.String() != "{}\n" {
		t.Fatalf("unbound command was rewritten: %q", stdout.String())
	}
	encodedResult, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var record hookRecord
	if json.Unmarshal(encodedResult, &record) != nil || record.ErrorCode == nil ||
		*record.ErrorCode != "core-context-relay-failed" || record.TransportInjected {
		t.Fatalf("missing tool ref did not fail closed: %+v", record)
	}
}

func TestRemovedCommandMutationFlagsAreRejectedWithoutOutputMutation(t *testing.T) {
	var stdout bytes.Buffer
	run([]string{
		"--core-socket", "/tmp/not-contacted.sock",
		"--enter-tool-ref", testToolRef,
	}, strings.NewReader(""), &stdout)
	if stdout.String() != "{}\n" || bytes.Contains(stdout.Bytes(), []byte("updatedInput")) {
		t.Fatalf("removed mutation flag changed hook output: %q", stdout.String())
	}
}

func TestManagedConfigurationObservesEventsWithoutResultFiles(t *testing.T) {
	encoded, err := os.ReadFile("managed.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	configuration := string(encoded)
	for _, required := range []string{
		"[[hooks.UserPromptSubmit]]",
		"[[hooks.UserPromptSubmit.hooks]]",
		"[[hooks.PreToolUse]]",
		"matcher = \"^(Bash|exec|functions\\\\.exec)$\"",
		"[[hooks.PreToolUse.hooks]]",
		"--core-socket '/Library/Application Support/Beholder/run/core.sock'",
	} {
		if !strings.Contains(configuration, required) {
			t.Fatalf("managed config is missing %q", required)
		}
	}
	if strings.Count(configuration, "--core-socket") != 6 ||
		strings.Contains(configuration, "--ssh-shim-dir") ||
		strings.Contains(configuration, "--enter-tool-ref") ||
		strings.Contains(configuration, "--result-path") {
		t.Fatalf("managed config has the wrong transport/privacy shape: %s", configuration)
	}
}

func TestRunClassifiesSessionMetadataMismatch(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	transcriptPath := filepath.Join(root, "transcript.jsonl")
	resultPath := filepath.Join(root, "result.json")
	writeTestSessionMetadata(t, transcriptPath, "session-test-alpha", root)
	input := strings.NewReader(`{
		"session_id":"session-test-bravo",
		"transcript_path":` + quotedJSON(t, transcriptPath) + `,
		"cwd":` + quotedJSON(t, root) + `,
		"hook_event_name":"PreToolUse",
		"model":"gpt-5.6-luna",
		"permission_mode":"dontAsk",
		"turn_id":"turn-test-bravo",
		"tool_name":"Bash",
		"tool_use_id":"tool-use-test-bravo",
		"tool_input":{"command":"ignored"}
	}`)
	var stdout bytes.Buffer
	run([]string{"--result-path", resultPath}, input, &stdout)

	encodedResult, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	var record hookRecord
	if err := json.Unmarshal(encodedResult, &record); err != nil {
		t.Fatal(err)
	}
	if record.ErrorCode == nil || *record.ErrorCode != "hook-evidence-conflict" {
		t.Fatalf("expected hook-evidence-conflict, got %+v", record)
	}
	if record.SessionMetadataMatched {
		t.Fatal("mismatched session metadata was reported as matched")
	}
}

func writeTestSessionMetadata(t *testing.T, path, sessionID, cwd string) {
	t.Helper()
	line, err := json.Marshal(map[string]any{
		"type": "session_meta",
		"payload": map[string]any{
			"id":  sessionID,
			"cwd": cwd,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')
	if err := os.WriteFile(path, line, 0o600); err != nil {
		t.Fatal(err)
	}
}

func quotedJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func startHookRelayServer(t *testing.T) (string, <-chan hookRelayRequest) {
	return startHookRelayServerWithToolRef(t, testToolRef)
}

func startHookRelayServerWithToolRef(t *testing.T, toolRef string) (string, <-chan hookRelayRequest) {
	t.Helper()
	socketDir, err := os.MkdirTemp("/tmp", "beholder-e1-hook-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	path := filepath.Join(socketDir, "core.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan hookRelayRequest, 1)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request hookRelayRequest
		if json.NewDecoder(io.LimitReader(connection, maximumHookInputSize+1)).Decode(&request) != nil {
			return
		}
		requests <- request
		response := hookRelayResponse{
			SchemaVersion: hookRelaySchemaVersion,
			Accepted:      true,
		}
		if request.Kind == "host-observation" {
			response.ToolRef = toolRef
		}
		_ = json.NewEncoder(connection).Encode(response)
	}()
	return path, requests
}

func receiveHookRelayRequest(t *testing.T, requests <-chan hookRelayRequest) hookRelayRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(2 * time.Second):
		t.Fatal("hook relay timed out")
		return hookRelayRequest{}
	}
}
