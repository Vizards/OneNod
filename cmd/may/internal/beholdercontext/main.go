package beholdercontext

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maximumHookInputSize = 2 * 1024 * 1024
const hookRelaySchemaVersion = 1

type hookInput struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	CWD            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	Model          string          `json:"model"`
	PermissionMode string          `json:"permission_mode"`
	TurnID         string          `json:"turn_id"`
	ToolName       string          `json:"tool_name"`
	ToolUseID      string          `json:"tool_use_id"`
	Prompt         string          `json:"prompt"`
	ToolInput      json.RawMessage `json:"tool_input"`
}

type sessionEnvelope struct {
	Type    string `json:"type"`
	Payload struct {
		ID  string `json:"id"`
		CWD string `json:"cwd"`
	} `json:"payload"`
}

type hookRecord struct {
	SchemaVersion          int               `json:"schema_version"`
	ObservedAt             string            `json:"observed_at"`
	HookEventName          string            `json:"hook_event_name"`
	Model                  string            `json:"model"`
	PermissionMode         string            `json:"permission_mode"`
	ToolName               string            `json:"tool_name"`
	SessionRef             string            `json:"session_ref,omitempty"`
	MetadataThreadRef      string            `json:"metadata_thread_ref,omitempty"`
	TurnRef                string            `json:"turn_ref,omitempty"`
	ToolUseRef             string            `json:"tool_use_ref,omitempty"`
	SessionMetadataMatched bool              `json:"session_metadata_matched"`
	CWDRelation            string            `json:"cwd_relation,omitempty"`
	Process                processEvidence   `json:"process"`
	ToolInputFeatures      toolInputFeatures `json:"tool_input_features"`
	ContextRelayed         bool              `json:"context_relayed"`
	TransportInjected      bool              `json:"transport_injected"`
	RawContentStored       bool              `json:"raw_content_stored"`
	RawIDsStored           bool              `json:"raw_ids_stored"`
	PathsStored            bool              `json:"paths_stored"`
	ErrorCode              *string           `json:"error_code"`
}

func RunWorker(args []string, stdin io.Reader, stdout io.Writer) {
	run(args, stdin, stdout)
}

func run(args []string, stdin io.Reader, stdout io.Writer) {
	if len(args) == 1 && args[0] == "--identity" {
		fmt.Fprintln(stdout, `{"component":"beholder-context-worker","schema_version":1,"relay_schema_version":1}`)
		return
	}
	var coreSocket, resultPath string
	flags := flag.NewFlagSet("beholder-e1-pretool-hook", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&resultPath, "result-path", "", "absolute privacy-safe hook result path")
	flags.StringVar(&coreSocket, "core-socket", "", "optional absolute Beholder Core socket")
	parseErr := flags.Parse(args)
	record := hookRecord{
		SchemaVersion:    2,
		ObservedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		RawContentStored: false,
		RawIDsStored:     false,
		PathsStored:      false,
	}
	if parseErr != nil || flags.NArg() != 0 || (resultPath != "" && !filepath.IsAbs(resultPath)) ||
		(coreSocket != "" && !filepath.IsAbs(coreSocket)) {
		writeHookResult(resultPath, fail(record, "invalid-hook-input"))
		fmt.Fprintln(stdout, "{}")
		return
	}

	decoder := json.NewDecoder(io.LimitReader(stdin, maximumHookInputSize+1))
	var input hookInput
	if decoder.Decode(&input) != nil || !validHookEventInput(input) ||
		!safeJoinKey(input.SessionID) || !safeJoinKey(input.TurnID) ||
		!filepath.IsAbs(input.TranscriptPath) || !filepath.IsAbs(input.CWD) || !safeLabel(input.Model) ||
		!safePermissionMode(input.PermissionMode) {
		writeHookResult(resultPath, fail(record, "invalid-hook-input"))
		fmt.Fprintln(stdout, "{}")
		return
	}
	record.HookEventName = input.HookEventName
	record.Model = input.Model
	record.PermissionMode = input.PermissionMode
	record.SessionRef = hashRef("session", input.SessionID)
	record.TurnRef = hashRef("turn", input.TurnID)
	if input.ToolUseID != "" {
		record.ToolUseRef = hashRef("tool-use", input.ToolUseID)
	}
	var exactToolInput json.RawMessage
	if input.HookEventName == "PreToolUse" {
		command, normalizedToolName, ok := hookToolCommand(input.ToolName, input.ToolInput)
		if !ok {
			writeHookResult(resultPath, fail(record, "invalid-hook-input"))
			fmt.Fprintln(stdout, "{}")
			return
		}
		input.ToolName = normalizedToolName
		record.ToolName = normalizedToolName
		record.ToolInputFeatures = deriveToolInputFeatures(command)
		command = ""
		exactToolInput = append(json.RawMessage(nil), input.ToolInput...)
		clear(input.ToolInput)
		input.ToolInput = nil
	}
	process, processErr := captureHookProcessEvidence(os.Getpid())
	record.Process = process
	if processErr != nil {
		writeHookResult(resultPath, fail(record, "hook-process-unavailable"))
		fmt.Fprintln(stdout, "{}")
		return
	}

	metadataID, metadataCWD, err := readSessionMetadata(input.TranscriptPath)
	if err != nil {
		writeHookResult(resultPath, fail(record, "session-metadata-unavailable"))
		fmt.Fprintln(stdout, "{}")
		return
	}
	record.MetadataThreadRef = hashRef("thread", metadataID)
	record.SessionMetadataMatched = input.SessionID == metadataID
	record.CWDRelation = cwdRelation(metadataCWD, input.CWD)
	if !record.SessionMetadataMatched ||
		(record.CWDRelation != "exact" && record.CWDRelation != "descendant") {
		writeHookResult(resultPath, fail(record, "hook-evidence-conflict"))
		fmt.Fprintln(stdout, "{}")
		return
	}
	if coreSocket != "" {
		var relayErr error
		_, relayErr = relayHookContext(coreSocket, input, exactToolInput, record.ToolInputFeatures)
		if relayErr != nil {
			clear(exactToolInput)
			input.Prompt = ""
			writeHookResult(resultPath, fail(record, "core-context-relay-failed"))
			fmt.Fprintln(stdout, "{}")
			return
		}
		record.ContextRelayed = true
	}
	clear(exactToolInput)
	input.Prompt = ""
	writeHookResult(resultPath, record)
	// Correlation is completed later by the actual OneNod requester process.
	// Keeping this hook observation-only preserves the exact command shown in
	// Codex and prevents instrumentation text from re-entering the transcript.
	fmt.Fprintln(stdout, "{}")
}

func hookToolCommand(toolName string, raw json.RawMessage) (string, string, bool) {
	switch toolName {
	case "Bash":
		var input struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(raw, &input) != nil || input.Command == "" {
			return "", "", false
		}
		return input.Command, "Bash", true
	case "exec", "functions.exec":
		var source string
		if json.Unmarshal(raw, &source) == nil && source != "" {
			return source, "functions.exec", true
		}
		var input struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(raw, &input) != nil || input.Code == "" {
			return "", "", false
		}
		return input.Code, "functions.exec", true
	default:
		return "", "", false
	}
}

type hookRelayRequest struct {
	SchemaVersion int                    `json:"schema_version"`
	Kind          string                 `json:"kind"`
	ThreadID      string                 `json:"thread_id,omitempty"`
	ToolRef       string                 `json:"tool_ref,omitempty"`
	Prompt        *hookPromptObservation `json:"prompt,omitempty"`
	Host          *hookHostObservation   `json:"host,omitempty"`
}

type hookPromptObservation struct {
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	HookEventName  string `json:"hook_event_name"`
	Model          string `json:"model"`
	PermissionMode string `json:"permission_mode"`
	ObservedAt     string `json:"observed_at"`
	Prompt         []byte `json:"prompt"`
}

type hookHostObservation struct {
	SessionID         string            `json:"session_id"`
	TurnID            string            `json:"turn_id"`
	ToolUseID         string            `json:"tool_use_id"`
	TranscriptPath    string            `json:"transcript_path"`
	CWD               string            `json:"cwd"`
	HookEventName     string            `json:"hook_event_name"`
	ToolName          string            `json:"tool_name"`
	Model             string            `json:"model"`
	PermissionMode    string            `json:"permission_mode"`
	ObservedAt        string            `json:"observed_at"`
	ToolInput         json.RawMessage   `json:"tool_input"`
	ToolInputFeatures toolInputFeatures `json:"tool_input_features"`
}

type hookRelayResponse struct {
	SchemaVersion int     `json:"schema_version"`
	Accepted      bool    `json:"accepted"`
	ToolRef       string  `json:"tool_ref,omitempty"`
	ErrorCode     *string `json:"error_code"`
}

func relayHookContext(
	coreSocket string,
	input hookInput,
	exactToolInput json.RawMessage,
	features toolInputFeatures,
) (string, error) {
	request := hookRelayRequest{SchemaVersion: hookRelaySchemaVersion}
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	switch input.HookEventName {
	case "UserPromptSubmit":
		prompt := []byte(input.Prompt)
		defer clear(prompt)
		request.Kind = "prompt-observation"
		request.Prompt = &hookPromptObservation{
			SessionID: input.SessionID, TurnID: input.TurnID,
			TranscriptPath: input.TranscriptPath, CWD: input.CWD,
			HookEventName: input.HookEventName, Model: input.Model,
			PermissionMode: input.PermissionMode, ObservedAt: observedAt, Prompt: prompt,
		}
	case "PreToolUse":
		request.Kind = "host-observation"
		request.Host = &hookHostObservation{
			SessionID: input.SessionID, TurnID: input.TurnID, ToolUseID: input.ToolUseID,
			TranscriptPath: input.TranscriptPath, CWD: input.CWD,
			HookEventName: input.HookEventName, ToolName: input.ToolName,
			Model: input.Model, PermissionMode: input.PermissionMode, ObservedAt: observedAt,
			ToolInput: exactToolInput, ToolInputFeatures: features,
		}
	default:
		return "", errors.New("unsupported hook event")
	}
	connection, err := net.DialTimeout("unix", coreSocket, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return "", err
	}
	var response hookRelayResponse
	if json.NewDecoder(io.LimitReader(connection, maximumHookInputSize+1)).Decode(&response) != nil ||
		response.SchemaVersion != hookRelaySchemaVersion || !response.Accepted || response.ErrorCode != nil {
		return "", errors.New("Core rejected hook context")
	}
	if input.HookEventName == "PreToolUse" {
		if !validToolRef(response.ToolRef) {
			return "", errors.New("Core omitted tool reference")
		}
		return response.ToolRef, nil
	}
	if response.ToolRef != "" {
		return "", errors.New("Core returned an unexpected tool reference")
	}
	return "", nil
}

func validToolRef(value string) bool {
	const prefix = "tool-selector-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func validHookEventInput(input hookInput) bool {
	switch input.HookEventName {
	case "UserPromptSubmit":
		return input.ToolName == "" && input.ToolUseID == "" && len(input.ToolInput) == 0 &&
			input.Prompt != "" && len(input.Prompt) <= maximumHookInputSize
	case "PreToolUse":
		return (input.ToolName == "Bash" || input.ToolName == "exec" || input.ToolName == "functions.exec") &&
			safeJoinKey(input.ToolUseID) && len(input.ToolInput) != 0 &&
			len(input.ToolInput) <= maximumHookInputSize && json.Valid(input.ToolInput) && input.Prompt == ""
	default:
		return false
	}
}

func readSessionMetadata(path string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for line := 0; line < 64 && scanner.Scan(); line++ {
		var envelope sessionEnvelope
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil {
			return "", "", errors.New("invalid session metadata")
		}
		if envelope.Type == "session_meta" && safeJoinKey(envelope.Payload.ID) && filepath.IsAbs(envelope.Payload.CWD) {
			return envelope.Payload.ID, envelope.Payload.CWD, nil
		}
	}
	return "", "", errors.New("session metadata not found")
}

func writeHookResult(path string, record hookRecord) {
	if !filepath.IsAbs(path) {
		return
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".pretool-hook-*.tmp")
	if err != nil {
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil {
		temporary.Close()
		return
	}
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return
	}
	if temporary.Sync() != nil || temporary.Close() != nil {
		return
	}
	_ = os.Rename(temporaryPath, path)
}

func fail(record hookRecord, code string) hookRecord {
	record.ErrorCode = &code
	return record
}

func hashRef(kind, value string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + value))
	return kind + "-" + hex.EncodeToString(digest[:8])
}

func cwdRelation(sessionCWD, hookCWD string) string {
	sessionClean := filepath.Clean(sessionCWD)
	hookClean := filepath.Clean(hookCWD)
	if sessionClean == hookClean {
		return "exact"
	}
	relative, err := filepath.Rel(sessionClean, hookClean)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "descendant"
	}
	return "different"
}

func safeJoinKey(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}

func safePermissionMode(value string) bool {
	switch value {
	case "default", "acceptEdits", "plan", "dontAsk", "bypassPermissions":
		return true
	default:
		return false
	}
}
