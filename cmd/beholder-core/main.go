package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type codexHookInput struct {
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

type hookAck struct {
	SchemaVersion int     `json:"schema_version"`
	Accepted      bool    `json:"accepted"`
	ErrorCode     *string `json:"error_code"`
	RawStored     bool    `json:"raw_stored"`
}

var productVersion = "development"
var sourceCommit = "unknown"
var releaseTag = ""

func main() {
	var mode, socketPath, sessionRoot, trustMode, trustedHookPath, trustedHookSHA256, resultPath string
	var proxyRoot, upstreamAgentPath, trustedAgentPath, trustedAgentSHA256, outcomeStateRoot, outcomeQueueRoot string
	var gatekeeperSocket, trustedGatekeeperPath, trustedGatekeeperSHA256 string
	var authorityMode, authorityKeyPath string
	var scenario, surface, marker, operation, targetKind, targetID string
	var maximumConnections int
	var productionUID int
	var daemon bool
	var claimTTL, idleTimeout, bindingTTL, proxyTimeout, gatekeeperTimeout time.Duration
	flag.StringVar(&mode, "mode", "", "identity, authority-init, serve, hook, or request")
	flag.StringVar(&socketPath, "socket", "", "absolute private Unix socket path")
	flag.StringVar(&sessionRoot, "session-root", "", "absolute Codex session root")
	flag.StringVar(&trustMode, "trust-mode", "fixture", "fixture or production")
	flag.StringVar(&trustedHookPath, "trusted-hook", "", "absolute production managed hook path")
	flag.StringVar(&trustedHookSHA256, "trusted-hook-sha256", "", "exact production managed hook SHA-256")
	flag.StringVar(&resultPath, "result-path", "", "optional absolute privacy-safe hook acknowledgement path")
	flag.StringVar(&proxyRoot, "proxy-root", "", "optional absolute root for task-local Agent sockets")
	flag.StringVar(&upstreamAgentPath, "upstream-agent", "", "optional absolute OneNod Agent socket")
	flag.StringVar(&trustedAgentPath, "trusted-agent", "", "optional exact OneNod Agent executable path")
	flag.StringVar(&trustedAgentSHA256, "trusted-agent-sha256", "", "optional exact OneNod Agent SHA-256")
	flag.StringVar(&outcomeStateRoot, "outcome-state-root", "", "private durable human-outcome correlation root")
	flag.StringVar(&outcomeQueueRoot, "outcome-queue-root", "", "private durable human-outcome delivery queue")
	flag.StringVar(&gatekeeperSocket, "gatekeeper-socket", "", "optional E2 shadow Gatekeeper Unix socket")
	flag.StringVar(&trustedGatekeeperPath, "trusted-gatekeeper", "", "optional exact E2 shadow Gatekeeper executable")
	flag.StringVar(&trustedGatekeeperSHA256, "trusted-gatekeeper-sha256", "", "optional exact E2 shadow Gatekeeper SHA-256")
	flag.StringVar(&authorityMode, "authority-mode", "human-only", "human-only or dogfood-v1")
	flag.StringVar(&authorityKeyPath, "authority-key", "", "absolute root-controlled Beholder Ed25519 authority key")
	flag.IntVar(&maximumConnections, "max-connections", 2, "connections before fixture server exits")
	flag.IntVar(&productionUID, "production-uid", -1, "allowed user UID and socket owner in production")
	flag.BoolVar(&daemon, "daemon", false, "serve until SIGTERM instead of using fixture connection limits")
	flag.DurationVar(&claimTTL, "claim-ttl", 30*time.Second, "unowned tool-input cache TTL; claimed observations follow execution lifetime")
	flag.DurationVar(&idleTimeout, "idle-timeout", 45*time.Second, "fixture server idle timeout")
	flag.DurationVar(&bindingTTL, "binding-ttl", 30*time.Second, "in-memory transport binding TTL")
	flag.DurationVar(&proxyTimeout, "proxy-timeout", 12*time.Minute, "maximum task-local Agent proxy lifetime")
	flag.DurationVar(&gatekeeperTimeout, "gatekeeper-timeout", 610*time.Second, "E2 shadow Gatekeeper round-trip timeout")
	flag.StringVar(&scenario, "scenario", "beholder-core-fixture", "non-secret scenario label")
	flag.StringVar(&surface, "surface", "tool-child", "request surface")
	flag.StringVar(&marker, "marker", "", "non-secret one-time request nonce")
	flag.StringVar(&operation, "operation", "probe.observe", "structured request operation")
	flag.StringVar(&targetKind, "target-kind", "none", "structured target kind")
	flag.StringVar(&targetID, "target-id", "", "optional non-secret fixture target id")
	flag.Parse()

	if flag.NArg() != 0 || (mode != "identity" && mode != "authority-init" && !filepath.IsAbs(socketPath)) {
		fatal("invalid command input")
	}
	switch mode {
	case "identity":
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema_version": 1, "component": "beholder-core", "core_version": "e1-core-v30",
			"product_version": productVersion, "source_commit": sourceCommit, "release_tag": releaseTag,
		})
	case "authority-init":
		if authorityMode != "dogfood-v1" || !filepath.IsAbs(authorityKeyPath) {
			fatal("invalid Beholder authority initialization")
		}
		identity, err := initializeBeholderAuthority(authorityKeyPath, os.Geteuid() == 0)
		if err != nil {
			fatal(err.Error())
		}
		_ = json.NewEncoder(os.Stdout).Encode(identity)
	case "serve":
		if !filepath.IsAbs(sessionRoot) {
			fatal("invalid session root")
		}
		core, err := newBroker(
			sessionRoot, trustMode, trustedHookPath, trustedHookSHA256, claimTTL,
		)
		if err != nil {
			fatal("broker initialization failed: " + err.Error())
		}
		defer core.close()
		if trustMode == "production" {
			if err := core.configureProductionUser(productionUID); err != nil {
				fatal("production user configuration failed: " + err.Error())
			}
			if err := core.configurePromptLedger(productionPromptLedgerRoot); err != nil {
				fatal("prompt ledger initialization failed")
			}
		}
		switch authorityMode {
		case "human-only":
			if authorityKeyPath != "" {
				fatal("human-only mode cannot load a Beholder authority key")
			}
		case "dogfood-v1":
			if trustMode != "production" || !filepath.IsAbs(authorityKeyPath) {
				fatal("invalid Beholder authority configuration")
			}
			authority, err := loadBeholderAuthority(authorityKeyPath, true)
			if err != nil || core.configureAuthority(authority) != nil {
				if authority != nil {
					authority.close()
				}
				fatal("Beholder authority initialization failed")
			}
		default:
			fatal("unsupported Beholder authority mode")
		}
		if gatekeeperSocket != "" || trustedGatekeeperPath != "" || trustedGatekeeperSHA256 != "" {
			if trustMode != "production" || gatekeeperSocket == "" || trustedGatekeeperPath == "" ||
				trustedGatekeeperSHA256 == "" || productionUID <= 0 {
				fatal("invalid shadow Gatekeeper configuration")
			}
			gatekeeper, err := newShadowGatekeeperClient(
				gatekeeperSocket, trustedGatekeeperPath, trustedGatekeeperSHA256,
				uint32(productionUID), gatekeeperTimeout,
			)
			if err != nil || core.configureShadowGatekeeper(gatekeeper) != nil {
				fatal("shadow Gatekeeper initialization failed")
			}
		}
		if authorityMode == "dogfood-v1" && core.gatekeeper == nil {
			fatal("authoritative Beholder requires Gatekeeper")
		}
		var transport *transportCoordinator
		if proxyRoot != "" || upstreamAgentPath != "" {
			if !filepath.IsAbs(proxyRoot) || !filepath.IsAbs(upstreamAgentPath) ||
				(outcomeStateRoot != "" && !filepath.IsAbs(outcomeStateRoot)) ||
				(outcomeQueueRoot != "" && !filepath.IsAbs(outcomeQueueRoot)) ||
				(outcomeQueueRoot != "" && outcomeStateRoot == "") ||
				(trustMode == "production" && (outcomeStateRoot != productionOutcomeStateRoot ||
					outcomeQueueRoot != productionOutcomeQueueRoot)) {
				fatal("invalid transport paths")
			}
			stateRoots := []string{}
			if outcomeStateRoot != "" {
				stateRoots = append(stateRoots, outcomeStateRoot)
			}
			if outcomeQueueRoot != "" {
				stateRoots = append(stateRoots, outcomeQueueRoot)
			}
			transport, err = newTransportCoordinator(
				core, proxyRoot, upstreamAgentPath,
				trustedAgentPath, trustedAgentSHA256,
				bindingTTL, proxyTimeout,
				stateRoots...,
			)
			if err != nil {
				fatal("transport initialization failed: " + err.Error())
			}
			defer transport.close()
		}
		if daemon {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			go core.reapObservations(ctx)
			if err := serveBrokerDaemon(ctx, socketPath, core, transport); err != nil {
				fatal("broker daemon failed: " + err.Error())
			}
		} else {
			summary, err := serveBrokerWithTransport(
				socketPath, core, transport, maximumConnections, idleTimeout,
			)
			if err != nil {
				fatal("broker server failed")
			}
			_ = json.NewEncoder(os.Stdout).Encode(summary)
		}
	case "hook":
		runHookClient(socketPath, resultPath)
	case "request":
		runRequestClient(socketPath, scenario, surface, marker, operation, targetKind, targetID)
	default:
		fatal("invalid mode")
	}
}

func runHookClient(socketPath, resultPath string) {
	ack := hookAck{SchemaVersion: protocolSchemaVersion}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, maximumWireSize+1))
	var input codexHookInput
	if decoder.Decode(&input) != nil {
		ack.ErrorCode = stringPointer("invalid-hook-input")
		writeHookAck(resultPath, ack)
		fmt.Fprintln(os.Stdout, "{}")
		return
	}
	var response wireResponse
	var err error
	switch input.HookEventName {
	case "UserPromptSubmit":
		prompt := []byte(input.Prompt)
		input.Prompt = ""
		response, err = roundTrip(socketPath, wireRequest{
			SchemaVersion: protocolSchemaVersion,
			Kind:          "prompt-observation",
			Prompt: &promptObservation{
				SessionID: input.SessionID, TurnID: input.TurnID,
				TranscriptPath: input.TranscriptPath, CWD: input.CWD,
				HookEventName: input.HookEventName, Model: input.Model,
				PermissionMode: input.PermissionMode,
				ObservedAt:     time.Now().UTC().Format(time.RFC3339Nano), Prompt: prompt,
			},
		})
		clear(prompt)
	case "PreToolUse":
		command, normalizedToolName, ok := hookToolCommand(input.ToolName, input.ToolInput)
		if !ok {
			ack.ErrorCode = stringPointer("invalid-hook-input")
			writeHookAck(resultPath, ack)
			fmt.Fprintln(os.Stdout, "{}")
			return
		}
		features := deriveToolInputFeatures(command)
		command = ""
		toolInput := append(json.RawMessage(nil), input.ToolInput...)
		clear(input.ToolInput)
		input.ToolInput = nil
		response, err = roundTrip(socketPath, wireRequest{
			SchemaVersion: protocolSchemaVersion,
			Kind:          "host-observation",
			Host: &hostObservation{
				SessionID: input.SessionID, TurnID: input.TurnID, ToolUseID: input.ToolUseID,
				TranscriptPath: input.TranscriptPath, CWD: input.CWD,
				HookEventName: input.HookEventName, ToolName: normalizedToolName,
				Model: input.Model, PermissionMode: input.PermissionMode,
				ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
				ToolInput:  toolInput, ToolInputFeatures: features,
			},
		})
		clear(toolInput)
	default:
		ack.ErrorCode = stringPointer("invalid-hook-input")
		writeHookAck(resultPath, ack)
		fmt.Fprintln(os.Stdout, "{}")
		return
	}
	if err != nil {
		ack.ErrorCode = stringPointer("broker-unavailable")
	} else {
		ack.Accepted = response.Accepted
		ack.ErrorCode = response.ErrorCode
	}
	writeHookAck(resultPath, ack)
	// Observation-only E1 hook. The request entry gate, not this hook output,
	// maps missing evidence to escalate.
	fmt.Fprintln(os.Stdout, "{}")
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

func runRequestClient(socketPath, scenario, surface, marker, operation, targetKind, targetID string) {
	threadID := os.Getenv("CODEX_THREAD_ID")
	sessionID := os.Getenv("CODEX_SESSION_ID")
	presence := environmentPresence{
		CodexThreadID: threadID != "", CodexSessionID: sessionID != "",
		ThreadSessionEqual: threadID != "" && threadID == sessionID,
		SSHAuthSock:        os.Getenv("SSH_AUTH_SOCK") != "",
		GitEnvironment:     hasAnyEnvironmentPrefix("GIT_"),
		PermissionProfile:  os.Getenv("CODEX_PERMISSION_PROFILE") != "",
	}
	if !safeLabel(scenario) || !safeLabel(surface) || !safeJoinKey(marker) {
		emitWireResponse(wireResponse{SchemaVersion: protocolSchemaVersion, ErrorCode: stringPointer("invalid-request-input")})
		return
	}
	request := requestObservation{
		ThreadID: threadID, Nonce: marker, Surface: surface, Operation: operation,
		TargetKind: targetKind, TargetID: targetID,
		ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), EnvironmentPresence: presence,
	}
	response, err := roundTrip(socketPath, wireRequest{
		SchemaVersion: protocolSchemaVersion, Kind: "request-observation",
		Request: &request,
	})
	if err != nil {
		emitWireResponse(wireResponse{SchemaVersion: protocolSchemaVersion, ErrorCode: stringPointer("broker-unavailable")})
		return
	}
	emitWireResponse(response)
}

func roundTrip(socketPath string, request wireRequest) (wireResponse, error) {
	connection, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return wireResponse{}, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return wireResponse{}, err
	}
	var response wireResponse
	if err := json.NewDecoder(io.LimitReader(connection, maximumWireSize+1)).Decode(&response); err != nil {
		return wireResponse{}, err
	}
	if response.SchemaVersion != protocolSchemaVersion {
		return wireResponse{}, errors.New("unsupported broker response")
	}
	return response, nil
}

func emitWireResponse(response wireResponse) {
	_ = json.NewEncoder(os.Stdout).Encode(response)
}

func writeHookAck(path string, ack hookAck) {
	if path == "" {
		return
	}
	if !filepath.IsAbs(path) {
		return
	}
	encoded, err := json.Marshal(ack)
	if err != nil {
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".beholder-core-hook-*.tmp")
	if err != nil {
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil {
		temporary.Close()
		return
	}
	if _, err := temporary.Write(encoded); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return
	}
	_ = os.Rename(temporaryPath, path)
}

func hasAnyEnvironmentPrefix(prefix string) bool {
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
