package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	workerGatekeeperVersion = "beholder-worker-context-v1"
	workerConfigPath        = "/Library/Application Support/Beholder/config/worker-context.json"
)

type workerServiceConfiguration struct {
	SchemaVersion int    `json:"schema_version"`
	MayPath       string `json:"may_path"`
	MaySHA256     string `json:"may_sha256"`
	UserHome      string `json:"user_home"`
	GatewayOrigin string `json:"gateway_origin"`
}

func runWorkerServe(socketPath, recordPath, evidenceRoot string, aliases map[string]string) {
	// Core authenticates the executable, not its argv. User-controlled flags
	// therefore cannot select an executable, provider route, or model alias.
	workerConfig, workerConfigSHA256, err := loadWorkerServiceConfiguration()
	if err != nil || !filepath.IsAbs(socketPath) || !filepath.IsAbs(recordPath) ||
		!filepath.IsAbs(evidenceRoot) || len(aliases) != 0 {
		fatal("invalid Worker context service configuration")
	}
	records, err := newRecordWriter(recordPath)
	if err != nil {
		fatal("initialize context record writer failed")
	}
	evidence, err := newEvidenceStore(evidenceRoot)
	if err != nil {
		fatal("initialize context evidence store failed")
	}
	evidence.collectorVersion = workerGatekeeperVersion
	binarySHA, err := currentExecutableSHA256()
	if err != nil {
		fatal("context service executable identity unavailable")
	}
	var config confirmedConfig
	config.Retrieval.Enabled = true
	config.Invocation.TimeoutMS = 30000
	config.Invocation.MaximumConcurrency = 5
	config.Comparison.TimeoutMS = 180000
	config.Comparison.MaximumParallelPairs = 2
	config.Provider.Name = "Beholder Worker"
	service := &gatekeeperService{
		config: config, configSHA256: workerConfigSHA256,
		targetAliases: aliases, records: records, evidence: evidence,
		semaphore: make(chan struct{}, 5), waitingSlots: make(chan struct{}, 5),
		comparisonSemaphore: make(chan struct{}, 2), binarySHA256: binarySHA,
		policySHA256: gatekeeperPolicySHA256(), buildInput: buildRetrievalDecisionInput,
		workerMayPath: workerConfig.MayPath, workerMaySHA256: workerConfig.MaySHA256,
		workerMayHome: workerConfig.UserHome, workerGatewayOrigin: workerConfig.GatewayOrigin,
	}
	defer service.close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema_version": 1, "ready": true, "mode": "worker-context",
		"policy_sha256": service.policySHA256,
	})
	if err := serveGatekeeper(ctx, socketPath, service, 0); err != nil {
		fatal("Worker context service failed")
	}
}

// The human-controlled installer must create this fixed, root-owned file and
// its parent directories. A same-user process cannot select a different file
// or point the trusted Gatekeeper at an executable that fabricates decisions.
func loadWorkerServiceConfiguration() (workerServiceConfiguration, string, error) {
	var config workerServiceConfiguration
	var fileInfo os.FileInfo
	for current := workerConfigPath; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return config, "", errors.New("Worker configuration is not root-controlled")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return config, "", errors.New("Worker configuration is not root-owned")
		}
		if current == workerConfigPath {
			if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
				return config, "", errors.New("Worker configuration is invalid")
			}
			fileInfo = info
		} else if !info.IsDir() {
			return config, "", errors.New("Worker configuration parent is invalid")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	file, err := os.Open(workerConfigPath)
	if err != nil {
		return config, "", errors.New("Worker configuration is unavailable")
	}
	opened, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, 64*1024+1))
	_ = file.Close()
	defer clear(data)
	if statErr != nil || !os.SameFile(fileInfo, opened) || readErr != nil || len(data) > 64*1024 {
		return config, "", errors.New("Worker configuration changed while reading")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.SchemaVersion != 1 ||
		!validWorkerGatewayOrigin(config.GatewayOrigin) || !validWorkerHome(config.UserHome) ||
		verifyWorkerMay(config.MayPath, config.MaySHA256) != nil {
		return workerServiceConfiguration{}, "", errors.New("Worker configuration is invalid")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return workerServiceConfiguration{}, "", errors.New("Worker configuration has trailing data")
	}
	return config, digestValue(data), nil
}

func validWorkerHome(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") || os.Getuid() == 0 {
		return false
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (current == path && stat.Uid != uint32(os.Getuid())) ||
			(current != path && (stat.Uid != 0 || info.Mode().Perm()&0o022 != 0)) {
			return false
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return true
}

// The service may authorize through Core, so its network helper must be an
// immutable, root-controlled copy of the confirmed OneNod release. A mutable
// user-owned executable could fabricate a Worker decision on stdout.
func verifyWorkerMay(path, expected string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(expected) != sha256.Size*2 {
		return errors.New("invalid Worker requester path")
	}
	if _, err := hex.DecodeString(expected); err != nil || expected != strings.ToLower(expected) {
		return errors.New("invalid Worker requester digest")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		stat, ok := func() (*syscall.Stat_t, bool) {
			if err != nil {
				return nil, false
			}
			value, valid := info.Sys().(*syscall.Stat_t)
			return value, valid
		}()
		if err != nil || !ok || stat.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("Worker requester is not root-controlled")
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256*1024*1024 {
				return errors.New("Worker requester executable invalid")
			}
			file, openErr := os.Open(path)
			if openErr != nil {
				return errors.New("Worker requester unavailable")
			}
			opened, statErr := file.Stat()
			hash := sha256.New()
			_, readErr := io.Copy(hash, io.LimitReader(file, 256*1024*1024+1))
			_ = file.Close()
			if statErr != nil || !os.SameFile(info, opened) || readErr != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
				return errors.New("Worker requester digest mismatch")
			}
		} else if !info.IsDir() {
			return errors.New("Worker requester parent invalid")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func validWorkerGatewayOrigin(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func safeWorkerDeviceID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:-", r) {
			continue
		}
		return false
	}
	return true
}

type workerDecisionResponse struct {
	Phase      string              `json:"phase"`
	Capability string              `json:"capability"`
	Round      int                 `json:"round"`
	Calls      []retrievalToolCall `json:"calls"`
	Result     struct {
		Decision    string  `json:"decision"`
		Reason      string  `json:"reason"`
		ErrorCode   *string `json:"error_code"`
		ModelCalled bool    `json:"model_called"`
		ModelUsed   bool    `json:"model_used"`
		ModelRounds int     `json:"model_rounds"`
	} `json:"result"`
}

func (service *gatekeeperService) callWorkerRetrievalModel(content []byte, bundle *evidenceBundle, evidenceID string, variant modelCallVariant, deadlines ...time.Time) (result modelCallResult) {
	started := time.Now()
	result = failedModelCallResult("worker-decision-unavailable", 0)
	result.modelTransport = "worker"
	defer func() {
		result.latencyMS = time.Since(started).Milliseconds()
		if bundle == nil {
			return
		}
		// The detailed request and provider response live only in the Worker.
		// Finalize the existing local evidence lifecycle with metadata, so it
		// remains correlatable without claiming a local raw response exists.
		request := modelRequestEvidence{
			SchemaVersion: 1, RecordType: "beholder_model_request", EvidenceID: evidenceID,
			Variant: variant.name, Method: "POST", Endpoint: "beholder-worker",
			ContentType: "application/json", StartedAt: started.UTC(), RequestSent: result.modelCalled,
		}
		if !result.modelCalled && result.errorCode != "" {
			request.BuildError = stringPointer(result.errorCode)
		}
		if err := bundle.writeModelRequestVariant(variant.requestFile, request); err != nil {
			result.decision, result.modelUsed = "escalate", false
			result.errorCode = "evidence-model-request-write-failed"
			result.reason = localFailureReason(result.errorCode)
		}
		response := localResponseFromModelResult(evidenceID, result)
		response.Reason = "Decision recorded by the Beholder Worker."
		response.ScopeResolution = ""
		response.EvidenceRefs = nil
		if err := service.finishEvidenceBundleVariant(bundle, response, nil, 0, optionalString(result.errorCode), false, variant); err != nil {
			result.decision, result.modelUsed = "escalate", false
			result.errorCode = "evidence-model-response-write-failed"
			result.reason = localFailureReason(result.errorCode)
		}
	}()
	if bundle == nil || bundle.retrieval == nil || !safeWorkerDeviceID(bundle.workerRequesterID) {
		return result
	}
	workerVariant, budget := "primary", 30*time.Second
	if variant.name == comparisonVariantName {
		workerVariant, budget = "comparison", 180*time.Second
	}
	deadline := started.Add(budget)
	for _, candidate := range deadlines {
		if !candidate.IsZero() && candidate.Before(deadline) {
			deadline = candidate
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	remaining := time.Until(deadline).Milliseconds()
	if remaining <= 0 {
		return result
	}
	response, err := service.workerStep(ctx, evidenceID, workerVariant, "start", bundle.workerRequesterID, map[string]any{
		"input": string(content), "budget_ms": remaining,
	})
	if err != nil {
		return result
	}
	capability := response.Capability
	if len(capability) != 43 {
		return result
	}
	readEvidence := false
	for rounds := 0; rounds <= maximumRetrievalRounds; rounds++ {
		if response.Phase == "finished" {
			value := response.Result
			if (value.Decision != "allow" && value.Decision != "escalate") || !validModelReason(value.Reason) ||
				len(value.Reason) > 16*1024 || value.ModelRounds < 0 || value.ModelRounds > maximumRetrievalRounds ||
				(value.Decision == "allow" && (!value.ModelCalled || !value.ModelUsed || value.ErrorCode != nil || !readEvidence)) {
				return result
			}
			result.decision, result.reason = value.Decision, value.Reason
			result.modelCalled, result.modelUsed, result.modelRounds = value.ModelCalled, value.ModelUsed, value.ModelRounds
			result.responseShape = "worker-decision"
			if value.ErrorCode != nil && safeReasonCode(*value.ErrorCode) {
				result.errorCode = *value.ErrorCode
			} else {
				result.errorCode = ""
			}
			return result
		}
		if response.Phase != "tools" || response.Round != rounds+1 || len(response.Calls) == 0 || len(response.Calls) > maximumRoundToolCalls {
			return result
		}
		outputs := executeRetrievalCalls(ctx, bundle.retrieval.store, response.Calls)
		items := make([]map[string]string, len(outputs))
		for index, output := range outputs {
			items[index] = map[string]string{"tool_call_id": output.CallID, "content": output.Content}
			if output.Result.Error == "" {
				readEvidence = true
			}
			result.toolCalls++
			result.toolLatencyMS += output.LatencyMS
		}
		response, err = service.workerStep(ctx, evidenceID, workerVariant, "step", bundle.workerRequesterID, map[string]any{
			"capability": capability, "round": response.Round, "outputs": items,
		})
		if err != nil {
			return result
		}
	}
	return result
}

func (service *gatekeeperService) workerStep(ctx context.Context, evidenceID, variant, action, deviceID string, body any) (workerDecisionResponse, error) {
	var response workerDecisionResponse
	if err := verifyWorkerMay(service.workerMayPath, service.workerMaySHA256); err != nil {
		return response, err
	}
	input, err := json.Marshal(map[string]any{
		"evidence_id": evidenceID, "variant": variant, "action": action, "body": body,
	})
	if err != nil || len(input) > 16*1024*1024 {
		clear(input)
		return response, errors.New("Worker message invalid")
	}
	defer clear(input)
	var output limitedBuffer
	output.maximum = 1024 * 1024
	command := exec.CommandContext(ctx, service.workerMayPath, "__beholder-worker-step", service.workerGatewayOrigin, deviceID)
	// Exclude proxy, loader, certificate and runtime overrides supplied by the
	// user that launched Gatekeeper; only the confirmed account home is needed.
	command.Env = []string{"HOME=" + service.workerMayHome}
	command.Stdin, command.Stdout, command.Stderr = bytes.NewReader(input), &output, io.Discard
	if command.Run() != nil || output.overflow || json.Unmarshal(output.buffer.Bytes(), &response) != nil {
		output.clear()
		return response, errors.New("Worker decision transport failed")
	}
	output.clear()
	return response, nil
}
