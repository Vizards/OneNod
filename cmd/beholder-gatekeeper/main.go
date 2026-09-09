package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

type aliasFlags map[string]string

var productVersion = "development"
var sourceCommit = "unknown"
var releaseTag = ""

func (values *aliasFlags) String() string { return "item-id=experiment-alias" }

func (values *aliasFlags) Set(value string) error {
	itemID, alias, found := strings.Cut(value, "=")
	if !found || itemID == "" || alias == "" || strings.ContainsAny(itemID+alias, "\r\n\x00") {
		return errors.New("invalid target alias")
	}
	if *values == nil {
		*values = map[string]string{}
	}
	if _, exists := (*values)[itemID]; exists {
		return errors.New("duplicate target alias")
	}
	(*values)[itemID] = alias
	return nil
}

func main() {
	var mode, configPath, configSHA256, socketPath, mayPath, recordPath, evidenceRoot, reference, scenario string
	var planPath, planSHA256, decisionBinarySHA256, evaluationPath, humanDecision string
	var benchmarkRoot, benchmarkResultPath string
	var requestID, taskRefSHA256, taskCWDRefSHA256 string
	var decisionStartLine int
	var benchPeerUID int
	var executed bool
	var aliases aliasFlags
	flag.StringVar(&mode, "mode", "", "serve, bench-serve, counterexample-plan, counterexample-bench, probe-read, identity, verify-config, or finalize")
	flag.StringVar(&configPath, "config", "", "absolute human-confirmed E2-AI0 JSON path")
	flag.StringVar(&configSHA256, "config-sha256", "", "exact confirmed config SHA-256")
	flag.StringVar(&socketPath, "socket", "", "absolute private Gatekeeper Unix socket")
	flag.StringVar(&mayPath, "may", defaultUserPath(".onenod", "bin", "may"), "fixed OneNod requester path")
	flag.StringVar(&recordPath, "record-path", "", "absolute privacy-safe shadow JSONL path")
	flag.StringVar(&evidenceRoot, "evidence-root", "", "absolute E2-OBS-2 evidence root")
	flag.StringVar(&reference, "reference", "", "non-secret op://Agent item/field reference")
	flag.StringVar(&scenario, "scenario", "", "non-secret experiment scenario label")
	flag.StringVar(&planPath, "plan", "", "absolute blinded scenario plan path")
	flag.StringVar(&planSHA256, "plan-sha256", "", "exact blinded scenario plan SHA-256")
	flag.StringVar(&decisionBinarySHA256, "decision-binary-sha256", "", "exact Gatekeeper binary SHA-256 that produced the decision")
	flag.StringVar(&evaluationPath, "evaluation-path", "", "absolute privacy-safe evaluation JSONL path")
	flag.StringVar(&benchmarkRoot, "benchmark-root", "", "absolute isolated counterexample benchmark root")
	flag.StringVar(&benchmarkResultPath, "benchmark-result", "", "absolute counterexample benchmark result path")
	flag.StringVar(&humanDecision, "human-decision", "", "approved, rejected, timed_out, or not_applicable")
	flag.StringVar(&requestID, "request-id", "", "exact unassigned Gatekeeper request ID to join after decision")
	flag.StringVar(&taskRefSHA256, "task-ref-sha256", "", "SHA-256 of the user-owned task ID")
	flag.StringVar(&taskCWDRefSHA256, "task-cwd-ref-sha256", "", "SHA-256 of the isolated task cwd")
	flag.IntVar(&decisionStartLine, "decision-start-line", -1, "decision JSONL line count captured before arming")
	flag.IntVar(&benchPeerUID, "bench-peer-uid", -1, "current user UID for the isolated E2-Bench socket")
	flag.BoolVar(&executed, "executed", false, "whether the existing human path executed the request")
	flag.Var(&aliases, "target-alias", "repeat item-id=experiment-alias mapping")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal("invalid command input")
	}
	switch mode {
	case "serve":
		if benchPeerUID != -1 {
			fatal("bench peer UID is invalid for production serve mode")
		}
		runServe(configPath, configSHA256, socketPath, mayPath, recordPath, evidenceRoot, aliases, 0)
	case "bench-serve":
		benchRoot := defaultUserPath("Library", "Caches", "Beholder", "e2", "bench-v5")
		if benchPeerUID <= 0 || benchPeerUID != os.Getuid() || !pathWithinBase(benchRoot, socketPath) ||
			!pathWithinBase(benchRoot, recordPath) {
			fatal("invalid isolated benchmark serve boundary")
		}
		runServe(configPath, configSHA256, socketPath, mayPath, recordPath, evidenceRoot, aliases, uint32(benchPeerUID))
	case "counterexample-plan":
		if err := writeCounterexamplePlan(planPath); err != nil {
			fatal("freeze counterexample plan failed: " + err.Error())
		}
	case "counterexample-bench":
		if err := runCounterexampleBenchmark(
			configPath, configSHA256, mayPath, planPath, planSHA256,
			benchmarkRoot, benchmarkResultPath,
		); err != nil {
			fatal("counterexample benchmark failed: " + err.Error())
		}
	case "probe-read":
		runProbeRead(mayPath, reference, scenario)
	case "identity":
		runIdentity()
	case "verify-config":
		_, actual, err := loadProductionConfig(configPath, configSHA256)
		if err != nil {
			fatal(err.Error())
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema_version": 1, "config_sha256": actual, "valid": true})
	case "finalize":
		if err := finalizeEvaluation(
			planPath, planSHA256, decisionBinarySHA256, recordPath, evaluationPath,
			scenario, humanDecision, executed,
		); err != nil {
			fatal("finalize evaluation failed: " + err.Error())
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema_version": 1, "ok": true, "scenario": scenario, "evaluation_written": true,
		})
	case "finalize-unassigned":
		if err := finalizeUnassignedEvaluation(
			planPath, planSHA256, decisionBinarySHA256, recordPath, evaluationPath,
			scenario, requestID, taskRefSHA256, taskCWDRefSHA256, decisionStartLine,
			humanDecision, executed,
		); err != nil {
			fatal("finalize unassigned evaluation failed: " + err.Error())
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"schema_version": 1, "ok": true, "scenario": scenario,
			"request_id": requestID, "evaluation_written": true,
		})
	default:
		fatal("invalid mode")
	}
}

func runIdentity() {
	binarySHA256, err := currentExecutableSHA256()
	if err != nil {
		fatal("Gatekeeper executable identity unavailable")
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"schema_version": 1, "gatekeeper_version": gatekeeperVersion,
		"binary_sha256": binarySHA256, "policy_sha256": gatekeeperPolicySHA256(),
		"component": "beholder-gatekeeper", "product_version": productVersion,
		"source_commit": sourceCommit, "release_tag": releaseTag, "config_sha256": confirmedConfigSHA256,
	})
}

func runServe(
	configPath, configSHA256, socketPath, mayPath, recordPath, evidenceRoot string,
	aliases map[string]string,
	allowedPeerUID uint32,
) {
	if !filepath.IsAbs(socketPath) || !filepath.IsAbs(recordPath) || !filepath.IsAbs(evidenceRoot) {
		fatal("invalid serve paths")
	}
	config, actualSHA256, err := loadProductionConfig(configPath, configSHA256)
	if err != nil {
		fatal(err.Error())
	}
	credential, err := readCredentialWithMay(mayPath, config.Authentication.OneNodReference, os.Stderr)
	if err != nil {
		fatal(err.Error())
	}
	defer clear(credential)
	records, err := newRecordWriter(recordPath)
	if err != nil {
		fatal("initialize privacy-safe record writer failed")
	}
	evidence, err := newEvidenceStore(evidenceRoot)
	if err != nil || filepath.Clean(evidenceRoot) != config.Observability.EvidenceRoot {
		fatal("initialize E2-OBS-2 evidence store failed")
	}
	service, err := newGatekeeperService(config, actualSHA256, credential, aliases, records, evidence)
	clear(credential)
	if err != nil {
		fatal(err.Error())
	}
	defer service.close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ready := map[string]any{
		"schema_version": 1, "ready": true, "mode": "shadow",
		"provider": config.Provider.Name, "model": config.Model.PrimaryID,
		"config_sha256": actualSHA256, "raw_content_stored": true,
		"evidence_root": evidenceRoot, "evidence_contract": "E2-OBS-2",
	}
	_ = json.NewEncoder(os.Stdout).Encode(ready)
	if err := serveGatekeeper(ctx, socketPath, service, allowedPeerUID); err != nil {
		fatal("Gatekeeper server failed: " + err.Error())
	}
}

func pathWithinBase(base, candidate string) bool {
	if !filepath.IsAbs(base) || !filepath.IsAbs(candidate) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(candidate))
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func runProbeRead(mayPath, reference, scenario string) {
	if scenario == "" || !strings.HasPrefix(reference, "op://Agent/") {
		fatal("invalid probe-read input")
	}
	value, err := readCredentialWithMay(mayPath, reference, os.Stderr)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"ok": false, "scenario": scenario, "value_exposed": false,
			"error_code": "read-not-completed",
		})
		os.Exit(1)
	}
	clear(value)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"ok": true, "scenario": scenario, "value_exposed": false,
	})
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
