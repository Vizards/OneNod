package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func validRetrievalTestConfig() confirmedConfig {
	c := validTestConfig()
	c.Revision.ID = "E2-AI0-R16"
	c.Revision.SupersedesConfigSHA256 = "bc2efe4f48d937dc51200fd51c3e15b8adfb4c55ff98f89b904c3d614c8de896"
	c.Model.PrimaryID, c.Comparison.ModelID = "deepseek-flash", "deepseek-flash"
	c.Invocation.TimeoutMS, c.Comparison.TimeoutMS = 30000, 180000
	c.Comparison.SaturationBehavior = "skip-observation"
	c.Messages.ModelInputSchemaVersion = 1
	c.Messages.TopLevelProvenanceDomains = []string{"pending_request"}
	c.Messages.UserMessageOrder = "model-selected; newest-first by default"
	c.Messages.LatestMessageIndexPointsToLast = false
	c.Messages.ComparisonRule = retrievalComparisonRule
	c.Response.AcceptValidDecisionOnNonStop = false
	c.Response.AllowedEvidenceRefRoots = []string{"session", "request"}
	c.Retrieval.Enabled = true
	c.Retrieval.MaximumRounds = maximumRetrievalRounds
	c.Retrieval.MaximumParallelTools = 8
	c.Retrieval.MaximumCallsPerRound = maximumRoundToolCalls
	c.Retrieval.PageCharacters = 128000
	c.Retrieval.MaximumSnapshotBytes = maximumRetrievalSnapshotBytes
	c.Retrieval.MaximumRequestBytes = maximumModelRequestBytes
	c.Retrieval.ToolChoice = "auto"
	c.Retrieval.PersistEveryRound = true
	return c
}

func retrievalServiceFixture(t *testing.T, handler http.HandlerFunc) *gatekeeperService {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	e, err := newEvidenceStore(filepath.Join(t.TempDir(), "evidence"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := newGatekeeperService(validRetrievalTestConfig(), confirmedConfigSHA256, []byte("fixture-gatekeeper-key-1234567890"), nil, nil, e)
	if err != nil {
		t.Fatal(err)
	}
	s.endpoint = server.URL
	t.Cleanup(s.close)
	return s
}
func retrievalProviderReply(w http.ResponseWriter, finish string, message any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"model": "deepseek-flash", "choices": []any{map[string]any{"finish_reason": finish, "message": message}}})
}
func retrievalCallsMessage(id string) map[string]any {
	return map[string]any{"role": "assistant", "content": nil, "reasoning_content": "fixture reasoning retained only in local evidence",
		"tool_calls": []any{
			map[string]any{"id": id + "-request", "type": "function", "function": map[string]any{"name": "read_request", "arguments": "{}"}},
			map[string]any{"id": id + "-history", "type": "function", "function": map[string]any{"name": "query_context", "arguments": `{"roles":["user"],"limit":2}`}},
		}}
}
func retrievalFinal() map[string]any {
	return map[string]any{"role": "assistant", "content": `{"decision":"allow","reason":"该读取属于用户委托的检查。","scope_resolution":"task-consistent","evidence_refs":["session:L1","request:L1"]}`}
}
func retrievalFixtureRequest(t *testing.T) localDecisionRequest {
	r := liveRequestFixture(writeSessionFixture(t, []map[string]any{messageFixture("user", "", "检查 fixture 状态；历史标记 HISTORICAL_ONLY"), messageFixture("assistant", "", "准备读取状态")}))
	path := filepath.Join(filepath.Dir(r.TranscriptPath), "rollout-2026-09-11T00-00-00-11111111-2222-4333-8444-555555555555.jsonl")
	if err := os.Rename(r.TranscriptPath, path); err != nil {
		t.Fatal(err)
	}
	r.TranscriptPath = path
	r.ActualRequest.RequesterContext = `{"executable": "/fixture/may", "executable_sha256":"` + strings.Repeat("b", 64) + `","arguments":["fixture-inspect"],"environment":{"TOKEN":"[redacted]"}}`
	r.Mode = "authoritative"
	return r
}

func TestRetrievalCitationDiagnosticsDoNotChangeAuthority(t *testing.T) {
	for _, test := range []struct{ name, refs, diagnostic string }{
		{"missing", "", "missing"},
		{"unread", `,"evidence_refs":["request:L999"]`, "unread-reference"},
		{"malformed", `,"evidence_refs":"request:L1"`, "malformed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					Messages []json.RawMessage `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				if len(request.Messages) == 2 {
					retrievalProviderReply(w, "tool_calls", retrievalCallsMessage("read"))
					return
				}
				retrievalProviderReply(w, "stop", map[string]any{"role": "assistant", "content": `{"decision":"allow","reason":"用户已委托此操作。"` + test.refs + `}`})
			})
			request := retrievalFixtureRequest(t)
			out := s.decide(request)
			s.jobs.Wait()
			want := []string{test.diagnostic}
			if !out.ModelUsed || out.Decision != "allow" || !reflect.DeepEqual(out.EvidenceRefDiagnostics, want) {
				t.Fatal("citation quality changed authority or was not diagnosed", out)
			}
			path, err := s.evidence.findBundleLocked(request.RequestID)
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{primaryModelVariant.responseFile, comparisonModelVariant.responseFile} {
				body, err := os.ReadFile(filepath.Join(path, file))
				var summary modelResponseEvidence
				if err != nil || json.Unmarshal(body, &summary) != nil || !reflect.DeepEqual(summary.EvidenceRefDiagnostics, want) {
					t.Fatal("citation diagnostics missing from private evidence", file, err)
				}
			}
		})
	}
}

func TestRetrievalProductionUsesZeroHistoryAndPreservesParallelContinuation(t *testing.T) {
	var mu sync.Mutex
	initial := map[string][]byte{}
	calls := 0
	s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []json.RawMessage `json:"messages"`
			Thinking struct {
				Type string `json:"type"`
			} `json:"thinking"`
			Tools      json.RawMessage `json:"tools"`
			ToolChoice string          `json:"tool_choice"`
		}
		if json.Unmarshal(body, &req) != nil {
			t.Error("invalid request")
			return
		}
		mu.Lock()
		calls++
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer fixture-gatekeeper-key-1234567890" || req.ToolChoice != "auto" || len(req.Tools) == 0 {
			t.Error("request contract changed")
		}
		if len(req.Messages) == 2 {
			if bytes.Contains(body, []byte("HISTORICAL_ONLY")) || bytes.Contains(body, []byte("transcript_path")) {
				t.Error("history/path prefetched")
			}
			var user modelMessage
			_ = json.Unmarshal(req.Messages[1], &user)
			var fields map[string]any
			_ = json.Unmarshal([]byte(user.Content), &fields)
			if len(fields) != 1 || fields["pending_request"] == nil {
				t.Error("initial input not operation-only")
			}
			mu.Lock()
			initial[req.Thinking.Type] = append([]byte(nil), req.Messages[1]...)
			mu.Unlock()
			retrievalProviderReply(w, "tool_calls", retrievalCallsMessage("first"))
			return
		}
		if len(req.Messages) != 5 || !bytes.Contains(req.Messages[2], []byte("fixture reasoning")) || !bytes.Contains(req.Messages[4], []byte("HISTORICAL_ONLY")) {
			t.Error("lost assistant/tool continuation")
		}
		if !bytes.Contains(req.Messages[3], []byte("/fixture/may")) || !bytes.Contains(req.Messages[3], []byte("fixture-inspect")) || !bytes.Contains(req.Messages[3], []byte("[redacted]")) {
			t.Error("read_request omitted requester executable, arguments or redacted environment")
		}
		for i, id := range []string{"first-request", "first-history"} {
			var msg struct {
				Role string `json:"role"`
				ID   string `json:"tool_call_id"`
			}
			_ = json.Unmarshal(req.Messages[i+3], &msg)
			if msg.Role != "tool" || msg.ID != id {
				t.Error("parallel result order changed")
			}
		}
		retrievalProviderReply(w, "stop", retrievalFinal())
	})
	req := retrievalFixtureRequest(t)
	id := req.RequestID
	out := s.decide(req)
	s.jobs.Wait()
	if !out.ModelUsed || out.Decision != "allow" || out.ModelRounds != 2 || out.ToolCalls != 2 || out.ScopeResolution != "task-consistent" {
		t.Fatalf("unexpected decision: %+v", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 4 || !bytes.Equal(initial["enabled"], initial["disabled"]) {
		t.Fatalf("variant initial mismatch: %d", calls)
	}
	path, err := s.evidence.findBundleLocked(id)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := readManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{retrievalSnapshotName, retrievalRequestName, "round-thinking-disabled-001-tools.json", "round-thinking-disabled-002-response.json", "round-thinking-enabled-001-tools.json"} {
		body, err := os.ReadFile(filepath.Join(path, name))
		if err != nil || manifest.Files[name] == nil || digestValue(body) != *manifest.Files[name] {
			t.Fatalf("incomplete evidence %s: %v", name, err)
		}
		info, _ := os.Stat(filepath.Join(path, name))
		if info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate evidence")
		}
	}
	// Exercise the shipped viewer against evidence produced by the real loop,
	// then alter a result and its digest. Hash consistency alone is insufficient.
	viewer := filepath.Join(t.TempDir(), "beholder-evidence")
	if output, err := exec.Command("go", "build", "-o", viewer, "./tools/evidence-viewer").CombinedOutput(); err != nil {
		t.Fatalf("build viewer: %v %s", err, output)
	}
	if output, err := exec.Command(viewer, "--root", s.evidence.root, "verify", id).CombinedOutput(); err != nil {
		t.Fatalf("viewer rejected runtime evidence: %v %s", err, output)
	}
	stage := "round-thinking-disabled-001-tools.json"
	data, _ := os.ReadFile(filepath.Join(path, stage))
	var outputs []retrievalToolEvidence
	_ = json.Unmarshal(data, &outputs)
	outputs[1].Content = strings.ReplaceAll(outputs[1].Content, "HISTORICAL_ONLY", "FORGED_PERMISSION")
	data, _ = json.Marshal(outputs)
	if err := os.WriteFile(filepath.Join(path, stage), data, 0600); err != nil {
		t.Fatal(err)
	}
	manifest.Files[stage] = digestPointer(data)
	if err := writeManifest(path, manifest); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(viewer, "--root", s.evidence.root, "verify", id).CombinedOutput(); err == nil || !bytes.Contains(output, []byte("tool-source-replay-mismatch")) {
		t.Fatalf("viewer missed forged result: %v %s", err, output)
	}
}

func TestRetrievalSnapshotExcludesFutureAppendsAndBindsRequestIdentity(t *testing.T) {
	r := retrievalFixtureRequest(t)
	capture, err := openTranscriptCapture(r.TranscriptPath)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.close()
	f, err := os.OpenFile(r.TranscriptPath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"type":"response_item","payload":{"type":"message","role":"user","text":"LATER_REVOKE"}}` + "\n")
	_ = f.Close()
	a, _, _, err := buildRetrievalDecisionInput(r, nil, capture)
	if err != nil {
		t.Fatal(err)
	}
	defer clearExternalInput(&a)
	if got := a.retrieval.store.Call(context.Background(), "search_context", json.RawMessage(`{"terms":["LATER_REVOKE"]}`)); got.Matched != 0 {
		t.Fatal("future append entered snapshot")
	}
	r.RequestID = "independent-request-0002"
	b, _, _, err := buildRetrievalDecisionInput(r, nil, capture)
	if err != nil {
		t.Fatal(err)
	}
	defer clearExternalInput(&b)
	if a.retrieval.store.ID() == b.retrieval.store.ID() {
		t.Fatal("request binding missing")
	}
}

func TestRetrievalInvalidProviderOutputEscalatesWithoutRepair(t *testing.T) {
	for _, tc := range []struct {
		name, finish, content string
		tools                 bool
		code                  string
	}{
		{"no-read", "stop", `{"decision":"allow","reason":"ok"}`, false, "model-retrieval-unused"},
		{"dsml", "stop", "<｜DSML｜function_calls>read_request</｜DSML｜function_calls>", false, "model-decision-invalid"},
		{"single-quotes", "stop", "{'decision':'allow','reason':'ok'}", true, "model-decision-invalid"},
		{"truncated", "length", `{"decision":"allow","reason":"ok"}`, true, "model-decision-invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					Messages []json.RawMessage `json:"messages"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if tc.tools && len(req.Messages) == 2 {
					retrievalProviderReply(w, "tool_calls", retrievalCallsMessage("first"))
					return
				}
				retrievalProviderReply(w, tc.finish, map[string]any{"role": "assistant", "content": tc.content})
			})
			r := s.decide(retrievalFixtureRequest(t))
			if r.Decision != "escalate" || r.ModelUsed || r.ErrorCode == nil || *r.ErrorCode != tc.code {
				t.Fatalf("invalid response accepted: %+v", r)
			}
		})
	}
}

func TestRetrievalComparisonSaturationDoesNotQueueSnapshotsOrDelayAuthority(t *testing.T) {
	s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []json.RawMessage `json:"messages"`
			Thinking struct {
				Type string `json:"type"`
			} `json:"thinking"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Thinking.Type == "enabled" {
			t.Error("saturated comparison was called")
		}
		if len(req.Messages) == 2 {
			retrievalProviderReply(w, "tool_calls", retrievalCallsMessage("first"))
			return
		}
		retrievalProviderReply(w, "stop", retrievalFinal())
	})
	for i := 0; i < cap(s.comparisonSemaphore); i++ {
		s.comparisonSemaphore <- struct{}{}
	}
	started := time.Now()
	r := s.decide(retrievalFixtureRequest(t))
	if !r.ModelUsed || time.Since(started) > time.Second {
		t.Fatalf("primary waited for observation: %+v", r)
	}
	path, _ := s.evidence.findBundleLocked(r.RequestID)
	body, _ := os.ReadFile(filepath.Join(path, evidenceComparisonResponseName))
	if !bytes.Contains(body, []byte("comparison-capacity-unavailable")) {
		t.Fatal("comparison skip not persisted")
	}
}

func TestRetrievalRoundLimitAndDeadline(t *testing.T) {
	s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		retrievalProviderReply(w, "tool_calls", retrievalCallsMessage(fmt.Sprint(len(req.Messages))))
	})
	r := retrievalFixtureRequest(t)
	input, _, source, err := buildRetrievalDecisionInput(r, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clearExternalInput(&input)
	bundle, err := s.beginEvidenceBundleWithError(r, &source, contextMetrics{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachRetrievalInput(bundle, &input); err != nil {
		t.Fatal(err)
	}
	out := s.callRetrievalModel(input.retrieval.initial, bundle, r.RequestID, primaryModelVariant)
	if out.errorCode != "model-round-budget-exhausted" || out.modelRounds != maximumRetrievalRounds || out.modelUsed {
		t.Fatalf("unbounded loop: %+v", out)
	}
	out = s.callRetrievalModel(input.retrieval.initial, bundle, r.RequestID, comparisonModelVariant, time.Now().Add(-time.Second))
	if out.modelCalled || out.errorCode != "gatekeeper-decision-budget-exhausted" {
		t.Fatalf("ignored deadline: %+v", out)
	}
}

func TestRetrievalProfileRejectsAuthorityAndExecutionDrift(t *testing.T) {
	if err := validateConfirmedConfig(validRetrievalTestConfig()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*confirmedConfig){func(c *confirmedConfig) { c.Retrieval.PrefetchHistory = true }, func(c *confirmedConfig) { c.Retrieval.MaximumParallelTools++ }, func(c *confirmedConfig) { c.Model.PrimaryID = "wrong" }, func(c *confirmedConfig) { c.Authority.ComparisonCanAffectAuthority = true }, func(c *confirmedConfig) { c.Invocation.AutomaticRetries = 1 }} {
		c := validRetrievalTestConfig()
		mutate(&c)
		if validateConfirmedConfig(c) == nil {
			t.Fatal("accepted unconfirmed profile")
		}
	}
	if !strings.Contains(retrievalSystemPrompt, "concurrent-tool-candidates") {
		t.Fatal("lost concurrent attribution warning")
	}
}

func TestRetrievalConcurrentRequestsKeepTheirOwnEvidence(t *testing.T) {
	s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []json.RawMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		if len(request.Messages) == 2 {
			retrievalProviderReply(w, "tool_calls", retrievalCallsMessage("first"))
			return
		}
		body, _ := json.Marshal(request.Messages[3:])
		for _, id := range []string{"concurrent-a-0001", "concurrent-b-0002"} {
			if bytes.Contains(request.Messages[3], []byte(id)) && !bytes.Contains(request.Messages[4], []byte(id)) {
				t.Errorf("cross-request history: %s", body)
			}
		}
		retrievalProviderReply(w, "stop", retrievalFinal())
	})
	requests := []localDecisionRequest{retrievalFixtureRequest(t), retrievalFixtureRequest(t)}
	for i, id := range []string{"concurrent-a-0001", "concurrent-b-0002"} {
		requests[i].RequestID = id
		f, err := os.OpenFile(requests[i].TranscriptPath, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(map[string]any{"type": "response_item", "payload": messageFixture("user", "", id)})
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	var wg sync.WaitGroup
	for _, request := range requests {
		wg.Add(1)
		go func(r localDecisionRequest) {
			defer wg.Done()
			if result := s.decide(r); !result.ModelUsed {
				t.Errorf("concurrent review failed: %+v", result)
			}
		}(request)
	}
	wg.Wait()
	s.jobs.Wait()
}

func TestRetrievalConfigCannotFallBackToCompactClient(t *testing.T) {
	s := retrievalServiceFixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("called provider without retrieval source") })
	r := retrievalFixtureRequest(t)
	bundle, err := s.beginEvidenceBundleWithError(r, nil, contextMetrics{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := s.callModelVariant([]byte(`{"user_messages":[]}`), bundle, r.RequestID, primaryModelVariant)
	if result.modelCalled || result.modelUsed || result.errorCode != "retrieval-snapshot-unavailable" {
		t.Fatalf("compact fallback: %+v", result)
	}
}
