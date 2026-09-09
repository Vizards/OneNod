package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Vizards/OneNod/cmd/beholder-gatekeeper/internal/modelcontract"
)

func TestDogfoodCodeAndDummyCredentialShapesReachModelAndEvidenceUnchanged(t *testing.T) {
	const snippet = `password = opt["password"]; token=ghp_abcdefghijklmnopqrstuvwxyz; Authorization: Bearer dummy-abcdefghijklmnopqrstuvwxyz`
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var body chatCompletionRequest
		if json.Unmarshal(raw, &body) != nil || len(body.Messages) != 2 {
			t.Error("bad request")
			return
		}
		var input externalDecisionInput
		if err := json.Unmarshal([]byte(body.Messages[1].Content), &input); err != nil {
			t.Error(err)
			return
		}
		var tool map[string]string
		if json.Unmarshal(input.ToolCall.Input, &tool) != nil || tool["command"] != snippet {
			t.Error("tool text changed")
		}

		decision, _ := json.Marshal(map[string]string{"decision": "allow", "reason": snippet})
		_ = json.NewEncoder(w).Encode(map[string]any{"model": "deepseek-v4-flash", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(decision), "reasoning_content": snippet}}}})
	}))
	defer server.Close()
	evidence := testEvidenceStore(t)
	service, err := newGatekeeperService(validTestConfig(), confirmedConfigSHA256, []byte("fixture-gatekeeper-key-1234567890"), nil, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer service.close()
	service.endpoint = server.URL
	request := liveRequestFixture(writeSessionFixture(t, []map[string]any{messageFixture("user", "", "Current human request: read the match fixture.")}))
	request.ToolInput, _ = json.Marshal(map[string]string{"command": snippet})
	request.ActualRequest.RequesterContext = `{"ghp_abcdefghijklmnopqrstuvwxyz":"retain-value"}`
	result := service.decide(request)
	if !result.ModelCalled || !result.ModelUsed || result.Decision != "allow" || result.Reason != snippet {
		t.Fatalf("content changed or blocked: %+v", result)
	}
	service.close()
	if calls.Load() != 2 {
		t.Fatalf("expected both variants, got %d", calls.Load())
	}
	bundle := filepath.Join(evidence.root, time.Now().UTC().Format("2006-01"), request.RequestID)
	for _, name := range []string{evidenceSourceName, evidenceRequestName} {
		data, err := os.ReadFile(filepath.Join(bundle, name))
		if err != nil || !bytes.Contains(data, []byte("ghp_abcdefghijklmnopqrstuvwxyz")) || bytes.Contains(data, []byte("REDACTED")) {
			t.Fatalf("content rewritten in %s: %v", name, err)
		}
	}
}

func TestAnswerQuestionPreservesAnchorAndLatestHumanDirection(t *testing.T) {
	request := liveRequestFixture(writeSessionFixture(t, []map[string]any{
		messageFixture("user", "", "Earlier SSH authorization."),
		messageFixture("user", "", "Current human request: read the match fixture."),
		messageFixture("user", "", "Answer question: inspect the peer Mac and fixture router."),
		messageFixture("user", "", "Do not commit yet."),
	}))
	input, _, err := buildExternalDecisionInput(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(input)
	if err != nil || modelcontract.ValidateChronology(raw) != nil {
		t.Fatalf("shared validation: %v", err)
	}
	var wire modelDecisionInputWire
	if json.Unmarshal(raw, &wire) != nil || wire.UserMessages.TurnAnchorIndex == nil {
		t.Fatal("missing anchor")
	}
	users := wire.UserMessages
	if *users.TurnAnchorIndex != 1 || users.LatestMessageIndex != 3 || users.Messages[3].Text != "Do not commit yet." || users.Messages[1].IsLatest {
		t.Fatalf("bad chronology: %+v", users)
	}
	var decoded externalDecisionInput
	if json.Unmarshal(raw, &decoded) != nil || decoded.HumanIntent.CurrentPrompt != input.HumanIntent.CurrentPrompt {
		t.Fatal("anchor changed on round trip")
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(raw, reencoded) {
		t.Fatal("round trip changed timeline")
	}
	// The old forced-last anchor defect must be rejected by sender and viewer's shared contract.
	users.Messages[1], users.Messages[3] = users.Messages[3], users.Messages[1]
	wire.UserMessages = users
	invalid, _ := json.Marshal(wire)
	if modelcontract.ValidateChronology(invalid) == nil || json.Unmarshal(invalid, &decoded) == nil {
		t.Fatal("malformed chronology accepted")
	}
	input.HumanIntent.PriorMessages[0].Source = "forged-human"
	if _, err := json.Marshal(input); err == nil {
		t.Fatal("sender bypassed provenance validation")
	}
}
