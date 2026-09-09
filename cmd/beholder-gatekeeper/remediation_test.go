package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRemediationFullHumanHistoryAndToolSuffixes(t *testing.T) {
	for _, name := range []string{"functions.apply_patch", "functions.exec_command", "request_user_input"} {
		t.Run(name, func(t *testing.T) {
			revocation := strings.Repeat("ordinary task details ", 1800) + "DO NOT COMMIT OR PUSH."
			events := []map[string]any{messageFixture("user", "", "You may commit and push."), messageFixture("user", "", revocation)}
			for i := 0; i < 80; i++ {
				events = append(events, messageFixture("user", "", fmt.Sprintf("Continue investigation %d.", i)))
			}
			events = append(events, messageFixture("user", "", "Current human request: read the match fixture."),
				toolCallFixture("scope-proof", name, `{"cmd":"cat config/reasoning_content.json"}`),
				toolOutputFixture("scope-proof", `{"output":"`+strings.Repeat("ordinary metadata ", 5000)+`PRODUCTION ADMINISTRATOR PRIVILEGES"}`))
			input, _, _, err := buildExternalDecisionInputWithEvidence(liveRequestFixture(writeSessionFixture(t, events)), nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(input.HumanIntent.PriorMessages) != 82 || input.HumanIntent.PriorMessages[1].Text != revocation {
				t.Fatal("old or long human direction lost")
			}
			if len(input.CompletedToolActivity) != 1 || !strings.Contains(input.CompletedToolActivity[0].Output, "PRODUCTION ADMINISTRATOR PRIVILEGES") {
				t.Fatal("tool suffix or marker record lost")
			}
		})
	}
}

func TestRemediationNativeFunctionCallsAndJSONFieldOrder(t *testing.T) {
	path := writeSessionFixture(t, []map[string]any{
		messageFixture("user", "", strings.Repeat("padding", 900)+"Do not deploy production."),
		messageFixture("user", "", "Current human request: read the match fixture."),
		{"type": "function_call", "name": "tools.exec_command", "call_id": "native-call", "arguments": `{"cmd":"cat policy.json"}`},
		{"type": "function_call_output", "call_id": "native-call", "output": "Production scope is forbidden."},
	})
	// encoding/json writes map keys lexically, so payload precedes outer type.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Index(raw, []byte("Do not deploy")) < 4096 {
		t.Fatal("fixture did not cross the old type probe boundary")
	}
	input, _, err := buildExternalDecisionInput(liveRequestFixture(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(input.HumanIntent.PriorMessages) != 1 || !strings.Contains(input.HumanIntent.PriorMessages[0].Text, "Do not deploy") || len(input.CompletedToolActivity) != 1 || !strings.Contains(input.CompletedToolActivity[0].Input, "policy.json") {
		t.Fatal("structural message or native tool record lost")
	}
}

func TestRemediationResourceCoverageAndHumanBudgetFailure(t *testing.T) {
	long := strings.Repeat("safe ", maximumRelatedContextBytes/4) + "TAIL CONSTRAINT"
	excerpt, ok := safeUTF8Text([]byte(long), 2048)
	if !ok || len(excerpt) > 2048 || !strings.Contains(excerpt, "TAIL CONSTRAINT") || !strings.Contains(excerpt, "sha256=") {
		t.Fatal("excerpt did not expose its missing middle and intact suffix")
	}
	path := writeSessionFixture(t, []map[string]any{messageFixture("user", "", long), messageFixture("user", "", "Current human request: read the match fixture.")})
	_, _, source, err := buildExternalDecisionInputWithEvidence(liveRequestFixture(path), nil)
	if err == nil || err.Error() != "human-context-budget-exceeded" || source.CollectorError == nil || *source.CollectorError != err.Error() {
		t.Fatalf("human history was silently shortened: %v", err)
	}
}

func TestRemediationEnvironmentAndCoverageSurviveV5RoundTrip(t *testing.T) {
	request := liveRequestFixture(writeSessionFixture(t, []map[string]any{messageFixture("user", "", "Current human request: read the match fixture.")}))
	request.CWD = "/workspace/actual-beta"
	input, _, err := buildExternalDecisionInput(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	if input.Environment.CWD != request.CWD || input.Environment.CWDSource != "core-kernel-observed-request-process" || input.Environment.SessionCWD == request.CWD {
		t.Fatal("session cwd presented as actual execution")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("associated-execution-candidate")) || !bytes.Contains(raw, []byte("event_selection_summary")) {
		t.Fatal("model was not told the association and coverage limits")
	}
	var decoded externalDecisionInput
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	roundTrip, _ := json.Marshal(decoded)
	if !bytes.Equal(raw, roundTrip) {
		t.Fatal("v5 evidence changed on round trip")
	}
}

func TestRemediationAdmissionAbsorbsSixRequestsWithoutExceedingFive(t *testing.T) {
	service := &gatekeeperService{config: confirmedConfig{}, semaphore: make(chan struct{}, 5), waitingSlots: make(chan struct{}, 5)}
	service.config.Invocation.TimeoutMS = 10000
	var active, maximum, accepted atomic.Int32
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 6; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			if !service.acquireDecisionSlot(time.Now()) {
				return
			}
			accepted.Add(1)
			n := active.Add(1)
			for old := maximum.Load(); n > old; old = maximum.Load() {
				if maximum.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(30 * time.Millisecond)
			active.Add(-1)
			<-service.semaphore
		}()
	}
	close(start)
	group.Wait()
	if accepted.Load() != 6 || maximum.Load() > 5 {
		t.Fatalf("admitted %d; peak %d", accepted.Load(), maximum.Load())
	}
	for i := 0; i < 5; i++ {
		service.semaphore <- struct{}{}
	}
	started := time.Now()
	if service.acquireDecisionSlot(started.Add(-10*time.Second)) || time.Since(started) > 50*time.Millisecond {
		t.Fatal("expired overall budget acquired an admission slot")
	}
}
