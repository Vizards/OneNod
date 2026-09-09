package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLongActiveTurnKeepsLiveObservationIndependentOfNonceTTL(t *testing.T) {
	fixture := newBrokerFixture(t)
	defer fixture.core.close()
	for i := 0; i < 8; i++ {
		fixture.advance(20 * time.Minute)
		fixture.host.ToolUseID = fmt.Sprintf("tool-long-turn-%d", i)
		fixture.executionPeer.Nodes[1].PID++
		fixture.executionPeer.Nodes[0].ParentPID = fixture.executionPeer.Nodes[1].PID
		fixture.requestPeer.Nodes[1] = fixture.executionPeer.Nodes[1]
		fixture.requestPeer.Nodes[0].ParentPID = fixture.requestPeer.Nodes[1].PID
		fixture.host.ObservedAt = fixture.current.Format(time.RFC3339Nano)
		if got := fixture.registerPrimaryHost(); !got.Accepted {
			t.Fatalf("after %d minutes: %+v", (i+1)*20, got)
		}
	}
	fixture.advance(31 * time.Second)
	if got := fixture.checkPrimaryRequest(); !got.Accepted {
		t.Fatal("live tool claim expired with nonce TTL")
	}
}

func TestProtectedPromptProofRestoresAfterExpiryAndCoreRestart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint(restart), func(t *testing.T) {
			fixture := newBrokerFixture(t)
			ledgerRoot := filepath.Join(t.TempDir(), "proofs")
			if err := fixture.core.configurePromptLedger(ledgerRoot); err != nil {
				t.Fatal(err)
			}
			const prompt = "fixture current human prompt"
			observation := promptObservation{SessionID: fixture.sessionID, TurnID: fixture.turnID, TranscriptPath: fixture.transcriptPath, CWD: fixture.root, HookEventName: "UserPromptSubmit", Model: "fixture", PermissionMode: "dontAsk", ObservedAt: fixture.current.Format(time.RFC3339Nano), Prompt: []byte(prompt)}
			if got := fixture.core.registerPrompt(observation, fixture.hookPeer); !got.Accepted {
				t.Fatal(got)
			}
			event, _ := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": prompt}}}})
			file, err := os.OpenFile(fixture.transcriptPath, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = file.Write(append(event, '\n'))
			file.Close()
			if err != nil {
				t.Fatal(err)
			}
			proofBytes, err := os.ReadFile(outcomeStatePath(ledgerRoot, fixture.sessionID))
			if err != nil || bytes.Contains(proofBytes, []byte(prompt)) {
				t.Fatal("raw prompt persisted")
			}
			fixture.advance(48 * time.Minute)
			if restart {
				fixture.core.close()
				fixture.core, err = newBrokerWithKey(fixture.root, "fixture", "", "", 30*time.Second, bytes.Repeat([]byte{7}, 32), fixture.now)
				if err != nil {
					t.Fatal(err)
				}
				fixture.core.processAlive = func(processIdentity) bool { return true }
				if err = fixture.core.configurePromptLedger(ledgerRoot); err != nil {
					t.Fatal(err)
				}
			}
			defer fixture.core.close()
			fixture.host.ObservedAt = fixture.current.Format(time.RFC3339Nano)
			if got := fixture.registerPrimaryHost(); !got.Accepted {
				t.Fatalf("verified restore failed: %+v", got)
			}
			context, result := fixture.core.contexts.acquire(fixture.sessionID, fixture.turnID, fixture.toolUseID)
			if !result.Accepted || string(context.Prompt) != prompt {
				t.Fatal("restored wrong prompt")
			}
			context.clear()
			fixture.advance(48 * time.Minute)
			data, err := os.ReadFile(fixture.transcriptPath)
			if err != nil {
				t.Fatal(err)
			}
			fixture.core.contexts.completeTurn(fixture.sessionID, fixture.turnID)
			data = bytes.ReplaceAll(data, []byte(prompt), []byte("arbitrary modified history"))
			if err = os.WriteFile(fixture.transcriptPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			fixture.host.ObservedAt = fixture.current.Format(time.RFC3339Nano)
			if got := fixture.core.registerHost(fixture.host, fixture.hookPeer); got.Accepted || got.ErrorCode == nil || *got.ErrorCode != "prompt-proof-content-mismatch" {
				t.Fatalf("modified transcript accepted: %+v", got)
			}
		})
	}
}

func TestSessionTextAloneCannotCreatePromptProof(t *testing.T) {
	fixture := newBrokerFixture(t)
	defer fixture.core.close()
	if err := fixture.core.configurePromptLedger(filepath.Join(t.TempDir(), "proofs")); err != nil {
		t.Fatal(err)
	}
	fixture.advance(time.Hour)
	fixture.host.ObservedAt = fixture.current.Format(time.RFC3339Nano)
	got := fixture.core.registerHost(fixture.host, fixture.hookPeer)
	if got.Accepted || got.ErrorCode == nil || *got.ErrorCode != "prompt-proof-unavailable" {
		t.Fatalf("unproven session text accepted: %+v", got)
	}
}
