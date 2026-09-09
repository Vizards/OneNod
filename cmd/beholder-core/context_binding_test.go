package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTransientContextJoinsPromptAndExactToolInputInMemory(t *testing.T) {
	store := testTransientContextStore(t)
	prompt := []byte("Please inspect the fixture repository and run the harmless status command.")
	input := json.RawMessage(`{"command":"git status --short","yield_time_ms":10000}`)
	if result := store.registerPrompt("session-0001", "turn-0001", prompt); !result.Accepted {
		t.Fatal(result)
	}
	if result := store.registerToolInput("session-0001", "turn-0001", "tool-use-0001", input); !result.Accepted {
		t.Fatal(result)
	}
	context, result := store.acquire("session-0001", "turn-0001", "tool-use-0001")
	if !result.Accepted || string(context.Prompt) != string(prompt) || string(context.ToolInput) != string(input) {
		t.Fatalf("exact context was not joined: result=%+v prompt=%q input=%q", result, context.Prompt, context.ToolInput)
	}
	context.clear()
	if len(context.Prompt) != 0 || len(context.ToolInput) != 0 {
		t.Fatal("decision context was not cleared")
	}
	summary := store.summary()
	if summary.PromptCount != 1 || summary.ToolInputCount != 1 || summary.StateStorage != "memory-only" ||
		summary.RawPromptPersisted || summary.RawToolInputPersisted {
		t.Fatalf("unexpected context summary: %+v", summary)
	}
}

func TestTransientContextFailsClosedOnMissingOrConflictingEvents(t *testing.T) {
	store := testTransientContextStore(t)
	input := json.RawMessage(`{"command":"git status"}`)
	if result := store.registerToolInput("session-0001", "turn-0001", "tool-use-0001", input); result.ErrorCode != "prompt-binding-missing" {
		t.Fatalf("tool-before-prompt did not fail closed: %+v", result)
	}
	if result := store.registerPrompt("session-0001", "turn-0001", []byte("first prompt")); !result.Accepted {
		t.Fatal(result)
	}
	if result := store.registerPrompt("session-0001", "turn-0001", []byte("different prompt")); result.ErrorCode != "prompt-observation-conflict" {
		t.Fatalf("prompt conflict was not detected: %+v", result)
	}
	if result := store.registerToolInput("session-0001", "turn-0001", "tool-use-0001", input); !result.Accepted {
		t.Fatal(result)
	}
	if result := store.registerToolInput(
		"session-0001",
		"turn-0001",
		"tool-use-0001",
		json.RawMessage(`{"command":"git diff"}`),
	); result.ErrorCode != "tool-input-observation-conflict" {
		t.Fatalf("tool input conflict was not detected: %+v", result)
	}
	if _, result := store.acquire("session-0001", "turn-0001", "tool-use-other"); result.ErrorCode != "context-binding-missing" {
		t.Fatalf("wrong tool acquired context: %+v", result)
	}
}

func TestTransientContextSupportsMultipleToolsAndExplicitCleanup(t *testing.T) {
	store := testTransientContextStore(t)
	if result := store.registerPrompt("session-0001", "turn-0001", []byte("inspect both commands")); !result.Accepted {
		t.Fatal(result)
	}
	for index, command := range []string{"git status", "git diff"} {
		toolUseID := "tool-use-000" + string(rune('1'+index))
		input, _ := json.Marshal(map[string]string{"command": command})
		if result := store.registerToolInput("session-0001", "turn-0001", toolUseID, input); !result.Accepted {
			t.Fatal(result)
		}
	}
	if result := store.completeTool("session-0001", "turn-0001", "tool-use-0001"); !result.Accepted {
		t.Fatal(result)
	}
	if _, result := store.acquire("session-0001", "turn-0001", "tool-use-0001"); result.ErrorCode != "context-binding-missing" {
		t.Fatalf("completed tool remained available: %+v", result)
	}
	if _, result := store.acquire("session-0001", "turn-0001", "tool-use-0002"); !result.Accepted {
		t.Fatalf("sibling tool was removed too early: %+v", result)
	}
	if result := store.completeTurn("session-0001", "turn-0001"); !result.Accepted {
		t.Fatal(result)
	}
	if summary := store.summary(); summary.PromptCount != 0 || summary.ToolInputCount != 0 {
		t.Fatalf("turn cleanup left transient state: %+v", summary)
	}
}

func TestTransientContextConcurrentSessionsNeverCrossJoin(t *testing.T) {
	const sessions = 32
	store := testTransientContextStore(t)
	start := make(chan struct{})
	errorsSeen := make(chan error, sessions)
	var wait sync.WaitGroup
	for index := 0; index < sessions; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			sessionID := fmt.Sprintf("session-concurrent-%04d", index)
			turnID := fmt.Sprintf("turn-concurrent-%04d", index)
			toolUseID := fmt.Sprintf("tool-use-concurrent-%04d", index)
			prompt := []byte(fmt.Sprintf("prompt sentinel %04d", index))
			input := json.RawMessage(fmt.Sprintf(`{"command":"tool sentinel %04d"}`, index))
			if result := store.registerPrompt(sessionID, turnID, prompt); !result.Accepted {
				errorsSeen <- fmt.Errorf("register prompt %d: %s", index, result.ErrorCode)
				return
			}
			if result := store.registerToolInput(sessionID, turnID, toolUseID, input); !result.Accepted {
				errorsSeen <- fmt.Errorf("register tool %d: %s", index, result.ErrorCode)
				return
			}
			context, result := store.acquire(sessionID, turnID, toolUseID)
			defer context.clear()
			if !result.Accepted || string(context.Prompt) != string(prompt) || string(context.ToolInput) != string(input) {
				errorsSeen <- fmt.Errorf("cross-joined context %d", index)
				return
			}
			wrongIndex := (index + 1) % sessions
			wrongToolUseID := fmt.Sprintf("tool-use-concurrent-%04d", wrongIndex)
			if _, wrong := store.acquire(sessionID, turnID, wrongToolUseID); wrong.ErrorCode != "context-binding-missing" {
				errorsSeen <- fmt.Errorf("cross-session tool accepted %d -> %d", index, wrongIndex)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if summary := store.summary(); summary.PromptCount != sessions || summary.ToolInputCount != sessions {
		t.Fatalf("concurrent context counts: %+v", summary)
	}
}

func TestTransientContextExpiresAndRestartDoesNotRestoreContent(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := newTransientContextStoreWithKey(time.Minute, 10*time.Second, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if result := store.registerPrompt("session-0001", "turn-0001", []byte("temporary prompt")); !result.Accepted {
		t.Fatal(result)
	}
	if result := store.registerToolInput(
		"session-0001",
		"turn-0001",
		"tool-use-0001",
		json.RawMessage(`{"command":"git status"}`),
	); !result.Accepted {
		t.Fatal(result)
	}
	now = now.Add(11 * time.Second)
	if _, result := store.acquire("session-0001", "turn-0001", "tool-use-0001"); result.ErrorCode != "context-binding-missing" {
		t.Fatalf("expired tool input remained available: %+v", result)
	}
	restarted, err := newTransientContextStoreWithKey(time.Minute, 10*time.Second, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, result := restarted.acquire("session-0001", "turn-0001", "tool-use-0001"); result.ErrorCode != "context-binding-missing" {
		t.Fatalf("restart restored transient content: %+v", result)
	}
	store.close()
	restarted.close()
}

func TestTransientContextSummaryCannotSerializeRawContent(t *testing.T) {
	store := testTransientContextStore(t)
	sentinel := "SENTINEL-PROMPT-MUST-STAY-IN-MEMORY"
	if result := store.registerPrompt("session-0001", "turn-0001", []byte(sentinel)); !result.Accepted {
		t.Fatal(result)
	}
	if result := store.registerToolInput(
		"session-0001",
		"turn-0001",
		"tool-use-0001",
		json.RawMessage(`{"command":"SENTINEL-TOOL-INPUT"}`),
	); !result.Accepted {
		t.Fatal(result)
	}
	encoded, err := json.Marshal(store.summary())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), sentinel) || strings.Contains(string(encoded), "SENTINEL-TOOL-INPUT") {
		t.Fatalf("summary leaked transient content: %s", encoded)
	}
}

func testTransientContextStore(t *testing.T) *transientContextStore {
	t.Helper()
	store, err := newTransientContextStoreWithKey(
		30*time.Minute,
		5*time.Minute,
		[]byte("0123456789abcdef0123456789abcdef"),
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	return store
}
