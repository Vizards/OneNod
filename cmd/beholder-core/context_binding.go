package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const maximumTransientContextSize = 2 * 1024 * 1024

type transientContextStore struct {
	mu        sync.Mutex
	key       []byte
	promptTTL time.Duration
	toolTTL   time.Duration
	now       func() time.Time
	prompts   map[string]*transientPrompt
	tools     map[string]*transientToolInput
}

type transientPrompt struct {
	pins       int
	sessionRef string
	turnRef    string
	digestRef  string
	raw        []byte
	expiresAt  time.Time
}

type transientToolInput struct {
	pinned     bool
	sessionRef string
	turnRef    string
	toolUseRef string
	digestRef  string
	raw        []byte
	expiresAt  time.Time
}

type transientDecisionContext struct {
	Prompt    []byte
	ToolInput json.RawMessage
}

type transientContextResult struct {
	Accepted  bool
	ErrorCode string
	turnRef   string
	toolRef   string
}

type transientContextSummary struct {
	PromptCount           int    `json:"prompt_count"`
	ToolInputCount        int    `json:"tool_input_count"`
	StateStorage          string `json:"state_storage"`
	RawPromptPersisted    bool   `json:"raw_prompt_persisted"`
	RawToolInputPersisted bool   `json:"raw_tool_input_persisted"`
}

func newTransientContextStore(
	promptTTL, toolTTL time.Duration,
) (*transientContextStore, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return newTransientContextStoreWithKey(promptTTL, toolTTL, key, time.Now)
}

func newTransientContextStoreWithKey(
	promptTTL, toolTTL time.Duration,
	key []byte,
	now func() time.Time,
) (*transientContextStore, error) {
	if promptTTL <= 0 || promptTTL > time.Hour || toolTTL <= 0 || toolTTL > 10*time.Minute ||
		len(key) < 32 || now == nil {
		return nil, errors.New("invalid transient context configuration")
	}
	return &transientContextStore{
		key: append([]byte(nil), key...), promptTTL: promptTTL, toolTTL: toolTTL, now: now,
		prompts: map[string]*transientPrompt{}, tools: map[string]*transientToolInput{},
	}, nil
}

func (store *transientContextStore) registerPrompt(
	sessionID, turnID string,
	prompt []byte,
) transientContextResult {
	if store == nil || !safeJoinKey(sessionID) || !safeJoinKey(turnID) ||
		len(prompt) == 0 || len(prompt) > maximumTransientContextSize {
		return transientContextResult{ErrorCode: "invalid-prompt-observation"}
	}
	sessionRef := store.ref("session", []byte(sessionID))
	turnRef := store.ref("turn", []byte(sessionID+"\x00"+turnID))
	digestRef := store.ref("prompt", prompt)
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	if existing, found := store.prompts[turnRef]; found {
		if !hmac.Equal([]byte(existing.digestRef), []byte(digestRef)) {
			return transientContextResult{ErrorCode: "prompt-observation-conflict"}
		}
		existing.expiresAt = now.Add(store.promptTTL)
		return transientContextResult{Accepted: true, turnRef: turnRef}
	}
	if !store.hasCapacityLocked(len(prompt)) {
		return transientContextResult{ErrorCode: "observation-capacity-exceeded"}
	}
	store.prompts[turnRef] = &transientPrompt{
		sessionRef: sessionRef, turnRef: turnRef, digestRef: digestRef,
		raw: append([]byte(nil), prompt...), expiresAt: now.Add(store.promptTTL),
	}
	return transientContextResult{Accepted: true, turnRef: turnRef}
}

func (store *transientContextStore) registerToolInput(
	sessionID, turnID, toolUseID string,
	input json.RawMessage,
) transientContextResult {
	if store == nil || !safeJoinKey(sessionID) || !safeJoinKey(turnID) || !safeJoinKey(toolUseID) ||
		len(input) == 0 || len(input) > maximumTransientContextSize || !json.Valid(input) {
		return transientContextResult{ErrorCode: "invalid-tool-input-observation"}
	}
	turnRef := store.ref("turn", []byte(sessionID+"\x00"+turnID))
	toolUseRef := store.ref("tool-use", []byte(sessionID+"\x00"+turnID+"\x00"+toolUseID))
	digestRef := store.ref("tool-input", input)
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	prompt, found := store.prompts[turnRef]
	if !found {
		return transientContextResult{ErrorCode: "prompt-binding-missing"}
	}
	// Only a trusted, current-turn PreToolUse event reaches this registration.
	// Treat the cache deadline as inactivity, independently of short tool leases.
	prompt.expiresAt = now.Add(store.promptTTL)
	if existing, found := store.tools[toolUseRef]; found {
		if !hmac.Equal([]byte(existing.digestRef), []byte(digestRef)) {
			return transientContextResult{ErrorCode: "tool-input-observation-conflict"}
		}
		existing.expiresAt = now.Add(store.toolTTL)
		return transientContextResult{Accepted: true, turnRef: turnRef, toolRef: toolUseRef}
	}
	if !store.hasCapacityLocked(len(input)) {
		return transientContextResult{ErrorCode: "observation-capacity-exceeded"}
	}
	store.tools[toolUseRef] = &transientToolInput{
		sessionRef: prompt.sessionRef, turnRef: turnRef, toolUseRef: toolUseRef,
		digestRef: digestRef, raw: append([]byte(nil), input...), expiresAt: now.Add(store.toolTTL),
	}
	return transientContextResult{Accepted: true, turnRef: turnRef, toolRef: toolUseRef}
}

func (store *transientContextStore) acquire(
	sessionID, turnID, toolUseID string,
) (transientDecisionContext, transientContextResult) {
	if store == nil || !safeJoinKey(sessionID) || !safeJoinKey(turnID) || !safeJoinKey(toolUseID) {
		return transientDecisionContext{}, transientContextResult{ErrorCode: "context-binding-invalid"}
	}
	turnRef := store.ref("turn", []byte(sessionID+"\x00"+turnID))
	toolUseRef := store.ref("tool-use", []byte(sessionID+"\x00"+turnID+"\x00"+toolUseID))
	return store.acquireRefs(turnRef, toolUseRef)
}

func (store *transientContextStore) acquireRefs(
	turnRef, toolUseRef string,
) (transientDecisionContext, transientContextResult) {
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	prompt, promptFound := store.prompts[turnRef]
	tool, toolFound := store.tools[toolUseRef]
	if !promptFound || !toolFound || !hmac.Equal([]byte(prompt.turnRef), []byte(tool.turnRef)) ||
		!hmac.Equal([]byte(prompt.sessionRef), []byte(tool.sessionRef)) {
		return transientDecisionContext{}, transientContextResult{ErrorCode: "context-binding-missing"}
	}
	return transientDecisionContext{
		Prompt:    append([]byte(nil), prompt.raw...),
		ToolInput: append(json.RawMessage(nil), tool.raw...),
	}, transientContextResult{Accepted: true, turnRef: turnRef, toolRef: toolUseRef}
}

func (store *transientContextStore) completeTool(
	sessionID, turnID, toolUseID string,
) transientContextResult {
	if store == nil || !safeJoinKey(sessionID) || !safeJoinKey(turnID) || !safeJoinKey(toolUseID) {
		return transientContextResult{ErrorCode: "context-binding-invalid"}
	}
	toolUseRef := store.ref("tool-use", []byte(sessionID+"\x00"+turnID+"\x00"+toolUseID))
	store.mu.Lock()
	defer store.mu.Unlock()
	tool, found := store.tools[toolUseRef]
	if !found {
		return transientContextResult{ErrorCode: "context-binding-missing"}
	}
	clear(tool.raw)
	delete(store.tools, toolUseRef)
	return transientContextResult{Accepted: true}
}

func (store *transientContextStore) completeTurn(sessionID, turnID string) transientContextResult {
	if store == nil || !safeJoinKey(sessionID) || !safeJoinKey(turnID) {
		return transientContextResult{ErrorCode: "context-binding-invalid"}
	}
	turnRef := store.ref("turn", []byte(sessionID+"\x00"+turnID))
	store.mu.Lock()
	defer store.mu.Unlock()
	prompt, found := store.prompts[turnRef]
	if found {
		clear(prompt.raw)
		delete(store.prompts, turnRef)
	}
	for ref, tool := range store.tools {
		if hmac.Equal([]byte(tool.turnRef), []byte(turnRef)) {
			clear(tool.raw)
			delete(store.tools, ref)
		}
	}
	if !found {
		return transientContextResult{ErrorCode: "context-binding-missing"}
	}
	return transientContextResult{Accepted: true}
}

func (store *transientContextStore) summary() transientContextSummary {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(store.now().UTC())
	return transientContextSummary{
		PromptCount: len(store.prompts), ToolInputCount: len(store.tools), StateStorage: "memory-only",
		RawPromptPersisted: false, RawToolInputPersisted: false,
	}
}

func (store *transientContextStore) close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for ref, prompt := range store.prompts {
		clear(prompt.raw)
		delete(store.prompts, ref)
	}
	for ref, tool := range store.tools {
		clear(tool.raw)
		delete(store.tools, ref)
	}
	clear(store.key)
}

func (context *transientDecisionContext) clear() {
	if context == nil {
		return
	}
	clear(context.Prompt)
	clear(context.ToolInput)
	context.Prompt = nil
	context.ToolInput = nil
}

func (store *transientContextStore) expireLocked(now time.Time) {
	for ref, prompt := range store.prompts {
		if prompt.pins == 0 && !prompt.expiresAt.After(now) {
			clear(prompt.raw)
			delete(store.prompts, ref)
		}
	}
	for ref, tool := range store.tools {
		if !tool.pinned && !tool.expiresAt.After(now) {
			clear(tool.raw)
			delete(store.tools, ref)
		}
	}
}

func (store *transientContextStore) ref(kind string, value []byte) string {
	digest := hmac.New(sha256.New, store.key)
	_, _ = digest.Write([]byte(kind))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	return kind + "-" + hex.EncodeToString(digest.Sum(nil))
}
