package main

import (
	"context"
	"time"
)

func kernelProcessAlive(expected processIdentity) bool {
	if expected.PID <= 1 {
		return false
	}
	current, err := inspectProcess(expected.PID)
	return err == nil && rawProcessRef(current) == rawProcessRef(expected) &&
		current.UID == expected.UID && current.RealUID == expected.RealUID
}

// Pins belong to live broker observations, not to an authorization lease.
// Broker ownership is released on kernel exit/PID reuse or broker shutdown.
func (store *transientContextStore) pinRefs(turnRef, toolRef string) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	prompt, tool := store.prompts[turnRef], store.tools[toolRef]
	if prompt == nil || tool == nil || tool.turnRef != turnRef {
		return false
	}
	if !tool.pinned {
		prompt.pins++
		tool.pinned = true
	}
	return true
}

func (store *transientContextStore) releaseRefs(turnRef, toolRef string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if tool := store.tools[toolRef]; tool != nil {
		if prompt := store.prompts[turnRef]; prompt != nil && tool.pinned {
			prompt.pins--
		}
		clear(tool.raw)
		delete(store.tools, toolRef)
	}
	store.expireLocked(store.now().UTC())
}

// This bounds aggregate retained observations, including pinned contexts.
func (store *transientContextStore) hasCapacityLocked(additional int) bool {
	if len(store.prompts)+len(store.tools) >= 4096 {
		return false
	}
	total := additional
	for _, prompt := range store.prompts {
		total += len(prompt.raw)
	}
	for _, tool := range store.tools {
		total += len(tool.raw)
	}
	return total <= 64*1024*1024
}

func (broker *broker) reapObservations(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			broker.mu.Lock()
			broker.expireLocked(broker.now().UTC())
			broker.mu.Unlock()
		}
	}
}
