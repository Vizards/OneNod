package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDecisionBindingConsumesExactOperationTargetOnce(t *testing.T) {
	store := testDecisionBindingStore(t)
	request := testSSHOperationTarget("ssh.authentication", "deploy", "SHA256:host-a")
	capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: request})
	if issue.ErrorCode != "" || len(capability.raw) != decisionCapabilitySize {
		t.Fatalf("decision was not issued: %+v", issue)
	}
	replay := decisionCapability{raw: append([]byte(nil), capability.raw...)}
	if result := store.consume(capability, request); !result.Matched || result.ErrorCode != "" {
		t.Fatalf("exact request did not consume: %+v", result)
	}
	if result := store.consume(replay, request); result.Matched || result.ErrorCode != "decision-replay" {
		t.Fatalf("decision replay was not rejected: %+v", result)
	}
}

func TestDecisionBindingRejectsApproveAExecuteB(t *testing.T) {
	changes := []struct {
		name   string
		mutate func(*operationTarget)
	}{
		{name: "surface", mutate: func(request *operationTarget) { request.Surface = "direct-may" }},
		{name: "operation", mutate: func(request *operationTarget) { request.Operation = "git.ssh-signature" }},
		{name: "target kind", mutate: func(request *operationTarget) { request.TargetKind = "secret-field" }},
		{name: "target ID", mutate: func(request *operationTarget) { request.TargetID = "fixture-key-b" }},
		{name: "key", mutate: func(request *operationTarget) { request.KeyFingerprint = "SHA256:key-b" }},
		{name: "remote user", mutate: func(request *operationTarget) { request.RemoteUser = "root" }},
		{name: "host key", mutate: func(request *operationTarget) { request.HostKeyFingerprint = "SHA256:host-b" }},
		{name: "payload", mutate: func(request *operationTarget) { request.PayloadDigest = digestHex("payload-b") }},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			store := testDecisionBindingStore(t)
			approved := testSSHOperationTarget("ssh.authentication", "deploy", "SHA256:host-a")
			capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: approved})
			if issue.ErrorCode != "" {
				t.Fatal(issue)
			}
			actual := approved
			change.mutate(&actual)
			if result := store.consume(capability, actual); result.Matched || result.ErrorCode != "operation-target-mismatch" {
				t.Fatalf("substituted request was not rejected: %+v", result)
			}
			if result := store.consume(capability, approved); result.Matched || result.ErrorCode != "decision-binding-missing" {
				t.Fatalf("mismatch did not burn the one-time capability: %+v", result)
			}
		})
	}
}

func TestDecisionBindingEscalateNeverIssuesCapability(t *testing.T) {
	store := testDecisionBindingStore(t)
	capability, result := store.issue(gatekeeperDecisionFixture{
		Disposition: "escalate",
		Request:     testSSHOperationTarget("ssh.authentication", "deploy", "SHA256:host-a"),
	})
	if len(capability.raw) != 0 || result.ErrorCode != "gatekeeper-escalated" {
		t.Fatalf("escalate unexpectedly issued authority: capability=%d result=%+v", len(capability.raw), result)
	}
}

func TestDecisionBindingConcurrentConsumeHasOneWinner(t *testing.T) {
	store := testDecisionBindingStore(t)
	request := testSSHOperationTarget("git.ssh-signature", "", "")
	capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: request})
	if issue.ErrorCode != "" {
		t.Fatal(issue)
	}
	const contenders = 32
	start := make(chan struct{})
	results := make(chan decisionConsumption, contenders)
	var wait sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wait.Add(1)
		copy := decisionCapability{raw: append([]byte(nil), capability.raw...)}
		go func(candidate decisionCapability) {
			defer wait.Done()
			<-start
			results <- store.consume(candidate, request)
		}(copy)
	}
	clear(capability.raw)
	close(start)
	wait.Wait()
	close(results)
	matched, replayed := 0, 0
	for result := range results {
		switch {
		case result.Matched:
			matched++
		case result.ErrorCode == "decision-replay":
			replayed++
		default:
			t.Fatalf("unexpected concurrent result: %+v", result)
		}
	}
	if matched != 1 || replayed != contenders-1 {
		t.Fatalf("concurrent consumption matched=%d replayed=%d", matched, replayed)
	}
}

func TestDecisionBindingExpiresAndRestartLosesAuthority(t *testing.T) {
	now := time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC)
	key := []byte("0123456789abcdef0123456789abcdef")
	store, err := newDecisionBindingStoreWithKey(time.Second, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := testSSHOperationTarget("ssh.authentication", "deploy", "SHA256:host-a")
	capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: request})
	if issue.ErrorCode != "" {
		t.Fatal(issue)
	}
	restartCopy := decisionCapability{raw: append([]byte(nil), capability.raw...)}
	now = now.Add(2 * time.Second)
	if result := store.consume(capability, request); result.ErrorCode != "decision-binding-missing" {
		t.Fatalf("expired decision survived: %+v", result)
	}
	restarted, err := newDecisionBindingStoreWithKey(time.Second, key, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if result := restarted.consume(restartCopy, request); result.ErrorCode != "decision-binding-missing" {
		t.Fatalf("restart restored decision authority: %+v", result)
	}
}

func testDecisionBindingStore(t *testing.T) *decisionBindingStore {
	t.Helper()
	store, err := newDecisionBindingStoreWithKey(
		30*time.Second,
		[]byte("0123456789abcdef0123456789abcdef"),
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testSSHOperationTarget(operation, remoteUser, hostKey string) operationTarget {
	return operationTarget{
		SchemaVersion:  decisionBindingSchemaVersion,
		Surface:        "ssh-agent",
		Operation:      operation,
		TargetKind:     "ssh-key",
		TargetID:       "fixture-key-a",
		KeyFingerprint: "SHA256:key-a",
		RemoteUser:     remoteUser, HostKeyFingerprint: hostKey,
		PayloadDigest: digestHex(fmt.Sprintf("%s/%s/%s", operation, remoteUser, hostKey)),
	}
}

func digestHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
