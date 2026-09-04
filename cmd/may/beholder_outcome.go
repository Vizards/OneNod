package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// beholderOutcomeTracker is observation-only. It never changes the existing
// Gateway, remembered-grant, PWA, or local 1Password authorization result.
type beholderOutcomeTracker struct {
	deps                dependencies
	observation         beholderObservation
	requestID           string
	authorizationSource string
	statusTimeline      []beholderOutcomeStatus
	failureStage        string
	credentialOperation bool
	finished            bool
}

func newBeholderOutcomeTracker(
	deps dependencies,
	observation beholderObservation,
	credentialOperation bool,
) *beholderOutcomeTracker {
	return &beholderOutcomeTracker{
		deps: deps, observation: observation, authorizationSource: "unknown",
		statusTimeline: []beholderOutcomeStatus{}, credentialOperation: credentialOperation,
	}
}

func (tracker *beholderOutcomeTracker) setRequest(requestID, initialStatus string) {
	if tracker == nil {
		return
	}
	if safeBeholderField(requestID, 256, false) {
		tracker.requestID = requestID
	}
	tracker.observeStatus(initialStatus)
}

func (tracker *beholderOutcomeTracker) observeStatus(status string) {
	if tracker == nil {
		return
	}
	normalized := normalizeStatus(status)
	if !safeBeholderField(normalized, 96, false) {
		return
	}
	if len(tracker.statusTimeline) > 0 && tracker.statusTimeline[len(tracker.statusTimeline)-1].Status == normalized {
		return
	}
	tracker.statusTimeline = append(tracker.statusTimeline, beholderOutcomeStatus{
		Status: normalized, ObservedAt: time.Now().UTC(),
	})
	if normalized == "pending" || normalized == "waiting_approval" {
		tracker.authorizationSource = "pwa-interactive"
	} else if (normalized == "approved" || normalized == "authorized") && tracker.authorizationSource == "unknown" {
		tracker.authorizationSource = "remembered-grant"
	}
}

func (tracker *beholderOutcomeTracker) useLocalFallback() {
	if tracker == nil {
		return
	}
	tracker.authorizationSource = "local-fallback"
	tracker.observeStatus("local-fallback")
}

func (tracker *beholderOutcomeTracker) failAt(stage string) {
	if tracker == nil || !safeBeholderField(stage, 96, false) {
		return
	}
	tracker.failureStage = stage
}

func (tracker *beholderOutcomeTracker) finish(resultErr error, operationCompleted bool) {
	if tracker == nil || tracker.finished || tracker.observation.EvidenceID == "" {
		return
	}
	tracker.finished = true
	decision := classifyBeholderHumanDecision(resultErr, tracker.statusTimeline)
	if operationCompleted {
		decision = "approved"
	}
	var requestID *string
	if tracker.requestID != "" {
		value := tracker.requestID
		requestID = &value
	}
	outcome := beholderHumanOutcome{
		SchemaVersion: 1, RecordType: "beholder_human_outcome",
		EvidenceID: tracker.observation.EvidenceID, OneNodRequestID: requestID,
		AuthorizationSource: tracker.authorizationSource, Decision: decision,
		StatusTimeline:      append([]beholderOutcomeStatus(nil), tracker.statusTimeline...),
		OperationCompleted:  operationCompleted,
		CredentialDelivered: operationCompleted && tracker.credentialOperation,
		FailureStage:        tracker.failureStage, ObservedAt: time.Now().UTC(),
	}
	if targetSHA256, ok := beholderOperationTargetSHA256(tracker.observation.Target); ok {
		outcome.OperationTargetSHA256 = targetSHA256
	}
	status := recordBeholderHumanOutcome(tracker.deps, tracker.observation, outcome)
	if tracker.deps.stderr != nil {
		fmt.Fprintf(
			tracker.deps.stderr,
			"Beholder human outcome %s: %s.\n",
			tracker.observation.EvidenceID,
			status,
		)
	}
}

func classifyBeholderHumanDecision(err error, timeline []beholderOutcomeStatus) string {
	if err == nil {
		return "approved"
	}
	if len(timeline) > 0 {
		switch timeline[len(timeline)-1].Status {
		case "denied", "rejected":
			return "rejected"
		case "expired":
			return "expired"
		}
	}
	message := strings.ToLower(err.Error())
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(message, "timed out") ||
		strings.Contains(message, "deadline exceeded") {
		return "timed_out"
	}
	if strings.Contains(message, "expired") {
		return "expired"
	}
	if strings.Contains(message, "denied") || strings.Contains(message, "rejected") {
		return "rejected"
	}
	return "error"
}
