package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	maximumOutcomeQueueBytes    = 2 * 1024 * 1024
	maximumOutcomeDeliveryBatch = 64
	outcomeDeliveryRetryBase    = 5 * time.Second
	outcomeDeliveryRetryMaximum = 5 * time.Minute
	productionOutcomeQueueRoot  = "/Library/Application Support/Beholder/state/outcome-delivery/v1"
)

type queuedHumanOutcome struct {
	binding       outcomeBinding
	outcomeSHA256 string
	outcome       humanOutcome
	attemptCount  int
	lastAttemptAt *time.Time
	lastErrorCode string
}

type persistedHumanOutcomeDelivery struct {
	SchemaVersion       int          `json:"schema_version"`
	RecordType          string       `json:"record_type"`
	State               string       `json:"state"`
	EvidenceID          string       `json:"evidence_id"`
	TargetSHA256        string       `json:"target_sha256"`
	OutcomeSHA256       string       `json:"outcome_sha256"`
	RequesterUID        uint32       `json:"requester_uid"`
	RequesterProcessRef string       `json:"requester_process_ref"`
	ExpiresAt           time.Time    `json:"expires_at"`
	HumanOutcome        humanOutcome `json:"human_outcome"`
	AttemptCount        int          `json:"attempt_count"`
	LastAttemptAt       *time.Time   `json:"last_attempt_at"`
	LastErrorCode       string       `json:"last_error_code,omitempty"`
}

func initializeOutcomeQueueRoot(root string) error {
	if err := initializeOutcomeStateRoot(root); err != nil {
		return errors.New("initialize outcome delivery root failed")
	}
	return nil
}

func outcomeQueuePath(root, evidenceID string) string {
	digest := sha256.Sum256([]byte(evidenceID))
	return filepath.Join(root, hex.EncodeToString(digest[:])+".json")
}

func cloneHumanOutcome(value humanOutcome) humanOutcome {
	cloned := value
	if value.OneNodRequestID != nil {
		requestID := *value.OneNodRequestID
		cloned.OneNodRequestID = &requestID
	}
	cloned.StatusTimeline = append([]outcomeStatus(nil), value.StatusTimeline...)
	return cloned
}

func persistedHumanOutcome(evidenceID string, value queuedHumanOutcome) persistedHumanOutcomeDelivery {
	return persistedHumanOutcomeDelivery{
		SchemaVersion: 1, RecordType: "beholder_queued_human_outcome", State: "queued",
		EvidenceID: evidenceID, TargetSHA256: value.binding.targetSHA256,
		OutcomeSHA256: value.outcomeSHA256, RequesterUID: value.binding.requesterUID,
		RequesterProcessRef: value.binding.processRef, ExpiresAt: value.binding.expiresAt,
		HumanOutcome: cloneHumanOutcome(value.outcome), AttemptCount: value.attemptCount,
		LastAttemptAt: value.lastAttemptAt, LastErrorCode: value.lastErrorCode,
	}
}

func validPersistedHumanOutcomeDelivery(value persistedHumanOutcomeDelivery) bool {
	if value.SchemaVersion != 1 || value.RecordType != "beholder_queued_human_outcome" ||
		value.State != "queued" || !safeJoinKey(value.EvidenceID) ||
		!validCoreBinarySHA256(value.TargetSHA256) || !validCoreBinarySHA256(value.OutcomeSHA256) ||
		value.RequesterProcessRef == "" || len(value.RequesterProcessRef) > 128 || value.ExpiresAt.IsZero() ||
		value.AttemptCount < 0 || value.AttemptCount > 1_000_000 ||
		(value.AttemptCount == 0 && (value.LastAttemptAt != nil || value.LastErrorCode != "")) ||
		(value.AttemptCount > 0 && (value.LastAttemptAt == nil ||
			!safeDecisionField(value.LastErrorCode, 128, false))) ||
		!validHumanOutcome(value.HumanOutcome) || value.HumanOutcome.EvidenceID != value.EvidenceID ||
		value.HumanOutcome.OperationTargetSHA256 != value.TargetSHA256 {
		return false
	}
	digest, ok := outcomeSHA256(value.HumanOutcome)
	return ok && digest == value.OutcomeSHA256
}

func encodeHumanOutcomeDelivery(value persistedHumanOutcomeDelivery) ([]byte, error) {
	if !validPersistedHumanOutcomeDelivery(value) {
		return nil, errors.New("invalid queued human outcome")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(encoded) >= maximumOutcomeQueueBytes {
		clear(encoded)
		return nil, errors.New("encode queued human outcome failed")
	}
	return append(encoded, '\n'), nil
}

func writeHumanOutcomeDelivery(root string, value persistedHumanOutcomeDelivery) error {
	encoded, err := encodeHumanOutcomeDelivery(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	staged, err := os.CreateTemp(root, ".outcome-delivery-")
	if err != nil {
		return errors.New("stage queued human outcome failed")
	}
	stagedPath := staged.Name()
	complete := false
	defer func() {
		_ = staged.Close()
		if !complete {
			_ = os.Remove(stagedPath)
		}
	}()
	if staged.Chmod(0o600) != nil {
		return errors.New("secure queued human outcome failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write queued human outcome failed")
	}
	if err := os.Rename(stagedPath, outcomeQueuePath(root, value.EvidenceID)); err != nil {
		return errors.New("activate queued human outcome failed")
	}
	complete = true
	if directory, err := os.Open(root); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func readHumanOutcomeDelivery(path string) (persistedHumanOutcomeDelivery, error) {
	var value persistedHumanOutcomeDelivery
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximumOutcomeQueueBytes {
		return value, errors.New("queued human outcome file identity mismatch")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	defer clear(contents)
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return persistedHumanOutcomeDelivery{}, errors.New("decode queued human outcome failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validPersistedHumanOutcomeDelivery(value) {
		return persistedHumanOutcomeDelivery{}, errors.New("invalid queued human outcome")
	}
	return value, nil
}

func (coordinator *transportCoordinator) persistQueuedHumanOutcome(
	evidenceID string,
	queued queuedHumanOutcome,
) error {
	if coordinator == nil || coordinator.outcomeQueueRoot == "" {
		return errors.New("outcome delivery queue unavailable")
	}
	return writeHumanOutcomeDelivery(coordinator.outcomeQueueRoot, persistedHumanOutcome(evidenceID, queued))
}

func (coordinator *transportCoordinator) removeQueuedHumanOutcome(evidenceID string) {
	if coordinator == nil || coordinator.outcomeQueueRoot == "" {
		return
	}
	_ = os.Remove(outcomeQueuePath(coordinator.outcomeQueueRoot, evidenceID))
}

func (coordinator *transportCoordinator) loadOutcomeQueue(now time.Time) error {
	if coordinator == nil || coordinator.outcomeQueueRoot == "" {
		return nil
	}
	entries, err := os.ReadDir(coordinator.outcomeQueueRoot)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("unexpected outcome delivery entry")
		}
		path := filepath.Join(coordinator.outcomeQueueRoot, entry.Name())
		persisted, err := readHumanOutcomeDelivery(path)
		if err != nil || path != outcomeQueuePath(coordinator.outcomeQueueRoot, persisted.EvidenceID) {
			return errors.New("load queued human outcome failed")
		}
		if !persisted.ExpiresAt.After(now) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove expired queued human outcome failed")
			}
			continue
		}
		if used, found := coordinator.outcomeUsed[persisted.EvidenceID]; found {
			if used.targetSHA256 != persisted.TargetSHA256 || used.outcomeSHA256 != persisted.OutcomeSHA256 {
				return errors.New("recorded outcome conflicts with queued delivery")
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove recorded queued human outcome failed")
			}
			continue
		}
		binding := outcomeBinding{
			targetSHA256: persisted.TargetSHA256, processRef: persisted.RequesterProcessRef,
			requesterUID: persisted.RequesterUID, expiresAt: persisted.ExpiresAt,
		}
		if current, found := coordinator.outcomes[persisted.EvidenceID]; found {
			if current.targetSHA256 != binding.targetSHA256 || current.processRef != binding.processRef ||
				current.requesterUID != binding.requesterUID || !current.expiresAt.Equal(binding.expiresAt) {
				return errors.New("queued human outcome binding conflict")
			}
		} else {
			coordinator.outcomes[persisted.EvidenceID] = binding
			if err := coordinator.persistPendingOutcome(persisted.EvidenceID, binding); err != nil {
				return errors.New("recover queued human outcome binding failed")
			}
		}
		coordinator.outcomeQueue[persisted.EvidenceID] = queuedHumanOutcome{
			binding: binding, outcomeSHA256: persisted.OutcomeSHA256,
			outcome: cloneHumanOutcome(persisted.HumanOutcome), attemptCount: persisted.AttemptCount,
			lastAttemptAt: persisted.LastAttemptAt, lastErrorCode: persisted.LastErrorCode,
		}
	}
	return nil
}

func (coordinator *transportCoordinator) wakeOutcomeWorker() {
	if coordinator == nil || coordinator.outcomeWake == nil {
		return
	}
	select {
	case coordinator.outcomeWake <- struct{}{}:
	default:
	}
}

func (coordinator *transportCoordinator) runOutcomeWorker() {
	defer coordinator.outcomeWorker.Done()
	ticker := time.NewTicker(outcomeDeliveryRetryBase)
	defer ticker.Stop()
	for {
		select {
		case <-coordinator.outcomeWake:
			coordinator.flushOutcomeQueue()
		case <-ticker.C:
			coordinator.flushOutcomeQueue()
		case <-coordinator.outcomeStop:
			return
		}
	}
}

func outcomeDeliveryRetryDelay(attemptCount int) time.Duration {
	if attemptCount <= 0 {
		return 0
	}
	delay := outcomeDeliveryRetryBase
	for count := 1; count < attemptCount && delay < outcomeDeliveryRetryMaximum; count++ {
		delay *= 2
		if delay > outcomeDeliveryRetryMaximum {
			delay = outcomeDeliveryRetryMaximum
		}
	}
	return delay
}

func (coordinator *transportCoordinator) flushOutcomeQueue() {
	if coordinator == nil || coordinator.broker == nil || coordinator.broker.gatekeeper == nil {
		return
	}
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	if coordinator.closed {
		coordinator.mu.Unlock()
		return
	}
	coordinator.expireLocked(now)
	type delivery struct {
		evidenceID string
		queued     queuedHumanOutcome
	}
	deliveries := make([]delivery, 0, len(coordinator.outcomeQueue))
	for evidenceID, queued := range coordinator.outcomeQueue {
		if queued.lastAttemptAt != nil && queued.lastAttemptAt.Add(outcomeDeliveryRetryDelay(queued.attemptCount)).After(now) {
			continue
		}
		deliveries = append(deliveries, delivery{evidenceID: evidenceID, queued: queued})
		if len(deliveries) >= maximumOutcomeDeliveryBatch {
			break
		}
	}
	coordinator.mu.Unlock()
	sort.Slice(deliveries, func(left, right int) bool { return deliveries[left].evidenceID < deliveries[right].evidenceID })
	for _, delivery := range deliveries {
		err := coordinator.broker.gatekeeper.recordOutcome(cloneHumanOutcome(delivery.queued.outcome))
		coordinator.finishOutcomeDelivery(delivery.evidenceID, delivery.queued.outcomeSHA256, err)
	}
}

func (coordinator *transportCoordinator) finishOutcomeDelivery(
	evidenceID, outcomeDigest string,
	deliveryErr error,
) {
	now := coordinator.broker.now().UTC()
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	queued, found := coordinator.outcomeQueue[evidenceID]
	if !found || queued.outcomeSHA256 != outcomeDigest {
		return
	}
	if deliveryErr != nil {
		queued.attemptCount++
		queued.lastAttemptAt = &now
		queued.lastErrorCode = gatekeeperOutcomeFailureCode(deliveryErr)
		_ = coordinator.persistQueuedHumanOutcome(evidenceID, queued)
		coordinator.outcomeQueue[evidenceID] = queued
		return
	}
	if err := coordinator.persistRecordedOutcome(evidenceID, queued.binding, outcomeDigest); err != nil {
		queued.attemptCount++
		queued.lastAttemptAt = &now
		queued.lastErrorCode = "human-outcome-state-write-failed"
		_ = coordinator.persistQueuedHumanOutcome(evidenceID, queued)
		coordinator.outcomeQueue[evidenceID] = queued
		return
	}
	delete(coordinator.outcomes, evidenceID)
	coordinator.outcomeUsed[evidenceID] = outcomeUsedBinding{
		targetSHA256: queued.binding.targetSHA256, outcomeSHA256: outcomeDigest,
		expiresAt: queued.binding.expiresAt,
	}
	delete(coordinator.outcomeQueue, evidenceID)
	coordinator.removeQueuedHumanOutcome(evidenceID)
}
