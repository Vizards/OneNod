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
	"syscall"
	"time"
)

const (
	maximumOutcomeStateBytes   = 64 * 1024
	productionOutcomeStateRoot = "/Library/Application Support/Beholder/state/outcomes/v1"
)

type persistedOutcomeState struct {
	SchemaVersion       int       `json:"schema_version"`
	RecordType          string    `json:"record_type"`
	State               string    `json:"state"`
	EvidenceID          string    `json:"evidence_id"`
	TargetSHA256        string    `json:"target_sha256"`
	OutcomeSHA256       string    `json:"outcome_sha256,omitempty"`
	RequesterUID        uint32    `json:"requester_uid"`
	RequesterProcessRef string    `json:"requester_process_ref"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type outcomeUsedBinding struct {
	targetSHA256  string
	outcomeSHA256 string
	expiresAt     time.Time
}

func initializeOutcomeStateRoot(root string) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("outcome state root must be absolute and canonical")
	}
	if err := os.MkdirAll(root, 0o700); err != nil || os.Chmod(root, 0o700) != nil {
		return errors.New("create outcome state root failed")
	}
	return verifyOutcomeStateDirectory(root)
}

func verifyOutcomeStateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("outcome state directory identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("outcome state directory owner mismatch")
	}
	return nil
}

func outcomeStatePath(root, evidenceID string) string {
	digest := sha256.Sum256([]byte(evidenceID))
	return filepath.Join(root, hex.EncodeToString(digest[:])+".json")
}

func encodeOutcomeState(value persistedOutcomeState) ([]byte, error) {
	if !validPersistedOutcomeState(value) {
		return nil, errors.New("invalid outcome state")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func validPersistedOutcomeState(value persistedOutcomeState) bool {
	if value.SchemaVersion != 1 || value.RecordType != "beholder_outcome_correlation" ||
		(value.State != "pending" && value.State != "recorded") || !safeJoinKey(value.EvidenceID) ||
		!validCoreBinarySHA256(value.TargetSHA256) || value.ExpiresAt.IsZero() ||
		value.RequesterProcessRef == "" || len(value.RequesterProcessRef) > 128 {
		return false
	}
	if value.State == "pending" {
		return value.OutcomeSHA256 == ""
	}
	return validCoreBinarySHA256(value.OutcomeSHA256)
}

func writeOutcomeState(root string, value persistedOutcomeState) error {
	if root == "" {
		return nil
	}
	encoded, err := encodeOutcomeState(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	staged, err := os.CreateTemp(root, ".outcome-state-")
	if err != nil {
		return errors.New("stage outcome state failed")
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
		return errors.New("secure outcome state failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write outcome state failed")
	}
	if err := os.Rename(stagedPath, outcomeStatePath(root, value.EvidenceID)); err != nil {
		return errors.New("activate outcome state failed")
	}
	complete = true
	if directory, err := os.Open(root); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func readOutcomeState(path string) (persistedOutcomeState, error) {
	var value persistedOutcomeState
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximumOutcomeStateBytes {
		return value, errors.New("outcome state file identity mismatch")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return value, errors.New("outcome state file owner mismatch")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return persistedOutcomeState{}, errors.New("decode outcome state failed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validPersistedOutcomeState(value) {
		return persistedOutcomeState{}, errors.New("invalid outcome state")
	}
	return value, nil
}

func (coordinator *transportCoordinator) loadOutcomeStates(now time.Time) error {
	if coordinator == nil || coordinator.outcomeStateRoot == "" {
		return nil
	}
	entries, err := os.ReadDir(coordinator.outcomeStateRoot)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name() < entries[right].Name() })
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return errors.New("unexpected outcome state entry")
		}
		path := filepath.Join(coordinator.outcomeStateRoot, entry.Name())
		state, err := readOutcomeState(path)
		if err != nil || path != outcomeStatePath(coordinator.outcomeStateRoot, state.EvidenceID) {
			return errors.New("load outcome state failed")
		}
		if !state.ExpiresAt.After(now) {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return errors.New("remove expired outcome state failed")
			}
			continue
		}
		if _, pending := coordinator.outcomes[state.EvidenceID]; pending {
			return errors.New("duplicate outcome state")
		}
		if _, recorded := coordinator.outcomeUsed[state.EvidenceID]; recorded {
			return errors.New("duplicate outcome state")
		}
		if state.State == "pending" {
			coordinator.outcomes[state.EvidenceID] = outcomeBinding{
				targetSHA256: state.TargetSHA256, processRef: state.RequesterProcessRef,
				requesterUID: state.RequesterUID, expiresAt: state.ExpiresAt,
			}
		} else {
			coordinator.outcomeUsed[state.EvidenceID] = outcomeUsedBinding{
				targetSHA256: state.TargetSHA256, outcomeSHA256: state.OutcomeSHA256,
				expiresAt: state.ExpiresAt,
			}
		}
	}
	return nil
}

func outcomeSHA256(outcome humanOutcome) (string, bool) {
	encoded, err := json.Marshal(outcome)
	if err != nil {
		return "", false
	}
	defer clear(encoded)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func (coordinator *transportCoordinator) persistPendingOutcome(
	evidenceID string,
	binding outcomeBinding,
) error {
	return writeOutcomeState(coordinator.outcomeStateRoot, persistedOutcomeState{
		SchemaVersion: 1, RecordType: "beholder_outcome_correlation", State: "pending",
		EvidenceID: evidenceID, TargetSHA256: binding.targetSHA256,
		RequesterUID: binding.requesterUID, RequesterProcessRef: binding.processRef,
		ExpiresAt: binding.expiresAt,
	})
}

func (coordinator *transportCoordinator) persistRecordedOutcome(
	evidenceID string,
	binding outcomeBinding,
	outcomeDigest string,
) error {
	return writeOutcomeState(coordinator.outcomeStateRoot, persistedOutcomeState{
		SchemaVersion: 1, RecordType: "beholder_outcome_correlation", State: "recorded",
		EvidenceID: evidenceID, TargetSHA256: binding.targetSHA256, OutcomeSHA256: outcomeDigest,
		RequesterUID: binding.requesterUID, RequesterProcessRef: binding.processRef,
		ExpiresAt: binding.expiresAt,
	})
}

func (coordinator *transportCoordinator) removeOutcomeState(evidenceID string) {
	if coordinator == nil || coordinator.outcomeStateRoot == "" {
		return
	}
	_ = os.Remove(outcomeStatePath(coordinator.outcomeStateRoot, evidenceID))
}
