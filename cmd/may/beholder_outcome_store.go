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
)

const (
	beholderOutcomeSpoolSchema = 1
	maximumBeholderOutcomeFile = beholderMaximumWireSize
	maximumOutcomeFlushBatch   = 64
)

type beholderOutcomeRootFunc func() (string, error)

type beholderPendingOutcome struct {
	SchemaVersion int                     `json:"schema_version"`
	RecordType    string                  `json:"record_type"`
	EvidenceID    string                  `json:"evidence_id"`
	Target        beholderOperationTarget `json:"operation_target"`
	HumanOutcome  beholderHumanOutcome    `json:"human_outcome"`
}

func defaultBeholderOutcomeRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("resolve Beholder outcome spool failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "beholder-outcomes", "v1"), nil
}

func validPendingBeholderOutcome(value beholderPendingOutcome) bool {
	if value.SchemaVersion != beholderOutcomeSpoolSchema ||
		value.RecordType != "beholder_pending_human_outcome" ||
		value.EvidenceID != value.HumanOutcome.EvidenceID ||
		!safeBeholderToken(value.EvidenceID, 8, 96) ||
		!validBeholderOperationTarget(value.Target) || !validBeholderHumanOutcome(value.HumanOutcome) {
		return false
	}
	digest, ok := beholderOperationTargetSHA256(value.Target)
	return ok && digest == value.HumanOutcome.OperationTargetSHA256
}

func ensureBeholderOutcomeRoot(root string) error {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("invalid Beholder outcome spool root")
	}
	expected := filepath.Join(home, userAgentDirectoryName, "beholder-outcomes", "v1")
	if root != expected {
		return errors.New("Beholder outcome spool is outside the OneNod root")
	}
	current := home
	for _, element := range []string{userAgentDirectoryName, "beholder-outcomes", "v1"} {
		current = filepath.Join(current, element)
		if err := ensureBeholderPrivateDirectory(current); err != nil {
			return err
		}
	}
	return verifyBeholderOutcomeDirectory(root)
}

func ensureBeholderPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return errors.New("create Beholder outcome spool directory failed")
		}
		info, err = os.Lstat(path)
	}
	if err != nil || info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Beholder outcome spool path is unsafe")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return errors.New("secure Beholder outcome spool directory failed")
	}
	return nil
}

func verifyBeholderOutcomeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("Beholder outcome spool directory is unsafe")
	}
	return nil
}

func pendingBeholderOutcomePath(root, evidenceID string) string {
	digest := sha256.Sum256([]byte(evidenceID))
	return filepath.Join(root, hex.EncodeToString(digest[:])+".json")
}

func encodePendingBeholderOutcome(value beholderPendingOutcome) ([]byte, error) {
	if !validPendingBeholderOutcome(value) {
		return nil, errors.New("invalid pending Beholder outcome")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil || len(encoded) >= maximumBeholderOutcomeFile {
		clear(encoded)
		return nil, errors.New("encode pending Beholder outcome failed")
	}
	return append(encoded, '\n'), nil
}

func persistPendingBeholderOutcome(root string, value beholderPendingOutcome) error {
	encoded, err := encodePendingBeholderOutcome(value)
	if err != nil {
		return err
	}
	defer clear(encoded)
	path := pendingBeholderOutcomePath(root, value.EvidenceID)
	if existing, err := readPendingBeholderOutcome(path); err == nil {
		existingBytes, encodeErr := encodePendingBeholderOutcome(existing)
		matched := encodeErr == nil && bytes.Equal(existingBytes, encoded)
		clear(existingBytes)
		if matched {
			return nil
		}
		return errors.New("conflicting pending Beholder outcome")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staged, err := os.CreateTemp(root, ".pending-outcome-")
	if err != nil {
		return errors.New("stage pending Beholder outcome failed")
	}
	stagedPath := staged.Name()
	defer os.Remove(stagedPath)
	if staged.Chmod(0o600) != nil {
		staged.Close()
		return errors.New("secure pending Beholder outcome failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("write pending Beholder outcome failed")
	}
	if err := os.Link(stagedPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errors.New("activate pending Beholder outcome failed")
		}
		existing, readErr := readPendingBeholderOutcome(path)
		existingBytes, encodeErr := encodePendingBeholderOutcome(existing)
		matched := readErr == nil && encodeErr == nil && bytes.Equal(existingBytes, encoded)
		clear(existingBytes)
		if !matched {
			return errors.New("conflicting pending Beholder outcome")
		}
	}
	return syncBeholderOutcomeDirectory(root)
}

func readPendingBeholderOutcome(path string) (beholderPendingOutcome, error) {
	var value beholderPendingOutcome
	info, err := os.Lstat(path)
	if err != nil {
		return value, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximumBeholderOutcomeFile {
		return value, errors.New("pending Beholder outcome file is unsafe")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return value, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return beholderPendingOutcome{}, errors.New("pending Beholder outcome JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || !validPendingBeholderOutcome(value) ||
		path != pendingBeholderOutcomePath(filepath.Dir(path), value.EvidenceID) {
		return beholderPendingOutcome{}, errors.New("pending Beholder outcome is invalid")
	}
	return value, nil
}

func flushPendingBeholderOutcomes(deps dependencies) {
	if deps.beholder == nil || deps.beholderOutcomeRoot == nil {
		return
	}
	root, err := deps.beholderOutcomeRoot()
	if err != nil || ensureBeholderOutcomeRoot(root) != nil {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	type pendingEntry struct {
		name       string
		modifiedAt int64
	}
	pendingEntries := make([]pendingEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		pendingEntries = append(pendingEntries, pendingEntry{name: entry.Name(), modifiedAt: info.ModTime().UnixNano()})
	}
	sort.Slice(pendingEntries, func(left, right int) bool {
		if pendingEntries[left].modifiedAt == pendingEntries[right].modifiedAt {
			return pendingEntries[left].name < pendingEntries[right].name
		}
		return pendingEntries[left].modifiedAt > pendingEntries[right].modifiedAt
	})
	processed := 0
	for _, entry := range pendingEntries {
		if processed >= maximumOutcomeFlushBatch {
			break
		}
		processed++
		path := filepath.Join(root, entry.name)
		pending, err := readPendingBeholderOutcome(path)
		if err != nil {
			continue
		}
		acknowledged, reachable := sendPendingBeholderOutcome(deps, pending)
		if !reachable {
			break
		}
		if !acknowledged {
			continue
		}
		if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
			_ = syncBeholderOutcomeDirectory(root)
		}
	}
}

func sendPendingBeholderOutcome(deps dependencies, pending beholderPendingOutcome) (bool, bool) {
	if deps.beholder == nil || !validPendingBeholderOutcome(pending) {
		return false, false
	}
	response, err := deps.beholder(beholderWireRequest{
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "human-outcome",
		EvidenceID:    pending.EvidenceID,
		Operation:     &pending.Target,
		HumanOutcome:  &pending.HumanOutcome,
	})
	if err != nil {
		return false, false
	}
	return response.SchemaVersion == beholderProtocolSchemaVersion && response.Accepted &&
		response.ErrorCode == nil && response.EvidenceID == pending.EvidenceID, true
}

func syncBeholderOutcomeDirectory(root string) error {
	directory, err := os.Open(root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
