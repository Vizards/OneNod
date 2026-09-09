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
	"strings"
	"sync"
	"syscall"
)

const productionPromptLedgerRoot = "/Library/Application Support/Beholder/state/contexts/v1"

// The protected ledger stores a digest from a verified UserPromptSubmit event,
// never raw prompt text. A session file alone cannot establish this proof.
type promptLedger struct {
	mu   sync.Mutex
	root string
}

type promptProof struct {
	SchemaVersion  int    `json:"schema_version"`
	SessionID      string `json:"session_id"`
	TurnID         string `json:"turn_id"`
	TranscriptPath string `json:"transcript_path"`
	PromptSHA256   string `json:"prompt_sha256"`
}

func (broker *broker) configurePromptLedger(root string) error {
	if broker.trustMode == "production" && root != productionPromptLedgerRoot {
		return errors.New("invalid prompt ledger root")
	}
	if err := initializeOutcomeStateRoot(root); err != nil {
		return err
	}
	broker.promptLedger = &promptLedger{root: root}
	return nil
}

func (ledger *promptLedger) remember(observation promptObservation) error {
	if ledger == nil {
		return nil
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := verifyOutcomeStateDirectory(ledger.root); err != nil {
		return err
	}
	digest := sha256.Sum256(observation.Prompt)
	proof := promptProof{SchemaVersion: 1, SessionID: observation.SessionID, TurnID: observation.TurnID,
		TranscriptPath: observation.TranscriptPath, PromptSHA256: hex.EncodeToString(digest[:])}
	path := outcomeStatePath(ledger.root, observation.SessionID)
	if prior, err := readPromptProof(path); err == nil && prior.TurnID == proof.TurnID && prior != proof {
		return errors.New("prompt-proof-conflict")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	encoded, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	defer clear(encoded)
	staged, err := os.CreateTemp(ledger.root, ".prompt-proof-")
	if err != nil {
		return err
	}
	defer os.Remove(staged.Name())
	defer staged.Close()
	if staged.Chmod(0o600) != nil {
		return errors.New("prompt-proof-write-failed")
	}
	if _, err := staged.Write(encoded); err != nil || staged.Sync() != nil || staged.Close() != nil {
		return errors.New("prompt-proof-write-failed")
	}
	if err := os.Rename(staged.Name(), path); err != nil {
		return err
	}
	directory, err := os.Open(ledger.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readPromptProof(path string) (promptProof, error) {
	var proof promptProof
	info, err := os.Lstat(path)
	if err != nil {
		return proof, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 16*1024 {
		return proof, errors.New("prompt-proof-identity-invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return proof, errors.New("prompt-proof-owner-invalid")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return proof, err
	}
	defer clear(encoded)
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&proof) != nil || proof.SchemaVersion != 1 || !safeJoinKey(proof.SessionID) ||
		!safeJoinKey(proof.TurnID) || !filepath.IsAbs(proof.TranscriptPath) || !validCoreBinarySHA256(proof.PromptSHA256) {
		return promptProof{}, errors.New("prompt-proof-invalid")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return promptProof{}, errors.New("prompt-proof-invalid")
	}
	return proof, nil
}

func (broker *broker) restorePrompt(observation hostObservation) string {
	if broker.promptLedger == nil {
		return "prompt-binding-missing"
	}
	ledger := broker.promptLedger
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if verifyOutcomeStateDirectory(ledger.root) != nil {
		return "prompt-proof-unavailable"
	}
	proof, err := readPromptProof(outcomeStatePath(ledger.root, observation.SessionID))
	if err != nil {
		return "prompt-proof-unavailable"
	}
	if proof.SessionID != observation.SessionID || proof.TurnID != observation.TurnID ||
		proof.TranscriptPath != observation.TranscriptPath {
		return "prompt-proof-binding-mismatch"
	}
	prompt, err := recoverVerifiedPrompt(proof)
	if err != nil {
		return "prompt-proof-content-mismatch"
	}
	defer clear(prompt)
	result := broker.contexts.registerPrompt(observation.SessionID, observation.TurnID, prompt)
	return result.ErrorCode
}

func recoverVerifiedPrompt(proof promptProof) ([]byte, error) {
	file, err := os.Open(proof.TranscriptPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("prompt transcript unavailable")
	}
	end, err := completeSessionSnapshotEnd(file, info.Size())
	if err != nil {
		return nil, err
	}
	var candidate []byte
	stopped, _, err := visitSessionLinesReverse(file, end, maximumRecentEventScanSize, func(line []byte) (bool, error) {
		var event struct {
			Type    string `json:"type"`
			Payload struct {
				Type    string `json:"type"`
				TurnID  string `json:"turn_id"`
				Role    string `json:"role"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &event) != nil {
			return false, errors.New("invalid prompt transcript")
		}
		if event.Type == "turn_context" && event.Payload.TurnID != "" && event.Payload.TurnID != proof.TurnID {
			return false, errors.New("prompt turn boundary mismatch")
		}
		if event.Type == "event_msg" && event.Payload.Type == "task_started" {
			if event.Payload.TurnID != proof.TurnID || candidate == nil {
				return false, errors.New("verified prompt unavailable")
			}
			return true, nil
		}
		if event.Type == "response_item" && event.Payload.Type == "message" && event.Payload.Role == "user" {
			parts := []string{}
			for _, part := range event.Payload.Content {
				if part.Type == "input_text" || part.Type == "text" {
					parts = append(parts, part.Text)
				}
			}
			text := []byte(strings.Join(parts, "\n"))
			digest := sha256.Sum256(text)
			if hex.EncodeToString(digest[:]) == proof.PromptSHA256 {
				clear(candidate)
				candidate = text
			} else {
				clear(text)
			}
		}
		return false, nil
	})
	if err != nil || !stopped || candidate == nil {
		clear(candidate)
		return nil, errors.New("verified prompt unavailable")
	}
	return candidate, nil
}
