package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

const requesterStateSchema = 1

var requesterSlotPattern = regexp.MustCompile(`^(?:active|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)

type requesterLocalState struct {
	ActiveSlot    string `json:"active_slot"`
	Origin        string `json:"origin"`
	SchemaVersion int    `json:"schema_version"`
}

func requesterStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for requester state failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "requester.json"), nil
}

func activeRequesterSlot(origin string) (string, error) {
	slot, selected, err := selectedRequesterSlot(origin)
	if err != nil {
		return "", err
	}
	if !selected {
		return "active", nil
	}
	return slot, nil
}

func selectedRequesterSlot(origin string) (string, bool, error) {
	path, err := requesterStatePath()
	if err != nil {
		return "", false, err
	}
	encoded, exists, err := readOptionalRegularFile(path, maxManifestBytes)
	if err != nil {
		return "", false, err
	}
	if !exists {
		return "", false, nil
	}
	var state requesterLocalState
	if err := json.Unmarshal(encoded, &state); err != nil ||
		state.SchemaVersion != requesterStateSchema || state.Origin != origin ||
		!requesterSlotPattern.MatchString(state.ActiveSlot) {
		return "", false, errors.New("local requester identity state is invalid or belongs to another Origin")
	}
	return state.ActiveSlot, true, nil
}

func activateRequesterSlot(origin, slot string) error {
	if !requesterSlotPattern.MatchString(slot) {
		return errors.New("requester identity slot is invalid")
	}
	path, err := requesterStatePath()
	if err != nil {
		return err
	}
	state := requesterLocalState{
		ActiveSlot: slot, Origin: origin, SchemaVersion: requesterStateSchema,
	}
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return errors.New("encode local requester identity state failed")
	}
	encoded = append(encoded, '\n')
	return writeAtomicUserConfig(path, encoded, 0o600)
}
