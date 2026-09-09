package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	maximumSessionLineSize     = 16 * 1024 * 1024
	maximumRecentEventScanSize = 64 * 1024 * 1024
	reverseSessionBlockSize    = 1024 * 1024
	maximumRecentOps           = 12
)

type sessionEnvelope struct {
	Type    string `json:"type"`
	Payload struct {
		ID     string `json:"id"`
		CWD    string `json:"cwd"`
		TurnID string `json:"turn_id"`
		Type   string `json:"type"`
		Name   string `json:"name"`
	} `json:"payload"`
}

func validateTranscript(root, path, expectedSessionID, expectedTurnID, expectedCWD string) (bool, string, []string, string) {
	if !pathWithin(root, path) {
		return false, "unknown", nil, "transcript-outside-session-root"
	}
	metadataID, metadataCWD, err := readSessionMetadata(path)
	if err != nil {
		return false, "unknown", nil, "session-metadata-unavailable"
	}
	recentOps, turnID, taskStartedTurnID, err := readRecentEventContext(path)
	if err != nil {
		return false, "unknown", nil, "session-events-unavailable"
	}
	matched := metadataID == expectedSessionID && turnID == expectedTurnID && turnID == taskStartedTurnID
	if !matched {
		return false, cwdRelation(metadataCWD, expectedCWD), recentOps, "hook-evidence-conflict"
	}
	return true, cwdRelation(metadataCWD, expectedCWD), recentOps, ""
}

func readSessionMetadata(path string) (string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	scanner := newSessionScanner(file)
	for line := 0; line < 64 && scanner.Scan(); line++ {
		var envelope sessionEnvelope
		if json.Unmarshal(scanner.Bytes(), &envelope) != nil {
			return "", "", errors.New("invalid session metadata")
		}
		if envelope.Type == "session_meta" && safeJoinKey(envelope.Payload.ID) && filepath.IsAbs(envelope.Payload.CWD) {
			return envelope.Payload.ID, envelope.Payload.CWD, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	return "", "", errors.New("session metadata not found")
}

func readRecentEventContext(path string) ([]string, string, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, "", "", err
	}
	completeEnd, err := completeSessionSnapshotEnd(file, info.Size())
	if err != nil {
		return nil, "", "", err
	}

	state := reverseEventState{}
	stopped, reachedStart, err := visitSessionLinesReverse(
		file,
		completeEnd,
		maximumRecentEventScanSize,
		func(line []byte) (bool, error) {
			var envelope sessionEnvelope
			if json.Unmarshal(line, &envelope) != nil {
				return false, errors.New("invalid session event")
			}
			switch envelope.Type {
			case "turn_context":
				if envelope.Payload.TurnID == "" {
					return false, nil
				}
				return state.observeTurnContext(envelope.Payload.TurnID), nil
			case "event_msg":
				if envelope.Payload.Type == "task_started" && envelope.Payload.TurnID != "" {
					return state.observeTaskStarted(envelope.Payload.TurnID), nil
				}
			case "response_item":
				if envelope.Payload.Type == "custom_tool_call" && len(state.recentOpsNewestFirst) < maximumRecentOps {
					state.recentOpsNewestFirst = append(
						state.recentOpsNewestFirst,
						normalizeOperation(envelope.Payload.Name),
					)
				}
			}
			return false, nil
		})
	if err != nil {
		return nil, "", "", err
	}
	if !stopped {
		if !reachedStart || !state.sawTurn {
			return nil, "", "", errors.New("recent session event boundary unavailable")
		}
		state.taskStartedTurnID = ""
	}
	recentOps := make([]string, len(state.recentOpsNewestFirst))
	for index, operation := range state.recentOpsNewestFirst {
		recentOps[len(recentOps)-1-index] = operation
	}
	if recentOps == nil {
		recentOps = []string{}
	}
	return recentOps, state.turnID, state.taskStartedTurnID, nil
}

type reverseEventState struct {
	recentOpsNewestFirst []string
	turnID               string
	taskStartedTurnID    string
	sawTurn              bool
	awaitingPriorState   bool
}

func (state *reverseEventState) observeTaskStarted(turnID string) bool {
	if !state.sawTurn {
		state.sawTurn = true
		state.turnID = turnID
		state.taskStartedTurnID = turnID
		return true
	}
	if !state.awaitingPriorState {
		return true
	}
	if turnID == state.turnID {
		state.taskStartedTurnID = turnID
	}
	state.awaitingPriorState = false
	return true
}

func (state *reverseEventState) observeTurnContext(turnID string) bool {
	if !state.sawTurn {
		state.sawTurn = true
		state.turnID = turnID
		state.awaitingPriorState = true
		return false
	}
	if !state.awaitingPriorState {
		return true
	}
	if turnID == state.turnID {
		return false
	}
	state.awaitingPriorState = false
	return true
}

func completeSessionSnapshotEnd(file *os.File, size int64) (int64, error) {
	if size <= 0 {
		return 0, nil
	}
	last := []byte{0}
	if _, err := file.ReadAt(last, size-1); err != nil {
		return 0, err
	}
	if last[0] == '\n' {
		return size, nil
	}

	lowerBound := size - int64(maximumSessionLineSize) - 1
	if lowerBound < 0 {
		lowerBound = 0
	}
	for cursor := size; cursor > lowerBound; {
		start := cursor - int64(reverseSessionBlockSize)
		if start < lowerBound {
			start = lowerBound
		}
		chunk := make([]byte, cursor-start)
		if _, err := file.ReadAt(chunk, start); err != nil {
			return 0, err
		}
		if index := bytes.LastIndexByte(chunk, '\n'); index >= 0 {
			return start + int64(index) + 1, nil
		}
		cursor = start
	}
	if lowerBound > 0 {
		return 0, errors.New("incomplete session event exceeds maximum size")
	}
	return 0, nil
}

func visitSessionLinesReverse(
	file *os.File,
	end int64,
	maximumBytes int64,
	visit func([]byte) (bool, error),
) (stopped bool, reachedStart bool, err error) {
	if end < 0 || maximumBytes <= 0 || visit == nil {
		return false, false, errors.New("invalid reverse session scan")
	}
	cursor := end
	var pending []byte
	var scanned int64
	for cursor > 0 && scanned < maximumBytes {
		blockSize := int64(reverseSessionBlockSize)
		if blockSize > cursor {
			blockSize = cursor
		}
		if remaining := maximumBytes - scanned; blockSize > remaining {
			blockSize = remaining
		}
		start := cursor - blockSize
		chunk := make([]byte, blockSize)
		if _, err := file.ReadAt(chunk, start); err != nil {
			return false, false, err
		}
		data := make([]byte, 0, len(chunk)+len(pending))
		data = append(data, chunk...)
		data = append(data, pending...)
		parts := bytes.Split(data, []byte{'\n'})
		if len(data) > 0 && data[len(data)-1] == '\n' {
			parts = parts[:len(parts)-1]
		}

		if start > 0 {
			pending = append(pending[:0], parts[0]...)
			parts = parts[1:]
			if len(pending) > maximumSessionLineSize {
				return false, false, errors.New("session event exceeds maximum size")
			}
		} else {
			pending = nil
		}

		for index := len(parts) - 1; index >= 0; index-- {
			if len(parts[index]) > maximumSessionLineSize {
				return false, false, errors.New("session event exceeds maximum size")
			}
			stop, err := visit(parts[index])
			if err != nil {
				return false, false, err
			}
			if stop {
				return true, start == 0, nil
			}
		}
		cursor = start
		scanned += blockSize
	}
	return false, cursor == 0, nil
}

func pathWithin(root, path string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return false
	}
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(path))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func newSessionScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maximumSessionLineSize)
	return scanner
}

func normalizeOperation(name string) string {
	if !safeLabel(name) {
		return "other"
	}
	return name
}
