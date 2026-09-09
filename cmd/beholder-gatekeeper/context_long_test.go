package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHundredMegabyteSessionProducesBoundedAuditableSource(t *testing.T) {
	const taskID = "11111111-1111-4111-8111-111111111111"
	path := filepath.Join(t.TempDir(), "rollout-2026-09-04T00-00-00-"+taskID+".jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := bufio.NewWriterSize(file, 1024*1024)
	filler := []byte(`{"type":"event_msg","payload":{"padding":"` + strings.Repeat("x", 3600) + `"}}` + "\n")
	for index := 0; index < 30000; index++ {
		if _, err := writer.Write(filler); err != nil {
			t.Fatal(err)
		}
	}
	unsafeOutput, err := json.Marshal(map[string]any{
		"type":    "response_item",
		"payload": toolOutputFixture("unselected-call", `{"output":"api_key=abcdefghijklmnopqrstuvwxyz123456"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	boundary, err := json.Marshal(map[string]any{
		"type":    "response_item",
		"payload": messageFixture("user", "", "Current human request: read the match fixture."),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range [][]byte{unsafeOutput, boundary} {
		if _, err := writer.Write(line); err != nil || writer.WriteByte('\n') != nil {
			t.Fatal("write session tail failed")
		}
	}
	if writer.Flush() != nil || file.Close() != nil {
		t.Fatal("close long session fixture failed")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() < 100*1024*1024 {
		t.Fatalf("long fixture size = %d, want at least 100 MiB", info.Size())
	}

	request := liveRequestFixture(path)
	input, _, source, err := buildExternalDecisionInputWithEvidence(request, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clearExternalInput(&input)
	if source.TranscriptSnapshot.TaskID != taskID ||
		source.TranscriptSnapshot.ObservedCandidates != 30002 ||
		source.TranscriptSnapshot.RetainedCandidates > maximumEvidenceCandidates ||
		source.TranscriptSnapshot.ScannedBytes != info.Size() ||
		!validSHA256(source.TranscriptSnapshot.ScannedContentSHA256) {
		t.Fatalf("long-session snapshot was incomplete: %+v", source.TranscriptSnapshot)
	}
	if len(source.Candidates) > maximumEvidenceCandidates || len(source.CandidateSummary) == 0 {
		t.Fatalf("context inventory was not bounded: candidates=%d summary=%d", len(source.Candidates), len(source.CandidateSummary))
	}
	encoded, _, err := marshalEvidenceJSON(evidenceSourceName, source)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	if len(encoded) > 2*1024*1024 || bytes.Contains(encoded, []byte("abcdefghijklmnopqrstuvwxyz123456")) ||
		!bytes.Contains(encoded, []byte(`"codex_task_id": "`+taskID+`"`)) {
		t.Fatalf("bounded evidence invalid: bytes=%d", len(encoded))
	}
}
