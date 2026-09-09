package main

import (
	"os"
	"testing"
	"time"
)

func TestProfileLiveTranscriptContextCollection(t *testing.T) {
	path := os.Getenv("BEHOLDER_PROFILE_TRANSCRIPT")
	prompt := os.Getenv("BEHOLDER_PROFILE_PROMPT")
	if path == "" || prompt == "" {
		t.Skip("live transcript profile is opt-in")
	}
	started := time.Now()
	context, err := readRelatedContext(path, prompt)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"elapsed=%s bytes=%d events=%d candidates=%d humans=%d prior_agent=%d current_agent=%d tools=%d",
		time.Since(started), context.transcriptSnapshot.ScannedBytes,
		context.transcriptSnapshot.ScannedEvents, context.transcriptSnapshot.ObservedCandidates,
		len(context.priorHumans), len(context.priorAgentMessages), len(context.currentAgentMessages),
		len(context.completedTools),
	)
}
