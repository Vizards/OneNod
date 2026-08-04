package main

import (
	"io"
	"strings"
	"testing"
)

func TestGitSignAdapterFailurePointsToSafeAgentDiagnostics(t *testing.T) {
	err := runGitSignAdapter(
		[]string{"-Y"},
		dependencies{
			stdin:  strings.NewReader(""),
			stdout: io.Discard,
			stderr: io.Discard,
		},
	)
	if err == nil || !strings.Contains(err.Error(), "~/.onenod/logs/ssh-agent.error.log") {
		t.Fatalf("adapter failure omitted the safe Agent diagnostic path: %v", err)
	}
}
