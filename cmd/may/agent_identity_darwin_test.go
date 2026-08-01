//go:build darwin

package main

import "testing"

func TestKnownAgentLabelRecognizesPaseoAndSpecificAgents(t *testing.T) {
	t.Parallel()
	tests := []struct {
		command string
		label   string
	}{
		{command: "Paseo Daemon", label: "Paseo"},
		{command: "/Applications/Paseo.app/Contents/MacOS/Paseo", label: "Paseo"},
		{command: "/opt/homebrew/bin/codex app-server", label: "Codex"},
		{command: "claude --print", label: "Claude Code"},
	}
	for _, test := range tests {
		if actual := knownAgentLabel(test.command); actual != test.label {
			t.Fatalf("knownAgentLabel(%q) = %q, want %q", test.command, actual, test.label)
		}
	}
}

func TestParseMacOSApplicationLabelNormalizesPaseoHelpers(t *testing.T) {
	t.Parallel()
	output := `"CFBundleIdentifier"="sh.paseo.desktop.helper"
"LSDisplayName"="Paseo Daemon"
`
	if actual := parseMacOSApplicationLabel(output); actual != "Paseo" {
		t.Fatalf("parseMacOSApplicationLabel() = %q, want Paseo", actual)
	}
}

func TestParseMacOSApplicationLabelUsesLaunchServicesName(t *testing.T) {
	t.Parallel()
	output := `"CFBundleIdentifier"="com.apple.Terminal"
"LSDisplayName"="Terminal"
`
	if actual := parseMacOSApplicationLabel(output); actual != "Terminal" {
		t.Fatalf("parseMacOSApplicationLabel() = %q, want Terminal", actual)
	}
}

func TestProcessScopeBindsExactProcessLifetime(t *testing.T) {
	t.Parallel()
	process := localProcessIdentity{
		pid:          412,
		startSeconds: 1_722_000_000,
		startMicros:  125,
		terminal:     9,
	}
	kind, first := processScope("terminal-session", process)
	if kind != "terminal-session" || first == "" {
		t.Fatalf("unexpected process scope: %q %q", kind, first)
	}
	_, repeated := processScope("terminal-session", process)
	if repeated != first {
		t.Fatal("the same process lifetime produced a different scope")
	}
	process.startMicros++
	_, restarted := processScope("terminal-session", process)
	if restarted == first {
		t.Fatal("a reused PID with a new start time retained the old scope")
	}
}

func TestAuthorizationScopeFailsClosedWithoutObservedProcess(t *testing.T) {
	t.Parallel()
	kind, identifier := authorizationScope(nil, unknownLocalClient())
	if kind != "" || identifier != "" {
		t.Fatalf("unavailable process identity produced scope %q %q", kind, identifier)
	}
}
