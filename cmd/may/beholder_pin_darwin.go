package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// This is a diagnostic only. It never changes a root-owned Core configuration
// or treats the user-owned receipt as authority to change that configuration.
func beholderCorePinWarning(receipt *localInstallReceipt) string {
	if receipt == nil {
		return ""
	}
	const plist = "/Library/LaunchDaemons/com.vizards.beholder.e1-core.plist"
	info, err := os.Lstat(plist)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return "Beholder Core configuration cannot be safely inspected"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Size() <= 0 || info.Size() > 128*1024 {
		return "Beholder Core configuration cannot be safely inspected"
	}
	output, err := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", plist).Output()
	var document struct {
		ProgramArguments []string `json:"ProgramArguments"`
	}
	if err != nil || len(output) > 128*1024 || json.Unmarshal(output, &document) != nil {
		return "Beholder Core configuration cannot be safely inspected"
	}
	values := map[string]string{}
	for index := 0; index+1 < len(document.ProgramArguments); index++ {
		name := document.ProgramArguments[index]
		if name == "--upstream-agent" || name == "--trusted-agent" || name == "--trusted-agent-sha256" {
			if _, duplicate := values[name]; duplicate {
				return "Beholder Core configuration contains ambiguous Agent identity flags"
			}
			values[name] = document.ProgramArguments[index+1]
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || values["--upstream-agent"] != filepath.Join(home, userAgentDirectoryName, "agent.sock") {
		return ""
	}
	expectedPath := filepath.Join(home, userAgentDirectoryName, "versions", receipt.ReleaseVersion, "may")
	expectedDigest := strings.TrimPrefix(receipt.Files["bin/may"], "sha256:")
	if values["--trusted-agent"] != expectedPath || values["--trusted-agent-sha256"] != expectedDigest {
		return "Beholder Core trusts a different Agent release; complete the attended local Core installation before relying on automatic approvals"
	}
	return ""
}
