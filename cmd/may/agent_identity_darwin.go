//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumProcessAncestryDepth = 16

func detectLocalClientContext(connection net.Conn) localClientContext {
	pid, err := unixPeerPID(connection)
	if err != nil {
		return unknownLocalClientContext()
	}
	return detectLocalClientContextFromPID(pid)
}

func detectLocalClientFromPID(pid int) clientObservation {
	return detectLocalClientContextFromPID(pid).Observation
}

type localProcessIdentity struct {
	command      string
	parentPID    int
	pid          int
	startSeconds int64
	startMicros  int64
	terminal     int32
}

func detectLocalClientContextFromPID(pid int) localClientContext {
	var application string
	paseo := false
	ancestry := make([]localProcessIdentity, 0, maximumProcessAncestryDepth)
	for depth := 0; depth < maximumProcessAncestryDepth && pid > 1; depth++ {
		process, err := processIdentity(pid)
		if err != nil {
			break
		}
		ancestry = append(ancestry, process)
		if label := knownAgentLabel(process.command); label != "" {
			if label == "Paseo" {
				paseo = true
			} else if application == "" {
				application = label
			}
		}
		if process.parentPID <= 1 || process.parentPID == pid {
			break
		}
		pid = process.parentPID
	}
	observation := unknownLocalClient()
	if application != "" {
		if paseo {
			application += " via Paseo"
		}
		observation = observedLocalClient(application)
	} else if paseo {
		observation = observedLocalClient("Paseo")
	} else {
		for _, candidate := range ancestry {
			if label := macOSApplicationLabel(candidate.pid); label != "" {
				observation = observedLocalClient(label)
				break
			}
		}
	}
	scopeKind, scopeID := authorizationScope(ancestry, observation)
	return localClientContext{
		Observation: observation,
		ScopeID:     scopeID,
		ScopeKind:   scopeKind,
	}
}

func unixPeerPID(connection net.Conn) (int, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, errors.New("SSH agent client is not a Unix connection")
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var socketErr error
	if err := raw.Control(func(descriptor uintptr) {
		pid, socketErr = unix.GetsockoptInt(
			int(descriptor),
			unix.SOL_LOCAL,
			unix.LOCAL_PEERPID,
		)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil || pid <= 0 {
		return 0, errors.New("read SSH agent peer process failed")
	}
	return pid, nil
}

func processIdentity(pid int) (localProcessIdentity, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || int(info.Proc.P_pid) != pid {
		return localProcessIdentity{}, errors.New("process identity was unavailable")
	}
	output, err := exec.Command(
		"/bin/ps",
		"-o", "comm=",
		"-p", strconv.Itoa(pid),
	).Output()
	if err != nil {
		return localProcessIdentity{}, err
	}
	command := strings.TrimSpace(string(output))
	if command == "" {
		return localProcessIdentity{}, errors.New("process identity was incomplete")
	}
	return localProcessIdentity{
		command:      command,
		parentPID:    int(info.Eproc.Ppid),
		pid:          pid,
		startSeconds: info.Proc.P_starttime.Sec,
		startMicros:  int64(info.Proc.P_starttime.Usec),
		terminal:     info.Eproc.Tdev,
	}, nil
}

func knownAgentLabel(command string) string {
	value := strings.ToLower(command)
	switch {
	case strings.Contains(value, "claude"):
		return "Claude Code"
	case strings.Contains(value, "codex"):
		return "Codex"
	case strings.Contains(value, "cursor"):
		return "Cursor"
	case strings.Contains(value, "windsurf"):
		return "Windsurf"
	case strings.Contains(value, "paseo"):
		return "Paseo"
	default:
		return ""
	}
}

func macOSApplicationLabel(pid int) string {
	output, err := exec.Command(
		"/usr/bin/lsappinfo",
		"info",
		"-only", "bundleID,name",
		"-app", strconv.Itoa(pid),
	).Output()
	if err != nil {
		return ""
	}
	return parseMacOSApplicationLabel(string(output))
}

func parseMacOSApplicationLabel(output string) string {
	bundleID := quotedApplicationInfoValue(output, "CFBundleIdentifier")
	name := quotedApplicationInfoValue(output, "LSDisplayName")
	if strings.HasPrefix(strings.ToLower(bundleID), "sh.paseo.desktop") {
		return "Paseo"
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\x00\r\n\t") {
		return ""
	}
	return name
}

func quotedApplicationInfoValue(output string, key string) string {
	prefix := `"` + key + `"=`
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimPrefix(line, prefix)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			return value[1 : len(value)-1]
		}
	}
	return ""
}

func observedLocalClient(application string) clientObservation {
	return clientObservation{
		Application: application,
		Source:      "process-ancestry",
	}
}

func authorizationScope(
	ancestry []localProcessIdentity,
	observation clientObservation,
) (string, string) {
	if observation.Source == "unavailable" || len(ancestry) == 0 {
		return "", ""
	}
	for _, process := range ancestry {
		command := strings.ToLower(process.command)
		if strings.Contains(command, "terminal-worker-process") ||
			strings.Contains(command, "codex-code-mode-host") {
			return processScope("terminal-session", process)
		}
	}
	terminal := ancestry[0].terminal
	if terminal != 0 && terminal != -1 {
		anchor := ancestry[0]
		for _, process := range ancestry {
			if process.terminal != terminal {
				break
			}
			anchor = process
		}
		return processScope("terminal-session", anchor)
	}
	for _, process := range ancestry {
		label := knownAgentLabel(process.command)
		if label != "" && label != "Paseo" {
			return processScope("application", process)
		}
	}
	return processScope("application", ancestry[len(ancestry)-1])
}

func processScope(kind string, process localProcessIdentity) (string, string) {
	if process.pid <= 1 || process.startSeconds <= 0 {
		return "", ""
	}
	material := fmt.Sprintf(
		"onenod-local-session-v1\n%s\n%d\n%d\n%d\n%d",
		kind,
		process.pid,
		process.startSeconds,
		process.startMicros,
		process.terminal,
	)
	digest := sha256.Sum256([]byte(material))
	return kind, base64.RawURLEncoding.EncodeToString(digest[:])
}

func unknownLocalClient() clientObservation {
	return clientObservation{
		Application: "Unknown local client",
		Source:      "unavailable",
	}
}

func unknownLocalClientContext() localClientContext {
	return localClientContext{Observation: unknownLocalClient()}
}
