package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maximumAncestryDepth = 20

type processIdentity struct {
	PID               int
	ParentPID         int
	StartSeconds      uint64
	StartMicroseconds uint64
	UID               uint32
	RealUID           uint32
	Path              string
	CWD               string
}

type processChain struct {
	Nodes []processIdentity
	Roles []string
}

func captureProcessChain(pid int) (processChain, error) {
	if pid <= 1 {
		return processChain{}, fmt.Errorf("invalid process")
	}
	var chain processChain
	currentPID := pid
	for depth := 0; depth < maximumAncestryDepth; depth++ {
		identity, err := inspectProcess(currentPID)
		if err != nil {
			if depth == 0 {
				return processChain{}, err
			}
			break
		}
		chain.Nodes = append(chain.Nodes, identity)
		chain.Roles = append(chain.Roles, processRole(identity.Path))
		if identity.PID == 1 || identity.ParentPID <= 0 || identity.ParentPID == identity.PID {
			break
		}
		currentPID = identity.ParentPID
	}
	if len(chain.Nodes) == 0 {
		return processChain{}, fmt.Errorf("empty process chain")
	}
	return chain, nil
}

func processRole(path string) string {
	switch strings.ToLower(filepath.Base(path)) {
	case "e1-beholder-core", "e1-beholder-core.test":
		return "beholder-core-client"
	case "beholder-e1-pretool-hook", "beholder-e1-context":
		return "managed-hook"
	case "may":
		return "onenod-requester"
	case "may-ssh-sign":
		return "onenod-sign-adapter"
	case "ssh", "ssh-add", "ssh-keygen":
		return "ssh-client"
	case "git":
		return "git-client"
	case "zsh", "bash", "sh":
		return "shell"
	case "codex":
		return "codex-runtime"
	case "chatgpt":
		return "codex-desktop-host"
	case "launchd":
		return "launchd"
	case "go":
		return "go-tool"
	default:
		if path == "" {
			return "unknown"
		}
		return "other"
	}
}

func rawProcessRef(identity processIdentity) string {
	return fmt.Sprintf("%d:%d:%d", identity.PID, identity.StartSeconds, identity.StartMicroseconds)
}

func firstRoleIndex(chain processChain, role string) int {
	for index, candidate := range chain.Roles {
		if candidate == role {
			return index
		}
	}
	return -1
}

func executableOwnership(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "unknown", false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "unknown", false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown", false
	}
	ownerClass := "other"
	switch stat.Uid {
	case 0:
		ownerClass = "root"
	case uint32(os.Geteuid()):
		ownerClass = "current-user"
	}
	// This asks whether an ordinary user can replace the executable, not
	// whether the current (possibly root LaunchDaemon) process can write it.
	userWritable := info.Mode().Perm()&0o022 != 0 ||
		(stat.Uid != 0 && info.Mode().Perm()&0o200 != 0)
	return ownerClass, userWritable
}

func cwdRelation(parent, child string) string {
	if !filepath.IsAbs(parent) || !filepath.IsAbs(child) {
		return "unknown"
	}
	parentClean := filepath.Clean(parent)
	childClean := filepath.Clean(child)
	if parentClean == childClean {
		return "exact"
	}
	relative, err := filepath.Rel(parentClean, childClean)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "descendant"
	}
	return "different"
}
