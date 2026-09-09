package beholdercontext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maximumHookAncestryDepth = 16

type hookProcessIdentity struct {
	PID               int
	ParentPID         int
	StartSeconds      uint64
	StartMicroseconds uint64
	UID               uint32
	RealUID           uint32
	Path              string
}

type processEvidence struct {
	Observed              bool     `json:"observed"`
	SelfRef               string   `json:"self_ref,omitempty"`
	ParentRef             string   `json:"parent_ref,omitempty"`
	AncestryDepth         int      `json:"ancestry_depth"`
	AncestryRefs          []string `json:"ancestry_refs"`
	AncestryRoles         []string `json:"ancestry_roles"`
	SelfOwnerClass        string   `json:"self_owner_class"`
	SelfUserWritable      bool     `json:"self_user_writable"`
	PIDStartObserved      bool     `json:"pid_start_observed"`
	RawPIDsStored         bool     `json:"raw_pids_stored"`
	ExecutablePathsStored bool     `json:"executable_paths_stored"`
}

func captureHookProcessEvidence(pid int) (processEvidence, error) {
	evidence := processEvidence{
		AncestryRefs:          []string{},
		AncestryRoles:         []string{},
		SelfOwnerClass:        "unknown",
		RawPIDsStored:         false,
		ExecutablePathsStored: false,
	}
	if pid <= 1 {
		return evidence, fmt.Errorf("invalid process")
	}
	currentPID := pid
	var identities []hookProcessIdentity
	for depth := 0; depth < maximumHookAncestryDepth; depth++ {
		identity, err := inspectHookProcess(currentPID)
		if err != nil {
			if depth == 0 {
				return evidence, err
			}
			break
		}
		identities = append(identities, identity)
		evidence.AncestryRefs = append(evidence.AncestryRefs, hookProcessRef(identity))
		evidence.AncestryRoles = append(evidence.AncestryRoles, hookProcessRole(identity.Path))
		if identity.PID == 1 || identity.ParentPID <= 0 || identity.ParentPID == identity.PID {
			break
		}
		currentPID = identity.ParentPID
	}
	if len(identities) == 0 {
		return evidence, fmt.Errorf("process unavailable")
	}
	evidence.Observed = true
	evidence.PIDStartObserved = true
	evidence.AncestryDepth = len(identities)
	evidence.SelfRef = evidence.AncestryRefs[0]
	if len(evidence.AncestryRefs) > 1 {
		evidence.ParentRef = evidence.AncestryRefs[1]
	}
	evidence.SelfOwnerClass, evidence.SelfUserWritable = executableOwnership(identities[0].Path)
	return evidence, nil
}

func hookProcessRef(identity hookProcessIdentity) string {
	return hashRef("process", fmt.Sprintf(
		"%d:%d:%d", identity.PID, identity.StartSeconds, identity.StartMicroseconds,
	))
}

func hookProcessRole(path string) string {
	switch strings.ToLower(filepath.Base(path)) {
	case "beholder-e1-pretool-hook", "beholder-e1-pretool-hook.test":
		return "managed-hook"
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
	userWritable := info.Mode().Perm()&0o002 != 0
	if stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0o200 != 0 {
		userWritable = true
	}
	if stat.Gid == uint32(os.Getegid()) && info.Mode().Perm()&0o020 != 0 {
		userWritable = true
	}
	return ownerClass, userWritable
}
