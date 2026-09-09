package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func collectWorkspaceEvidence(cwd string, ref func(string, []byte) string) workspaceEvidence {
	evidence := workspaceEvidence{
		RepositoryKind: "none",
		HeadState:      "unknown",
		RawPathsStored: false,
	}
	if !filepath.IsAbs(cwd) {
		return evidence
	}
	evidence.CWDUserWritable = directoryUserWritable(cwd)
	repositoryRoot, gitPath, kind := findRepository(cwd)
	if repositoryRoot == "" {
		return evidence
	}
	evidence.RepositoryObserved = true
	evidence.RepositoryKind = kind
	evidence.RepositoryRef = ref("repository", []byte(repositoryRoot))
	headPath := filepath.Join(gitPath, "HEAD")
	encoded, err := os.ReadFile(headPath)
	if err != nil || len(encoded) == 0 || len(encoded) > 4096 {
		return evidence
	}
	encoded = bytes.TrimSpace(encoded)
	if bytes.HasPrefix(encoded, []byte("ref: ")) {
		head := strings.TrimSpace(string(bytes.TrimPrefix(encoded, []byte("ref: "))))
		if safeGitRef(head) {
			evidence.HeadState = "symbolic"
			evidence.HeadRef = ref("git-head", []byte(head))
		}
		return evidence
	}
	if safeHexObject(string(encoded)) {
		evidence.HeadState = "detached"
		evidence.HeadRef = ref("git-head", encoded)
	}
	return evidence
}

func findRepository(cwd string) (string, string, string) {
	current := filepath.Clean(cwd)
	for {
		gitEntry := filepath.Join(current, ".git")
		info, err := os.Lstat(gitEntry)
		if err == nil && info.IsDir() {
			return current, gitEntry, "standard"
		}
		if err == nil && info.Mode().IsRegular() {
			encoded, readErr := os.ReadFile(gitEntry)
			if readErr == nil && len(encoded) <= 4096 && bytes.HasPrefix(encoded, []byte("gitdir: ")) {
				gitDir := strings.TrimSpace(string(bytes.TrimPrefix(encoded, []byte("gitdir: "))))
				if !filepath.IsAbs(gitDir) {
					gitDir = filepath.Join(current, gitDir)
				}
				gitDir = filepath.Clean(gitDir)
				if stat, statErr := os.Stat(gitDir); statErr == nil && stat.IsDir() {
					return current, gitDir, "worktree"
				}
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", "", ""
		}
		current = parent
	}
}

func directoryUserWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	mode := info.Mode().Perm()
	return mode&0o002 != 0 ||
		(stat.Uid == uint32(os.Geteuid()) && mode&0o200 != 0) ||
		(stat.Gid == uint32(os.Getegid()) && mode&0o020 != 0)
}

func safeGitRef(value string) bool {
	if value == "" || len(value) > 1024 || strings.Contains(value, "..") {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character == 0x7f || strings.ContainsRune("~^:?*[\\", character) {
			return false
		}
	}
	return true
}

func safeHexObject(value string) bool {
	if len(value) < 40 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
