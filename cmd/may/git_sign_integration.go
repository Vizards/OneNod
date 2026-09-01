package main

import (
	"errors"
	"os"
	"os/exec"
)

const gitSignAdapterBinaryName = "may-ssh-sign"

// runGitSignAdapter mirrors 1Password's op-ssh-sign shape: Git still invokes
// the system ssh-keygen implementation, while signatures are obtained through
// may's fixed SSH_AUTH_SOCK.
func runGitSignAdapter(args []string, deps dependencies) error {
	socketPath := gitSignAgentSocket(deps)
	if socketPath == "" {
		return errors.New("resolve may SSH agent socket failed")
	}
	command := exec.Command("/usr/bin/ssh-keygen", args...)
	command.Env = withEnvironmentValue(os.Environ(), "SSH_AUTH_SOCK", socketPath)
	command.Stdin = deps.stdin
	command.Stdout = deps.stdout
	command.Stderr = deps.stderr
	if err := command.Run(); err != nil {
		return errors.New("system ssh-keygen command failed; inspect ~/.onenod/logs/ssh-agent.error.log for the OneNod request stage, request ID, and safe cause")
	}
	return nil
}

func gitSignAgentSocket(deps dependencies) string {
	if lease, err := requestBeholderSSHLease(deps, beholderLeasePurposeGit); err == nil {
		return lease.AgentSocket
	}
	return defaultAgentSocket()
}

func withEnvironmentValue(environment []string, name, value string) []string {
	prefix := name + "="
	result := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if len(entry) >= len(prefix) && entry[:len(prefix)] == prefix {
			continue
		}
		result = append(result, entry)
	}
	return append(result, prefix+value)
}
