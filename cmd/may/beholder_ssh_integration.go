package main

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

const systemSSHPath = "/usr/bin/ssh"

type processExecFunc func(path string, argv []string, environment []string) error

func defaultProcessExec(path string, argv []string, environment []string) error {
	return syscall.Exec(path, argv, environment)
}

// runBeholderSSHShim preserves the ordinary ssh command surface. A recent
// Codex hook event may supply a one-use Agent proxy; otherwise the system ssh
// command runs unchanged and OneNod's fixed IdentityAgent remains responsible
// for the normal human-approval path.
func runBeholderSSHShim(args []string, deps dependencies) error {
	execProcess := deps.processExec
	if execProcess == nil {
		execProcess = defaultProcessExec
	}
	arguments := make([]string, 0, len(args)+3)
	arguments = append(arguments, systemSSHPath)
	if lease, err := requestBeholderSSHLease(deps, beholderLeasePurposeSSH); err == nil {
		arguments = append(arguments, "-o", "IdentityAgent="+quoteOpenSSHConfigValue(lease.AgentSocket))
	}
	arguments = append(arguments, args...)
	if err := execProcess(systemSSHPath, arguments, os.Environ()); err != nil {
		return errors.New("execute system ssh failed")
	}
	return nil
}

// OpenSSH parses each -o value with its configuration lexer after argv has
// already been split. Preserve spaces in the fixed Beholder installation path
// and escape the two characters that remain special inside a quoted value.
func quoteOpenSSHConfigValue(value string) string {
	escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	return `"` + escaped + `"`
}
