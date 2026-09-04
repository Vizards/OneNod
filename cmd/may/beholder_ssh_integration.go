package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const systemSSHPath = "/usr/bin/ssh"

type processExecFunc func(path string, argv []string, environment []string) error
type processRunFunc func(
	path string,
	argv []string,
	environment []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	started func(int),
) error

func defaultProcessExec(path string, argv []string, environment []string) error {
	return syscall.Exec(path, argv, environment)
}

func defaultProcessRun(
	path string,
	argv []string,
	environment []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	started func(int),
) error {
	if len(argv) == 0 {
		return errors.New("process arguments are missing")
	}
	command := exec.Command(path, argv[1:]...)
	command.Args[0] = argv[0]
	command.Env = environment
	command.Stdin = readerOrDefault(stdin, os.Stdin)
	command.Stdout = writerOrDefault(stdout, os.Stdout)
	command.Stderr = writerOrDefault(stderr, os.Stderr)
	if err := command.Start(); err != nil {
		return errors.New("start system ssh failed")
	}
	if started != nil {
		started(command.Process.Pid)
	}
	err := command.Wait()
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if exitError.ExitCode() >= 0 {
			return shellPluginProcessExitError{code: exitError.ExitCode()}
		}
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return shellPluginProcessExitError{code: 128 + int(status.Signal())}
		}
	}
	return errors.New("wait for system ssh failed")
}

// runBeholderSSHShim preserves the ordinary ssh command surface. A recent
// Codex hook event may supply a one-use binding to a proxy hosted by this
// transparent OneNod process. Keeping the upstream Agent connection here (and
// out of the root Core daemon) preserves the real Codex application ancestry.
func runBeholderSSHShim(args []string, deps dependencies) error {
	execProcess := deps.processExec
	if execProcess == nil {
		execProcess = defaultProcessExec
	}
	lease, leaseErr := requestBeholderSSHLease(deps, beholderLeasePurposeSSH)
	if leaseErr != nil {
		return execOrdinarySSH(args, execProcess)
	}
	defer lease.clear()
	proxy, proxyErr := startBeholderClientProxy(lease.Nonce)
	if proxyErr != nil {
		return execOrdinarySSH(args, execProcess)
	}
	defer proxy.close()
	arguments := make([]string, 0, len(args)+3)
	arguments = append(arguments, systemSSHPath, "-o", "IdentityAgent="+quoteOpenSSHConfigValue(proxy.socketPath))
	arguments = append(arguments, args...)
	runProcess := deps.processRun
	if runProcess == nil {
		runProcess = defaultProcessRun
	}
	if err := runProcess(
		systemSSHPath, arguments, os.Environ(), deps.stdin, deps.stdout, deps.stderr,
		proxy.expectPeer,
	); err != nil {
		var targetExit shellPluginProcessExitError
		if errors.As(err, &targetExit) {
			return targetExit
		}
		return errors.New("execute system ssh failed")
	}
	return nil
}

func execOrdinarySSH(args []string, execProcess processExecFunc) error {
	arguments := append([]string{systemSSHPath}, args...)
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
