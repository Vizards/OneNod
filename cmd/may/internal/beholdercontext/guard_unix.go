//go:build darwin || linux

package beholdercontext

import (
	"os/exec"
	"syscall"
)

func configureWorkerGroup(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killWorkerGroup(command *exec.Cmd) {
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	_ = command.Process.Kill()
}
