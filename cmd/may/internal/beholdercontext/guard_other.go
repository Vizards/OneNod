//go:build !darwin && !linux

package beholdercontext

import "os/exec"

func configureWorkerGroup(command *exec.Cmd) {}

func killWorkerGroup(command *exec.Cmd) {
	_ = command.Process.Kill()
}
