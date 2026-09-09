package beholdercontext

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

const GuardName = "beholder-e1-context"
const WorkerName = "beholder-e1-pretool-hook"
const workerDeadline = 3 * time.Second

// RunGuard isolates observation failures from Codex's reserved blocking status
// and JSON. The managed shell command must also normalize status/output, covering
// failures before this function can run (including loader errors and panics).
func RunGuard(args []string, stdin, stdout *os.File) {
	if len(args) == 1 && args[0] == "--identity" {
		fmt.Fprintln(stdout, `{"component":"beholder-context-guard","schema_version":1,"worker":"beholder-e1-pretool-hook","deadline_ms":3000}`)
		return
	}
	defer fmt.Fprintln(stdout, "{}")
	self, err := os.Executable()
	if err != nil {
		return
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return
	}
	// The worker is a fixed sibling, never an environment or argv-selected path.
	worker := filepath.Join(filepath.Dir(self), WorkerName)
	sink, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer sink.Close()
	command := exec.Command(worker, args...)
	command.Stdin, command.Stdout, command.Stderr = stdin, sink, sink
	configureWorkerGroup(command)
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	if command.Start() != nil {
		return
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	deadline := time.NewTimer(workerDeadline)
	defer deadline.Stop()
	select {
	case <-done:
		return
	case <-deadline.C:
	case <-interrupt:
	}
	killWorkerGroup(command)
	// Do not wait without a bound even after SIGKILL. stdout/stderr are files,
	// so descendants cannot hold a pipe open and extend the Hook lifetime.
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
	}
}
