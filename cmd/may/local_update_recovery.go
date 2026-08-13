package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var (
	currentLocalUpdateExecutable = currentExecutablePath
	execLocalUpdateProcess       = syscall.Exec
)

type resolvedLocalUpdateActor struct {
	info os.FileInfo
	path string
}

// The helper rejects status from the wrong exact actor, so actor selection
// must precede transport reconciliation.
func bootstrapLocalUpdateRecovery(
	channel, version string,
	running *resolvedLocalUpdateActor,
) (bool, error) {
	journal, found, err := readTransportUpdateJournal()
	if err != nil || !found {
		return false, err
	}
	if channel != "" || version != journal.NewRelease {
		return false, errors.New("an interrupted local transport transaction must be recovered with its exact --version before another update")
	}
	actor, err := installedLocalUpdateActor(journal.Origin, journal.NewRelease, "")
	if err != nil {
		return false, err
	}
	selected, err := resolveLocalUpdateActor(actor)
	if err != nil {
		return false, err
	}
	if os.SameFile(running.info, selected.info) {
		return false, nil
	}
	environment, err := localUpdateProcessEnvironment()
	if err != nil {
		return false, err
	}
	arguments := []string{selected.path, "update", "--version", version}
	if err := execLocalUpdateProcess(selected.path, arguments, environment); err != nil {
		return true, errors.New("required exact OneNod actor could not resume local update recovery")
	}
	return true, nil
}

func snapshotCurrentLocalUpdateActor() (*resolvedLocalUpdateActor, error) {
	path, err := currentLocalUpdateExecutable()
	if err != nil {
		return nil, errors.New("resolve running local update actor failed")
	}
	return resolveLocalUpdateActor(path)
}

func resolveLocalUpdateActor(path string) (*resolvedLocalUpdateActor, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, errors.New("resolve exact local update actor failed")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return nil, errors.New("exact local update actor is unsafe")
	}
	return &resolvedLocalUpdateActor{info: info, path: filepath.Clean(resolved)}, nil
}

func reexecuteLocalUpdateAfterRecovery(
	previous *resolvedLocalUpdateActor,
	version string,
	deps dependencies,
) (bool, error) {
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		return false, err
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil || !found {
		return false, errors.New("local update recovery did not restore a verified current receipt")
	}
	path, err := verifiedInstalledMayActor(receipt.ReleaseVersion, receipt.Files["bin/may"])
	if err != nil || stableMayMatchesRelease(receipt.ReleaseVersion) != nil {
		return false, errors.New("local update recovery did not restore the receipt-bound stable actor")
	}
	actor, err := resolveLocalUpdateActor(path)
	if err != nil {
		return false, err
	}
	if os.SameFile(previous.info, actor.info) {
		return false, nil
	}
	arguments := []string{actor.path, "update"}
	if version != "" {
		arguments = append(arguments, "--version", version)
	}
	environment, err := localUpdateProcessEnvironment()
	if err != nil {
		return false, err
	}
	if err := execLocalUpdateProcess(actor.path, arguments, environment); err != nil {
		return true, errors.New("restored current OneNod release could not continue the local update")
	}
	return true, nil
}
