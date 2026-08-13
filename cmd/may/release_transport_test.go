package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTransportUpdateJournalRejectsCapabilitiesAndUnsafeTargets(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	journal := transportUpdateJournal{
		NewHelperVersion: "2.0.0", OldHelperVersion: "2.0.0",
		NewRelease: "0.0.2-alpha.21",
		NewTargets: managedReleaseTargets("0.0.2-alpha.21", "0.0.2-alpha.21"),
		OldRelease: "0.0.2-alpha.20",
		OldTargets: managedReleaseTargets("0.0.2-alpha.20", "0.0.2-alpha.20"),
		Origin:     "https://example.workers.dev", Phase: "staged",
		SchemaVersion: transportJournalSchema, Slot: "default",
		TransactionID: strings.Repeat("A", 32),
	}
	if err := writeTransportUpdateJournal(journal); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := readTransportUpdateJournal()
	if err != nil || !found || loaded.TransactionID != journal.TransactionID {
		t.Fatalf("journal round trip failed: %+v found=%v err=%v", loaded, found, err)
	}
	encoded, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), userAgentDirectoryName, "transport-update.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("capability")) {
		t.Fatal("transport journal persisted a commit capability")
	}
	journal.NewTargets["may"] = "/tmp/attacker"
	if err := writeTransportUpdateJournal(journal); err == nil {
		t.Fatal("absolute transport target was accepted")
	}
}

func TestInterruptedTransportUpdateAlwaysRollsBackWithoutCommitCapability(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		filepath.Join(root, "bin"), filepath.Join(root, "versions", "0.0.2-alpha.20"),
		filepath.Join(root, "versions", "0.0.2-alpha.21"),
		filepath.Join(root, "skill-versions", "0.0.2-alpha.20", "onenod"),
		filepath.Join(root, "skill-versions", "0.0.2-alpha.21", "onenod"),
		filepath.Join(root, "receipt-versions"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"may", gitSignAdapterBinaryName} {
		if err := os.WriteFile(filepath.Join(root, "versions", "0.0.2-alpha.20", name), []byte("old"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "versions", "0.0.2-alpha.21", name), []byte("new"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	newTargets := managedReleaseTargets("0.0.2-alpha.21", "0.0.2-alpha.21")
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		if err := os.Symlink(newTargets[name], stable); err != nil {
			t.Fatal(err)
		}
	}
	oldReceipt := []byte(`{"schema_version":2,"release_version":"0.0.2-alpha.20"}`)
	if err := os.WriteFile(filepath.Join(root, "receipt-versions", "0.0.2-alpha.20.json"), oldReceipt, 0o600); err != nil {
		t.Fatal(err)
	}
	journal := transportUpdateJournal{
		NewHelperVersion: "2.0.0", OldHelperVersion: "2.0.0",
		NewRelease: "0.0.2-alpha.21", NewTargets: newTargets,
		OldRelease: "0.0.2-alpha.20",
		OldTargets: managedReleaseTargets("0.0.2-alpha.20", "0.0.2-alpha.20"),
		Origin:     "https://example.workers.dev", Phase: "promoting",
		SchemaVersion: transportJournalSchema, Slot: "default",
		TransactionID: strings.Repeat("B", 32),
	}
	if err := writeTransportUpdateJournal(journal); err != nil {
		t.Fatal(err)
	}
	oldQuery := queryTransportUpdateStatus
	oldAbort := runTransportUpdateAbort
	oldRestart := restartTransportAgent
	aborted := false
	restarted := false
	queryTransportUpdateStatus = func(origin, slot string) (transportHelperStatus, error) {
		return transportHelperStatus{
			Role: "staged", TransactionID: journal.TransactionID, TransactionState: "staged",
		}, nil
	}
	runTransportUpdateAbort = func(_ string, origin, slot, transactionID string) error {
		aborted = origin == journal.Origin && slot == journal.Slot && transactionID == journal.TransactionID
		return nil
	}
	restartTransportAgent = func(_ *userCLIInstallPlan) error { restarted = true; return nil }
	t.Cleanup(func() {
		queryTransportUpdateStatus = oldQuery
		runTransportUpdateAbort = oldAbort
		restartTransportAgent = oldRestart
	})
	if err := reconcileInterruptedTransportUpdate(dependencies{stdout: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if !aborted {
		t.Fatal("interrupted helper transaction was not aborted")
	}
	if !restarted {
		t.Fatal("prior may SSH Agent was not restarted after staged recovery")
	}
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		target, err := os.Readlink(stable)
		if err != nil || target != journal.OldTargets[name] {
			t.Fatalf("%s target = %q, %v", name, target, err)
		}
	}
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		t.Fatalf("reconciled journal remained: found=%v err=%v", found, err)
	}
	restoredReceipt, err := os.ReadFile(filepath.Join(root, "install.json"))
	if err != nil || !bytes.Equal(restoredReceipt, oldReceipt) {
		t.Fatalf("prior install receipt was not restored: %q, %v", restoredReceipt, err)
	}
}

func TestInterruptedCommittedTransportUpdateKeepsPromotedRelease(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	journal := transportUpdateJournal{
		HelperChanged:    true,
		NewHelperVersion: "3.0.0", OldHelperVersion: "2.0.0",
		NewRelease: "0.0.2-alpha.21",
		NewTargets: managedReleaseTargets("0.0.2-alpha.21", "0.0.2-alpha.21"),
		OldRelease: "0.0.2-alpha.20",
		OldTargets: managedReleaseTargets("0.0.2-alpha.20", "0.0.2-alpha.20"),
		Origin:     "https://example.workers.dev", Phase: "health_checked",
		SchemaVersion: transportJournalSchema, Slot: "default",
		TransactionID: strings.Repeat("K", 32),
	}
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		if err := os.Symlink(journal.NewTargets[name], stable); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeTransportUpdateJournal(journal); err != nil {
		t.Fatal(err)
	}

	oldQuery := queryTransportUpdateStatus
	oldAbort := runTransportUpdateAbort
	oldRestart := restartTransportAgent
	aborted := false
	restarted := false
	queryTransportUpdateStatus = func(origin, slot string) (transportHelperStatus, error) {
		if origin != journal.Origin || slot != journal.Slot {
			return transportHelperStatus{}, errors.New("unexpected recovery identity")
		}
		return transportHelperStatus{
			Role: "current", TransactionID: journal.TransactionID,
			TransactionState: "committed",
		}, nil
	}
	runTransportUpdateAbort = func(string, string, string, string) error {
		aborted = true
		return nil
	}
	restartTransportAgent = func(*userCLIInstallPlan) error {
		restarted = true
		return nil
	}
	t.Cleanup(func() {
		queryTransportUpdateStatus = oldQuery
		runTransportUpdateAbort = oldAbort
		restartTransportAgent = oldRestart
	})

	var output bytes.Buffer
	if err := reconcileInterruptedTransportUpdate(dependencies{stdout: &output}); err != nil {
		t.Fatal(err)
	}
	if aborted || restarted {
		t.Fatalf("committed recovery mutated the promoted runtime: aborted=%t restarted=%t", aborted, restarted)
	}
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		target, err := os.Readlink(stable)
		if err != nil || target != journal.NewTargets[name] {
			t.Fatalf("committed %s target = %q, %v", name, target, err)
		}
	}
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		t.Fatalf("committed recovery journal remained: found=%v err=%v", found, err)
	}
	if !strings.Contains(output.String(), "new local release remains active") {
		t.Fatalf("committed recovery outcome was not reported: %q", output.String())
	}
}

func TestFinalizeChildErrorUsesAuthenticatedCommittedState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.2", nil)}
	release.Manifest.Source.Commit = strings.Repeat("a", 40)
	transaction := &exactBuildUpdateTransaction{
		capability: make([]byte, 32), newMayPath: "/verified/new/may",
		journal: transportUpdateJournal{
			NewHelperVersion: "2.0.0", OldHelperVersion: "2.0.0",
			NewRelease: "0.0.2", NewTargets: managedReleaseTargets("0.0.2", "0.0.2"),
			OldRelease: "0.0.1", OldTargets: managedReleaseTargets("0.0.1", "0.0.1"),
			Origin: "https://example.workers.dev", Phase: "health_checked", Slot: "active",
			SchemaVersion: transportJournalSchema, TransactionID: strings.Repeat("C", 32),
		},
	}
	if err := writeTransportUpdateJournal(transaction.journal); err != nil {
		t.Fatal(err)
	}
	oldAgent := queryTransportAgentVersion
	oldFinalize := runTransportFinalizeChild
	oldStatus := queryFinalizedTransportStatus
	queryTransportAgentVersion = func(string) (agentRuntimeVersion, error) {
		return agentRuntimeVersion{
			ClientProtocol: release.Manifest.Components.May.ClientProtocol,
			SourceCommit:   release.Manifest.Source.Commit, Version: release.Manifest.ReleaseVersion,
		}, nil
	}
	runTransportFinalizeChild = func(string, string, string, string, bool, []byte) error {
		return errors.New("response pipe lost after commit")
	}
	queryFinalizedTransportStatus = func(string, string, string, string) (transportHelperStatus, error) {
		return transportHelperStatus{
			Role: "current", TransactionID: transaction.journal.TransactionID,
			TransactionState: "committed",
		}, nil
	}
	t.Cleanup(func() {
		queryTransportAgentVersion = oldAgent
		runTransportFinalizeChild = oldFinalize
		queryFinalizedTransportStatus = oldStatus
	})
	if err := transaction.finalize(&userCLIInstallPlan{socketPath: "/unused"}, release, dependencies{stderr: io.Discard}); err != nil {
		t.Fatal(err)
	}
	if !transaction.committed {
		t.Fatal("authenticated committed state was not retained")
	}
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		t.Fatalf("committed recovery journal remained: found=%v err=%v", found, err)
	}
}

func TestFinalizeChildErrorAndUnavailableStatusIsFailSafe(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.2", nil)}
	release.Manifest.Source.Commit = strings.Repeat("a", 40)
	transaction := &exactBuildUpdateTransaction{
		capability: make([]byte, 32), newMayPath: "/verified/new/may",
		journal: transportUpdateJournal{
			NewHelperVersion: "2.0.0", OldHelperVersion: "2.0.0",
			NewRelease: "0.0.2", NewTargets: managedReleaseTargets("0.0.2", "0.0.2"),
			OldRelease: "0.0.1", OldTargets: managedReleaseTargets("0.0.1", "0.0.1"),
			Origin: "https://example.workers.dev", Phase: "health_checked", Slot: "active",
			SchemaVersion: transportJournalSchema, TransactionID: strings.Repeat("D", 32),
		},
	}
	if err := writeTransportUpdateJournal(transaction.journal); err != nil {
		t.Fatal(err)
	}
	oldAgent := queryTransportAgentVersion
	oldFinalize := runTransportFinalizeChild
	oldStatus := queryFinalizedTransportStatus
	queryTransportAgentVersion = func(string) (agentRuntimeVersion, error) {
		return agentRuntimeVersion{
			ClientProtocol: release.Manifest.Components.May.ClientProtocol,
			SourceCommit:   release.Manifest.Source.Commit, Version: release.Manifest.ReleaseVersion,
		}, nil
	}
	runTransportFinalizeChild = func(string, string, string, string, bool, []byte) error {
		return errors.New("unknown child outcome")
	}
	queryFinalizedTransportStatus = func(string, string, string, string) (transportHelperStatus, error) {
		return transportHelperStatus{}, errors.New("unavailable")
	}
	t.Cleanup(func() {
		queryTransportAgentVersion = oldAgent
		runTransportFinalizeChild = oldFinalize
		queryFinalizedTransportStatus = oldStatus
	})
	err := transaction.finalize(&userCLIInstallPlan{socketPath: "/unused"}, release, dependencies{stderr: io.Discard})
	if !errors.Is(err, errTransportFinalizeUncertain) || transaction.committed {
		t.Fatalf("uncertain finalize did not fail safe: committed=%v err=%v", transaction.committed, err)
	}
	if _, found, readErr := readTransportUpdateJournal(); readErr != nil || !found {
		t.Fatalf("uncertain finalize removed recovery journal: found=%v err=%v", found, readErr)
	}
	journal, found, readErr := readTransportUpdateJournal()
	if readErr != nil || !found || journal.Phase != "health_checked" {
		t.Fatalf("uncertain finalize did not preserve its recoverable phase: %+v found=%v err=%v", journal, found, readErr)
	}
}

func TestPrepareExactBuildRejectsCandidateReplacedAfterVerifiedExtraction(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://example.workers.dev"
	if err := activateRequesterSlot(origin, "11111111-2222-4333-8444-555555555555"); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Join(home, userAgentDirectoryName),
		filepath.Join(home, userAgentDirectoryName, "bin"),
		filepath.Join(home, userAgentDirectoryName, "update"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mayPath := filepath.Join(home, "may")
	adapterPath := filepath.Join(home, "adapter")
	helperPath := filepath.Join(home, "helper")
	for path, value := range map[string]string{mayPath: "replaced", adapterPath: "adapter", helperPath: "helper"} {
		if err := os.WriteFile(path, []byte(value), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	adapterDigest, _ := regularFileSHA256(adapterPath, maxReleaseArtifactBytes)
	helperDigest, _ := regularFileSHA256(helperPath, maxReleaseArtifactBytes)
	previous := &localInstallReceipt{ReleaseVersion: "0.0.1", Files: map[string]string{
		"bin/may":                         "sha256:" + strings.Repeat("1", 64),
		"bin/" + gitSignAdapterBinaryName: "sha256:" + strings.Repeat("2", 64),
	}}
	previous.Helper.Version = "2.0.0"
	previous.Helper.BinarySHA256 = "sha256:" + strings.Repeat("3", 64)
	previous.Skill.Version = "0.0.1"
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.2", nil)}
	oldQuery := queryTransportUpdateStatus
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		return transportHelperStatus{Role: "current"}, nil
	}
	t.Cleanup(func() { queryTransportUpdateStatus = oldQuery })
	_, err := prepareExactBuildUpdateTransaction(
		release, origin, mayPath, adapterPath, helperPath, previous,
		verifiedLocalTransportDescriptor{
			MaySHA256:     "sha256:" + strings.Repeat("a", 64),
			AdapterSHA256: adapterDigest, HelperSHA256: helperDigest,
			MayIdentity: testExactBuildRuntimeIdentity(), AdapterIdentity: testExactBuildRuntimeIdentity(),
			HelperIdentity: testExactBuildRuntimeIdentity(),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "changed after verified extraction") {
		t.Fatalf("replaced candidate was accepted: %v", err)
	}
}

func TestPrepareExactBuildSkipsTransportWithoutSelectedRequester(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	oldQuery := queryTransportUpdateStatus
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		t.Fatal("transport status was queried without a selected requester")
		return transportHelperStatus{}, nil
	}
	t.Cleanup(func() { queryTransportUpdateStatus = oldQuery })
	transaction, err := prepareExactBuildUpdateTransaction(
		&verifiedRelease{}, "https://example.workers.dev", "", "", "",
		&localInstallReceipt{}, verifiedLocalTransportDescriptor{},
	)
	if err != nil || transaction != nil {
		t.Fatalf("unselected requester transport = %+v, %v", transaction, err)
	}
}

func TestPartialStageErrorAbortsAndRemovesPreparedJournal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://example.workers.dev"
	if err := os.MkdirAll(filepath.Join(home, userAgentDirectoryName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := activateRequesterSlot(origin, "11111111-2222-4333-8444-555555555555"); err != nil {
		t.Fatal(err)
	}
	mayPath := filepath.Join(home, "may")
	adapterPath := filepath.Join(home, "adapter")
	helperPath := filepath.Join(home, "helper")
	for path, value := range map[string]string{mayPath: "new may", adapterPath: "new adapter", helperPath: "new helper"} {
		if err := os.WriteFile(path, []byte(value), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mayDigest, _ := regularFileSHA256(mayPath, maxReleaseArtifactBytes)
	adapterDigest, _ := regularFileSHA256(adapterPath, maxReleaseArtifactBytes)
	helperDigest, _ := regularFileSHA256(helperPath, maxReleaseArtifactBytes)
	previous := &localInstallReceipt{ReleaseVersion: "0.0.1", Files: map[string]string{
		"bin/may":                         "sha256:" + strings.Repeat("1", 64),
		"bin/" + gitSignAdapterBinaryName: "sha256:" + strings.Repeat("2", 64),
	}}
	previous.Helper.Version = "2.0.0"
	previous.Helper.BinarySHA256 = "sha256:" + strings.Repeat("3", 64)
	previous.Skill.Version = "0.0.1"
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.2", nil)}
	oldQuery := queryTransportUpdateStatus
	oldStage := stageVerifiedTransport
	oldAbort := abortStagedTransport
	queries := 0
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		queries++
		if queries == 1 {
			return transportHelperStatus{Role: "current"}, nil
		}
		journal, found, err := readTransportUpdateJournal()
		if err != nil || !found {
			return transportHelperStatus{}, errors.New("prepared journal unavailable")
		}
		return transportHelperStatus{
			Role: "current", TransactionID: journal.TransactionID, TransactionState: "staged",
		}, nil
	}
	stageVerifiedTransport = func(string, string, string, string, string, string, string, string, string, exactBuildRuntimeIdentity, exactBuildRuntimeIdentity, exactBuildRuntimeIdentity) ([]byte, error) {
		return nil, errors.New("ACL failed after content write")
	}
	aborted := false
	abortStagedTransport = func(string, string, string) error { aborted = true; return nil }
	t.Cleanup(func() {
		queryTransportUpdateStatus = oldQuery
		stageVerifiedTransport = oldStage
		abortStagedTransport = oldAbort
	})
	_, err := prepareExactBuildUpdateTransaction(
		release, origin, mayPath, adapterPath, helperPath, previous,
		verifiedLocalTransportDescriptor{
			MaySHA256: mayDigest, AdapterSHA256: adapterDigest, HelperSHA256: helperDigest,
			MayIdentity: testExactBuildRuntimeIdentity(), AdapterIdentity: testExactBuildRuntimeIdentity(),
			HelperIdentity: testExactBuildRuntimeIdentity(),
		},
	)
	if err == nil || !aborted {
		t.Fatalf("partial stage was not safely aborted: aborted=%v err=%v", aborted, err)
	}
	if _, found, readErr := readTransportUpdateJournal(); readErr != nil || found {
		t.Fatalf("successfully aborted stage retained journal: found=%v err=%v", found, readErr)
	}
}

func TestStagedJournalWriteAndAbortFailurePreservesNextRunRecovery(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://example.workers.dev"
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "libexec"),
		filepath.Join(root, "versions", "0.0.1"),
		filepath.Join(root, "skill-versions", "0.0.1", "onenod"),
		filepath.Join(root, "receipt-versions"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := activateRequesterSlot(origin, "11111111-2222-4333-8444-555555555555"); err != nil {
		t.Fatal(err)
	}
	oldTargets := managedReleaseTargets("0.0.1", "0.0.1")
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		if err := os.Symlink(oldTargets[name], stable); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"may", gitSignAdapterBinaryName} {
		if err := os.WriteFile(filepath.Join(root, "versions", "0.0.1", name), []byte("old "+name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldReceipt := []byte(`{"schema_version":2,"release_version":"0.0.1"}`)
	if err := os.WriteFile(filepath.Join(root, "receipt-versions", "0.0.1.json"), oldReceipt, 0o600); err != nil {
		t.Fatal(err)
	}

	mayPath := filepath.Join(home, "new-may")
	adapterPath := filepath.Join(home, "new-adapter")
	helperPath := filepath.Join(root, "libexec", keychainHelperBinaryName)
	for path, value := range map[string]string{
		mayPath: "new may", adapterPath: "new adapter", helperPath: "unchanged helper",
	} {
		if err := os.WriteFile(path, []byte(value), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mayDigest, _ := regularFileSHA256(mayPath, maxReleaseArtifactBytes)
	adapterDigest, _ := regularFileSHA256(adapterPath, maxReleaseArtifactBytes)
	helperDigest, _ := regularFileSHA256(helperPath, maxReleaseArtifactBytes)
	previous := &localInstallReceipt{ReleaseVersion: "0.0.1", Files: map[string]string{
		"bin/may":                         "sha256:" + strings.Repeat("1", 64),
		"bin/" + gitSignAdapterBinaryName: "sha256:" + strings.Repeat("2", 64),
	}}
	previous.Helper.Version = "2.0.0"
	previous.Helper.BinarySHA256 = helperDigest
	previous.Skill.Version = "0.0.1"
	release := &verifiedRelease{Manifest: validManifestFixture("0.0.2", nil)}

	oldQuery := queryTransportUpdateStatus
	oldStage := stageVerifiedTransport
	oldStageAbort := abortStagedTransport
	oldRecoveryAbort := runTransportUpdateAbort
	oldRestart := restartTransportAgent
	queryCount := 0
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		queryCount++
		if queryCount == 1 {
			return transportHelperStatus{Role: "current"}, nil
		}
		journal, found, err := readTransportUpdateJournal()
		if err != nil || !found {
			return transportHelperStatus{}, errors.New("prepared recovery journal unavailable")
		}
		return transportHelperStatus{
			Role: "current", TransactionID: journal.TransactionID,
			TransactionState: "staged",
		}, nil
	}
	displacedRoot := home + "-journal-fault"
	faultActive := false
	restoreJournalRoot := func() {
		if !faultActive {
			return
		}
		_ = os.Remove(root)
		if err := os.Rename(displacedRoot, root); err != nil {
			t.Fatalf("restore journal root: %v", err)
		}
		faultActive = false
	}
	stageVerifiedTransport = func(string, string, string, string, string, string, string, string, string, exactBuildRuntimeIdentity, exactBuildRuntimeIdentity, exactBuildRuntimeIdentity) ([]byte, error) {
		if err := os.Rename(root, displacedRoot); err != nil {
			return nil, err
		}
		if err := os.WriteFile(root, []byte("block journal directory"), 0o600); err != nil {
			_ = os.Rename(displacedRoot, root)
			return nil, err
		}
		faultActive = true
		return bytes.Repeat([]byte{0x7d}, 32), nil
	}
	abortStagedTransport = func(string, string, string) error {
		return errors.New("simulated helper abort outage")
	}
	recoveredAbort := false
	runTransportUpdateAbort = func(_ string, _, _ string, transactionID string) error {
		recoveredAbort = transportTransactionPattern.MatchString(transactionID)
		return nil
	}
	restartTransportAgent = func(*userCLIInstallPlan) error { return nil }
	t.Cleanup(func() {
		restoreJournalRoot()
		queryTransportUpdateStatus = oldQuery
		stageVerifiedTransport = oldStage
		abortStagedTransport = oldStageAbort
		runTransportUpdateAbort = oldRecoveryAbort
		restartTransportAgent = oldRestart
	})

	_, err := prepareExactBuildUpdateTransaction(
		release, origin, mayPath, adapterPath, "", previous,
		verifiedLocalTransportDescriptor{
			MaySHA256: mayDigest, AdapterSHA256: adapterDigest, HelperSHA256: helperDigest,
			MayIdentity: testExactBuildRuntimeIdentity(), AdapterIdentity: testExactBuildRuntimeIdentity(),
			HelperIdentity: testExactBuildRuntimeIdentity(),
		},
	)
	if err == nil || !strings.Contains(err.Error(), "staged transport abort also failed") {
		t.Fatalf("journal+abort fault did not fail closed: %v", err)
	}
	restoreJournalRoot()
	journal, found, err := readTransportUpdateJournal()
	if err != nil || !found || journal.Phase != "prepared" {
		t.Fatalf("prepared recovery journal was not preserved: %+v found=%v err=%v", journal, found, err)
	}
	if err := reconcileInterruptedTransportUpdate(dependencies{stdout: io.Discard}); err != nil {
		t.Fatalf("next-run recovery failed: %v", err)
	}
	if !recoveredAbort {
		t.Fatal("next-run recovery did not abort the staged helper transaction")
	}
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		t.Fatalf("successful next-run recovery retained journal: found=%v err=%v", found, err)
	}
	for name, stable := range map[string]string{
		"may":                    filepath.Join(root, "bin", "may"),
		gitSignAdapterBinaryName: filepath.Join(root, "bin", gitSignAdapterBinaryName),
		"skill":                  filepath.Join(root, "skill"),
	} {
		target, err := os.Readlink(stable)
		if err != nil || target != oldTargets[name] {
			t.Fatalf("recovered %s target = %q, %v", name, target, err)
		}
	}
}
