package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testActorOldVersion = "0.0.2-alpha.26"
	testActorNewVersion = "0.0.2-alpha.27"
	testActorOrigin     = "https://example.workers.dev"
)

type localUpdateActorFixture struct {
	home      string
	journal   transportUpdateJournal
	newHelper string
	newMay    string
	oldHelper string
	oldMay    string
	root      string
}

func newLocalUpdateActorFixture(t *testing.T) *localUpdateActorFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	root := filepath.Join(home, userAgentDirectoryName)
	for _, directory := range []string{
		filepath.Join(root, "bin"),
		filepath.Join(root, "libexec"),
		filepath.Join(root, "versions", testActorOldVersion),
		filepath.Join(root, "versions", testActorNewVersion),
		filepath.Join(root, "helper-versions", "3.0.1"),
		filepath.Join(root, "helper-versions", "3.0.2"),
		filepath.Join(root, "receipt-versions"),
		filepath.Join(root, "skill-versions", testActorOldVersion, "onenod"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &localUpdateActorFixture{
		home: home, root: root,
		oldMay: filepath.Join(root, "versions", testActorOldVersion, "may"),
		newMay: filepath.Join(root, "versions", testActorNewVersion, "may"),
		oldHelper: filepath.Join(
			root, "helper-versions", "3.0.1", keychainHelperBinaryName,
		),
		newHelper: filepath.Join(
			root, "helper-versions", "3.0.2", keychainHelperBinaryName,
		),
	}
	for path, content := range map[string]string{
		fixture.oldMay:    "old exact may",
		fixture.newMay:    "new exact may",
		fixture.oldHelper: "old exact helper",
		fixture.newHelper: "new exact helper",
		filepath.Join(root, "versions", testActorOldVersion, gitSignAdapterBinaryName): "old adapter",
		filepath.Join(root, "versions", testActorNewVersion, gitSignAdapterBinaryName): "new adapter",
	} {
		if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldMayDigest, err := regularFileSHA256(fixture.oldMay, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	oldAdapterDigest, err := regularFileSHA256(
		filepath.Join(root, "versions", testActorOldVersion, gitSignAdapterBinaryName),
		maxReleaseArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldHelperDigest, err := regularFileSHA256(fixture.oldHelper, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, "skill-versions", testActorOldVersion, "onenod", "SKILL.md"),
		[]byte("old exact Skill"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	oldSkillDigest, err := directoryTreeSHA256(
		filepath.Join(root, "skill-versions", testActorOldVersion, "onenod"),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt := writeTestLocalInstallReceipt(
		t, home, testActorOrigin, testActorOldVersion,
	)
	receipt.Files["bin/may"] = oldMayDigest
	receipt.Files["bin/"+gitSignAdapterBinaryName] = oldAdapterDigest
	receipt.Helper.Version = "3.0.1"
	receipt.Helper.BinarySHA256 = oldHelperDigest
	receipt.Skill.TreeSHA256 = oldSkillDigest
	if err := writeLocalInstallReceipt(filepath.Join(root, "install.json"), receipt); err != nil {
		t.Fatal(err)
	}
	if err := preserveImmutableReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	fixture.journal = transportUpdateJournal{
		HelperChanged:    true,
		NewHelperVersion: "3.0.2",
		NewRelease:       testActorNewVersion,
		NewTargets:       managedReleaseTargets(testActorNewVersion, testActorNewVersion),
		OldHelperVersion: "3.0.1",
		OldRelease:       testActorOldVersion,
		OldTargets:       managedReleaseTargets(testActorOldVersion, testActorOldVersion),
		Origin:           testActorOrigin,
		Phase:            "staged",
		SchemaVersion:    transportJournalSchema,
		Slot:             "default",
		TransactionID:    strings.Repeat("A", 32),
	}
	fixture.setStableMay(t, "old")
	fixture.setStableHelper(t, "old")
	if err := writeTransportUpdateJournal(fixture.journal); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture *localUpdateActorFixture) setStableMay(t *testing.T, side string) {
	t.Helper()
	path := filepath.Join(fixture.root, "bin", "may")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	target := fixture.journal.OldTargets["may"]
	if side == "new" {
		target = fixture.journal.NewTargets["may"]
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func (fixture *localUpdateActorFixture) setStableHelper(t *testing.T, side string) {
	t.Helper()
	path := filepath.Join(fixture.root, "libexec", keychainHelperBinaryName)
	source := fixture.oldHelper
	if side == "new" {
		source = fixture.newHelper
	}
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o700); err != nil {
		t.Fatal(err)
	}
}

func (fixture *localUpdateActorFixture) setLiveReceiptToNew(t *testing.T) {
	t.Helper()
	receipt := writeTestLocalInstallReceipt(
		t, fixture.home, testActorOrigin, testActorNewVersion,
	)
	mayDigest, err := regularFileSHA256(fixture.newMay, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	adapterDigest, err := regularFileSHA256(
		filepath.Join(fixture.root, "versions", testActorNewVersion, gitSignAdapterBinaryName),
		maxReleaseArtifactBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	helperDigest, err := regularFileSHA256(fixture.newHelper, maxReleaseArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Files["bin/may"] = mayDigest
	receipt.Files["bin/"+gitSignAdapterBinaryName] = adapterDigest
	receipt.Helper.Version = "3.0.2"
	receipt.Helper.BinarySHA256 = helperDigest
	if err := writeLocalInstallReceipt(
		filepath.Join(fixture.root, "install.json"), receipt,
	); err != nil {
		t.Fatal(err)
	}
}

func useFixtureRunningActor(
	t *testing.T,
	path, version, commit string,
) {
	t.Helper()
	priorExecutable := currentLocalUpdateExecutable
	priorVersion, priorTag, priorCommit := productVersion, releaseTag, sourceCommit
	currentLocalUpdateExecutable = func() (string, error) { return path, nil }
	productVersion, releaseTag, sourceCommit = version, "v"+version, commit
	t.Cleanup(func() {
		currentLocalUpdateExecutable = priorExecutable
		productVersion, releaseTag, sourceCommit = priorVersion, priorTag, priorCommit
	})
}

func TestInstalledLocalUpdateActorCoversCrashMatrix(t *testing.T) {
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	tests := []struct {
		name             string
		stableMay        string
		stableHelper     string
		removeNewHelper  bool
		helperChanged    bool
		liveReceiptNew   bool
		expectedActorNew bool
	}{
		{name: "prepared old may old helper without new helper", stableMay: "old", stableHelper: "old", removeNewHelper: true},
		{name: "helper activated before may promotion", stableMay: "old", stableHelper: "new"},
		{name: "new may old helper live receipt old", stableMay: "new", stableHelper: "old"},
		{name: "new may old helper live receipt new", stableMay: "new", stableHelper: "old", liveReceiptNew: true},
		{name: "new may helper live receipt old", stableMay: "new", stableHelper: "new", expectedActorNew: true},
		{name: "new may helper live receipt new", stableMay: "new", stableHelper: "new", liveReceiptNew: true, expectedActorNew: true},
		{name: "unchanged helper with new may", stableMay: "new", stableHelper: "old", helperChanged: false, expectedActorNew: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLocalUpdateActorFixture(t)
			fixture.setStableMay(t, test.stableMay)
			fixture.setStableHelper(t, test.stableHelper)
			fixture.journal.HelperChanged = test.helperChanged || test.name != "unchanged helper with new may"
			if test.liveReceiptNew {
				fixture.setLiveReceiptToNew(t)
			}
			if test.removeNewHelper {
				if err := os.Remove(fixture.newHelper); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeTransportUpdateJournal(fixture.journal); err != nil {
				t.Fatal(err)
			}
			useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)
			actor, err := installedLocalUpdateActor(
				testActorOrigin, testActorNewVersion, targetCommit,
			)
			if err != nil {
				t.Fatal(err)
			}
			expected := fixture.oldMay
			if test.expectedActorNew {
				expected = fixture.newMay
			}
			actorInfo, actorErr := os.Stat(actor)
			expectedInfo, expectedErr := os.Stat(expected)
			if actorErr != nil || expectedErr != nil || !os.SameFile(actorInfo, expectedInfo) {
				t.Fatalf("selected actor %q, want %q", actor, expected)
			}
		})
	}
}

func TestInstalledLocalUpdateActorRejectsAmbiguousStateAndMismatches(t *testing.T) {
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	t.Run("unknown helper", func(t *testing.T) {
		fixture := newLocalUpdateActorFixture(t)
		fixture.setStableMay(t, "new")
		if err := os.WriteFile(
			filepath.Join(fixture.root, "libexec", keychainHelperBinaryName),
			[]byte("neither helper"), 0o700,
		); err != nil {
			t.Fatal(err)
		}
		useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)
		if _, err := installedLocalUpdateActor(
			testActorOrigin, testActorNewVersion, targetCommit,
		); err == nil {
			t.Fatal("ambiguous helper state selected an actor")
		}
	})
	t.Run("different transaction target", func(t *testing.T) {
		fixture := newLocalUpdateActorFixture(t)
		useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)
		if _, err := installedLocalUpdateActor(
			testActorOrigin, "0.0.2-alpha.28", targetCommit,
		); err == nil || !strings.Contains(err.Error(), "recover that exact transaction first") {
			t.Fatalf("different journal target returned %v", err)
		}
	})
	t.Run("different Origin", func(t *testing.T) {
		fixture := newLocalUpdateActorFixture(t)
		useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)
		if _, err := installedLocalUpdateActor(
			"https://other.workers.dev", testActorNewVersion, targetCommit,
		); err == nil || !strings.Contains(err.Error(), "Origins differ") {
			t.Fatalf("mixed Origins returned %v", err)
		}
	})
}

func TestOperatorPreflightRejectsMissingTargetAndRollbackMaterial(t *testing.T) {
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *localUpdateActorFixture)
	}{
		{
			name: "stable new target missing",
			mutate: func(t *testing.T, fixture *localUpdateActorFixture) {
				fixture.setStableMay(t, "new")
				fixture.setStableHelper(t, "new")
				if err := os.Remove(fixture.newMay); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "old helper rollback source missing",
			mutate: func(t *testing.T, fixture *localUpdateActorFixture) {
				fixture.setStableMay(t, "old")
				fixture.setStableHelper(t, "new")
				if err := os.Remove(fixture.oldHelper); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLocalUpdateActorFixture(t)
			test.mutate(t, fixture)
			useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)
			priorCanonical := canonicalLocalUpdateHome
			canonicalLocalUpdateHome = func() (string, error) { return fixture.home, nil }
			t.Cleanup(func() { canonicalLocalUpdateHome = priorCanonical })
			if _, err := validateInstalledLocalUpdateHandoff(
				testActorOrigin, testActorNewVersion, targetCommit,
			); err == nil {
				t.Fatal("operator preflight accepted incomplete local recovery material")
			}
		})
	}
}

func TestUnchangedHelperJournalRequiresStableHelperBytes(t *testing.T) {
	for _, stableMay := range []string{"old", "new"} {
		t.Run(stableMay, func(t *testing.T) {
			fixture := newLocalUpdateActorFixture(t)
			fixture.journal.HelperChanged = false
			fixture.setStableMay(t, stableMay)
			if err := writeTransportUpdateJournal(fixture.journal); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(
				filepath.Join(fixture.root, "libexec", keychainHelperBinaryName),
				[]byte("corrupt unchanged helper"), 0o700,
			); err != nil {
				t.Fatal(err)
			}
			useFixtureRunningActor(
				t, fixture.newMay, testActorNewVersion,
				"cccccccccccccccccccccccccccccccccccccccc",
			)
			if _, err := installedLocalUpdateActor(
				testActorOrigin, testActorNewVersion,
				"cccccccccccccccccccccccccccccccccccccccc",
			); err == nil || !strings.Contains(err.Error(), "unchanged stable helper") {
				t.Fatalf("corrupt unchanged helper returned %v", err)
			}
		})
	}
}

func TestInstalledActorWithoutJournalIsReceiptBoundAndStable(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	if err := removeTransportUpdateJournal(); err != nil {
		t.Fatal(err)
	}
	actor, err := installedLocalUpdateActor(
		testActorOrigin, testActorNewVersion, strings.Repeat("c", 40),
	)
	if err != nil || actor != fixture.oldMay {
		t.Fatalf("receipt-bound actor=%q err=%v", actor, err)
	}
	fixture.setStableMay(t, "new")
	if _, err := installedLocalUpdateActor(
		testActorOrigin, testActorNewVersion, strings.Repeat("c", 40),
	); err == nil || !strings.Contains(err.Error(), "stable may") {
		t.Fatalf("receipt/stable mismatch returned %v", err)
	}
}

func TestOperatorLocalBranchesDelegateWithoutOuterHelperPrompt(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	priorCanonical := canonicalLocalUpdateHome
	canonicalLocalUpdateHome = func() (string, error) { return fixture.home, nil }
	t.Cleanup(func() { canonicalLocalUpdateHome = priorCanonical })
	if err := removeTransportUpdateJournal(); err != nil {
		t.Fatal(err)
	}
	priorChild := runInstalledLocalUpdateChild
	childCalls := 0
	runInstalledLocalUpdateChild = func(
		_ context.Context, actor, version string, _ dependencies,
	) error {
		childCalls++
		if actor != fixture.oldMay ||
			version != testActorNewVersion {
			t.Fatalf("child received actor=%q version=%q", actor, version)
		}
		return nil
	}
	t.Cleanup(func() { runInstalledLocalUpdateChild = priorChild })
	var output strings.Builder
	deps := dependencies{
		stdin: strings.NewReader("this input must remain unread"), stdout: &output, stderr: io.Discard,
	}
	if err := runInstalledLocalUpdate(
		context.Background(), testActorOrigin, testActorNewVersion,
		strings.Repeat("c", 40), deps,
	); err != nil {
		t.Fatal(err)
	}
	transaction := &operatorUpdateTransaction{Outcome: "pending"}
	transactionPath := filepath.Join(fixture.home, "operator-transaction.json")
	if err := runPostDeploymentLocalUpdate(
		context.Background(), testActorOrigin, testActorNewVersion,
		strings.Repeat("c", 40), transaction, transactionPath, deps,
	); err != nil {
		t.Fatal(err)
	}
	if childCalls != 2 {
		t.Fatalf("local branches made %d child calls", childCalls)
	}
	if strings.Contains(output.String(), "Update the OneNod Keychain helper now?") {
		t.Fatalf("outer handoff duplicated the helper prompt: %s", output.String())
	}
}

func TestPostDeploymentChildFailureRemainsLocalPending(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	priorCanonical := canonicalLocalUpdateHome
	canonicalLocalUpdateHome = func() (string, error) { return fixture.home, nil }
	t.Cleanup(func() { canonicalLocalUpdateHome = priorCanonical })
	if err := removeTransportUpdateJournal(); err != nil {
		t.Fatal(err)
	}
	priorChild := runInstalledLocalUpdateChild
	runInstalledLocalUpdateChild = func(
		context.Context, string, string, dependencies,
	) error {
		return errors.New("child rejected helper ceremony")
	}
	t.Cleanup(func() { runInstalledLocalUpdateChild = priorChild })
	transaction := &operatorUpdateTransaction{Outcome: "pending"}
	path := filepath.Join(fixture.home, "operator-transaction.json")
	err := runPostDeploymentLocalUpdate(
		context.Background(), testActorOrigin, testActorNewVersion,
		strings.Repeat("c", 40), transaction, path,
		dependencies{stdin: strings.NewReader("n\n"), stdout: io.Discard, stderr: io.Discard},
	)
	if err == nil || transaction.Outcome != "remote_complete_local_pending" {
		t.Fatalf("child failure outcome=%q err=%v", transaction.Outcome, err)
	}
	var stored operatorUpdateTransaction
	if err := readStrictPrivateJSON(path, &stored); err != nil ||
		stored.Outcome != "remote_complete_local_pending" {
		t.Fatalf("stored local-pending transaction=%+v err=%v", stored, err)
	}
}

func TestInstalledLocalUpdateChildUsesCanonicalEnvironmentAndExactArgv(t *testing.T) {
	stage := t.TempDir()
	result := filepath.Join(stage, "result")
	script := filepath.Join(stage, "actor")
	content := "#!/bin/sh\n" +
		"printf '%s\\n' \"$HOME\" \"$PATH\" \"$#\" \"$1\" \"$2\" \"$3\" \"${ONENOD_UPDATE_REEXEC_IDENTITY-unset}\" \"${CF_API_TOKEN-unset}\" \"${DYLD_INSERT_LIBRARIES-unset}\" > " + result + "\n"
	if err := os.WriteFile(script, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ONENOD_UPDATE_REEXEC_IDENTITY", "leak")
	t.Setenv("CF_API_TOKEN", "leak")
	t.Setenv("DYLD_INSERT_LIBRARIES", "leak")
	t.Setenv("PATH", "/usr/bin:/bin:/test/user-bin")
	if err := runInstalledLocalUpdateProcess(
		context.Background(), script, testActorNewVersion,
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := localUpdateProcessEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(environment[0], "HOME=") + "\n/usr/bin:/bin:/test/user-bin\n3\nupdate\n--version\n" + testActorNewVersion + "\nunset\nunset\nunset\n"
	if string(encoded) != want {
		t.Fatalf("child authority surface:\n%s\nwant:\n%s", encoded, want)
	}
}

func TestRecoveryBootstrapAndPostRecoveryReexecUseFixedActors(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	fixture.setStableMay(t, "new")
	fixture.setStableHelper(t, "old")
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	useFixtureRunningActor(
		t, filepath.Join(fixture.root, "bin", "may"), testActorNewVersion, targetCommit,
	)
	priorExec := execLocalUpdateProcess
	var calls [][]string
	var paths []string
	execLocalUpdateProcess = func(path string, argv, environment []string) error {
		paths = append(paths, path)
		calls = append(calls, append([]string(nil), argv...))
		if len(environment) < 1 || len(environment) > 2 ||
			!strings.HasPrefix(environment[0], "HOME=") ||
			(len(environment) == 2 && !strings.HasPrefix(environment[1], "PATH=")) {
			t.Fatalf("reexec environment=%q", environment)
		}
		return nil
	}
	t.Cleanup(func() { execLocalUpdateProcess = priorExec })
	reexecuted, err := bootstrapLocalUpdateRecovery(
		"", testActorNewVersion, mustSnapshotLocalUpdateActor(t),
	)
	if len(paths) != 1 {
		t.Fatalf("bootstrap paths=%q reexecuted=%v err=%v", paths, reexecuted, err)
	}
	selectedInfo, selectedErr := os.Stat(paths[0])
	oldInfo, oldErr := os.Stat(fixture.oldMay)
	if err != nil || !reexecuted || selectedErr != nil ||
		oldErr != nil || !os.SameFile(selectedInfo, oldInfo) {
		t.Fatalf("bootstrap paths=%q reexecuted=%v err=%v", paths, reexecuted, err)
	}
	if strings.Join(calls[0][1:], " ") != "update --version "+testActorNewVersion {
		t.Fatalf("bootstrap argv=%q", calls[0])
	}

	// Snapshot the new inode while the stable symlink still points at it. A
	// rollback then changes that same symlink string to old; comparison must use
	// the saved inode, not resolve the old symlink after mutation.
	fixture.setStableMay(t, "new")
	before, err := snapshotCurrentLocalUpdateActor()
	if err != nil {
		t.Fatal(err)
	}
	fixture.setStableMay(t, "old")
	if err := removeTransportUpdateJournal(); err != nil {
		t.Fatal(err)
	}
	reexecuted, err = reexecuteLocalUpdateAfterRecovery(
		before, testActorNewVersion,
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	)
	if len(paths) != 2 {
		t.Fatalf("post-recovery paths=%q reexecuted=%v err=%v", paths, reexecuted, err)
	}
	selectedInfo, selectedErr = os.Stat(paths[1])
	if err != nil || !reexecuted || selectedErr != nil ||
		!os.SameFile(selectedInfo, oldInfo) {
		t.Fatalf("post-recovery paths=%q reexecuted=%v err=%v", paths, reexecuted, err)
	}
}

func TestStagedTargetRecoveryHandsContinuationBackToOldActor(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	fixture.setStableMay(t, "new")
	fixture.setStableHelper(t, "new")
	fixture.setLiveReceiptToNew(t)
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)

	priorQuery := queryTransportUpdateStatus
	priorAbort := runTransportUpdateAbort
	priorRestart := restartTransportAgent
	priorExec := execLocalUpdateProcess
	var events []string
	queryTransportUpdateStatus = func(origin, slot string) (transportHelperStatus, error) {
		events = append(events, "target-status")
		return transportHelperStatus{
			Role: "staged", TransactionID: fixture.journal.TransactionID,
			TransactionState: "staged",
		}, nil
	}
	runTransportUpdateAbort = func(mayPath, origin, slot, transactionID string) error {
		events = append(events, "old-abort")
		if mayPath != fixture.oldMay || origin != fixture.journal.Origin ||
			slot != fixture.journal.Slot || transactionID != fixture.journal.TransactionID {
			t.Fatalf("abort authority path=%q origin=%q slot=%q id=%q", mayPath, origin, slot, transactionID)
		}
		return nil
	}
	restartTransportAgent = func(*userCLIInstallPlan) error { return nil }
	execLocalUpdateProcess = func(path string, argv, environment []string) error {
		events = append(events, "old-continue")
		info, infoErr := os.Stat(path)
		oldInfo, oldErr := os.Stat(fixture.oldMay)
		if infoErr != nil || oldErr != nil || !os.SameFile(info, oldInfo) ||
			strings.Join(argv[1:], " ") != "update --version "+testActorNewVersion {
			t.Fatalf("continuation path=%q argv=%q", path, argv)
		}
		return nil
	}
	t.Cleanup(func() {
		queryTransportUpdateStatus = priorQuery
		runTransportUpdateAbort = priorAbort
		restartTransportAgent = priorRestart
		execLocalUpdateProcess = priorExec
	})

	if reexecuted, err := bootstrapLocalUpdateRecovery(
		"", testActorNewVersion, mustSnapshotLocalUpdateActor(t),
	); err != nil || reexecuted {
		t.Fatalf("target bootstrap reexecuted=%v err=%v", reexecuted, err)
	}
	before, err := snapshotCurrentLocalUpdateActor()
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileInterruptedTransportUpdate(
		dependencies{stdout: io.Discard},
	); err != nil {
		t.Fatal(err)
	}
	if reexecuted, err := reexecuteLocalUpdateAfterRecovery(
		before, testActorNewVersion,
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	); err != nil || !reexecuted {
		t.Fatalf("old continuation reexecuted=%v err=%v", reexecuted, err)
	}
	if strings.Join(events, ",") != "target-status,old-abort,old-continue" {
		t.Fatalf("recovery actor sequence=%q", events)
	}
}

func TestOldActorSecondBootstrapFinishesNewMayOldHelperRecovery(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	fixture.setStableMay(t, "new")
	fixture.setStableHelper(t, "old")
	const targetCommit = "cccccccccccccccccccccccccccccccccccccccc"
	useFixtureRunningActor(t, fixture.newMay, testActorNewVersion, targetCommit)

	priorExec := execLocalUpdateProcess
	var selected string
	execLocalUpdateProcess = func(path string, _ []string, _ []string) error {
		selected = path
		return nil
	}
	t.Cleanup(func() { execLocalUpdateProcess = priorExec })
	newSnapshot := mustSnapshotLocalUpdateActor(t)
	if reexecuted, err := bootstrapLocalUpdateRecovery(
		"", testActorNewVersion, newSnapshot,
	); err != nil || !reexecuted || !sameTestFile(selected, fixture.oldMay) {
		t.Fatalf("new actor selected=%q reexecuted=%v err=%v", selected, reexecuted, err)
	}

	// Simulate syscall.Exec into old: the second bootstrap must accept old as
	// the already-selected actor and must not require it to claim new's build.
	useFixtureRunningActor(t, fixture.oldMay, testActorOldVersion, strings.Repeat("b", 40))
	oldSnapshot := mustSnapshotLocalUpdateActor(t)
	selected = ""
	if reexecuted, err := bootstrapLocalUpdateRecovery(
		"", testActorNewVersion, oldSnapshot,
	); err != nil || reexecuted || selected != "" {
		t.Fatalf("old actor selected=%q reexecuted=%v err=%v", selected, reexecuted, err)
	}
	priorQuery := queryTransportUpdateStatus
	priorAbort := runTransportUpdateAbort
	priorRestart := restartTransportAgent
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		return transportHelperStatus{
			Role: "current", TransactionID: fixture.journal.TransactionID,
			TransactionState: "staged",
		}, nil
	}
	runTransportUpdateAbort = func(string, string, string, string) error { return nil }
	restartTransportAgent = func(*userCLIInstallPlan) error { return nil }
	t.Cleanup(func() {
		queryTransportUpdateStatus = priorQuery
		runTransportUpdateAbort = priorAbort
		restartTransportAgent = priorRestart
	})
	if err := reconcileInterruptedTransportUpdate(
		dependencies{stdout: io.Discard},
	); err != nil {
		t.Fatal(err)
	}
	if _, found, err := readTransportUpdateJournal(); err != nil || found {
		t.Fatalf("old actor recovery retained journal: found=%v err=%v", found, err)
	}
}

func sameTestFile(first, second string) bool {
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	return firstErr == nil && secondErr == nil && os.SameFile(firstInfo, secondInfo)
}

func TestRecoveryBootstrapAcceptsOnlyItsExactVersion(t *testing.T) {
	fixture := newLocalUpdateActorFixture(t)
	useFixtureRunningActor(
		t, fixture.oldMay, testActorOldVersion, strings.Repeat("b", 40),
	)
	for _, selection := range []struct {
		channel string
		version string
	}{
		{},
		{channel: "alpha"},
		{version: "0.0.2-alpha.28"},
	} {
		if reexecuted, err := bootstrapLocalUpdateRecovery(
			selection.channel, selection.version, mustSnapshotLocalUpdateActor(t),
		); err == nil || reexecuted || !strings.Contains(err.Error(), "exact --version") {
			t.Fatalf("selection %+v reexecuted=%v err=%v", selection, reexecuted, err)
		}
	}
}

func mustSnapshotLocalUpdateActor(t *testing.T) *resolvedLocalUpdateActor {
	t.Helper()
	actor, err := snapshotCurrentLocalUpdateActor()
	if err != nil {
		t.Fatal(err)
	}
	return actor
}

func TestOperatorHandoffRejectsAmbientHomeBeforeChild(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	priorChild := runInstalledLocalUpdateChild
	called := false
	runInstalledLocalUpdateChild = func(
		context.Context, string, string, dependencies,
	) error {
		called = true
		return nil
	}
	t.Cleanup(func() { runInstalledLocalUpdateChild = priorChild })
	err := runInstalledLocalUpdate(
		context.Background(), testActorOrigin, testActorNewVersion,
		strings.Repeat("c", 40),
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	)
	if err == nil || called || !strings.Contains(err.Error(), "canonical account home") {
		t.Fatalf("ambient HOME mismatch called=%v err=%v", called, err)
	}
}

func TestSnapshotFailurePreventsTransportReconcile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	priorCanonical := canonicalLocalUpdateHome
	canonicalLocalUpdateHome = func() (string, error) { return home, nil }
	t.Cleanup(func() { canonicalLocalUpdateHome = priorCanonical })
	priorExecutable := currentLocalUpdateExecutable
	currentLocalUpdateExecutable = func() (string, error) {
		return "", errors.New("snapshot failed")
	}
	t.Cleanup(func() { currentLocalUpdateExecutable = priorExecutable })
	priorQuery := queryTransportUpdateStatus
	queried := false
	queryTransportUpdateStatus = func(string, string) (transportHelperStatus, error) {
		queried = true
		return transportHelperStatus{}, nil
	}
	t.Cleanup(func() { queryTransportUpdateStatus = priorQuery })
	if err := runLocalUpdate(
		[]string{"--version", testActorNewVersion},
		dependencies{stdin: strings.NewReader(""), stdout: io.Discard, stderr: io.Discard},
	); err == nil || queried || !strings.Contains(err.Error(), "running local update actor") {
		t.Fatalf("snapshot failure queried=%v err=%v", queried, err)
	}
}
