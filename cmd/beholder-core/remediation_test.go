package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRemediationCrossDirectoryFileIdentityAndLongExecution(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	writeSessionFixture(t, filepath.Join(f.root, "copy.jsonl"), f.sessionID, f.turnID, f.root)
	if err := os.WriteFile(filepath.Join(f.root, "unrelated.jsonl"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	f.host.CWD = filepath.Dir(f.root)
	if r := f.registerPrimaryHost(); !r.Accepted {
		t.Fatal(r)
	}
	f.requestPeer.Nodes[0].CWD = filepath.Join(filepath.Dir(f.root), "sibling-project")
	f.advance(2 * time.Hour)
	checked := f.checkPrimaryRequest()
	if !checked.Accepted || checked.decisionCWD != f.requestPeer.Nodes[0].CWD {
		t.Fatal("live cross-project context was not retained")
	}
	checked.clearTransient()
	f.advance(time.Minute)
	assertEscalated(t, f.checkPrimaryRequest(), "request-replay")
	f.request.Nonce = "fresh-after-long-execution"
	if err := os.Rename(f.transcriptPath, f.transcriptPath+".original"); err != nil {
		t.Fatal(err)
	}
	writeSessionFixture(t, f.transcriptPath, f.sessionID, f.turnID, f.root)
	assertEscalated(t, f.checkPrimaryRequest(), "transcript-identity-changed")
}

func TestRemediationLifecycleKeepsPTYAndCancelsAuthorityContext(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if r := f.registerPrimaryHost(); !r.Accepted {
		t.Fatal(r)
	}
	event := lifecycleObservation{SessionID: f.sessionID, TurnID: f.turnID, ToolUseID: f.toolUseID, TranscriptPath: f.transcriptPath, Event: "PostToolUse"}
	if r := f.core.observeLifecycle(event, f.hookPeer); !r.Accepted {
		t.Fatal(r)
	}
	f.advance(301 * time.Second)
	if r := f.checkPrimaryRequest(); !r.Accepted {
		t.Fatal("nonterminal tool return invalidated live PTY")
	}
	event.Event, event.ToolUseID = "Stop", ""
	f.core.observeLifecycle(event, f.hookPeer)
	f.request.Nonce = "after-normal-turn-return"
	if r := f.checkPrimaryRequest(); !r.Accepted {
		t.Fatal("turn return was mistaken for process exit")
	}
	event.Event = "Interrupt"
	if r := f.core.observeLifecycle(event, f.hookPeer); !r.Accepted {
		t.Fatal(r)
	}
	f.request.Nonce = "after-human-interruption"
	assertEscalated(t, f.checkPrimaryRequest(), "execution-root-unverified")
	if _, r := f.core.contexts.acquire(f.sessionID, f.turnID, f.toolUseID); r.Accepted {
		t.Fatal("cancelled tool context still available to a transport lease")
	}
}

func TestRemediationCompletedUnboundCallCannotPolluteNextCall(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if r := f.core.registerHost(f.host, f.hookPeer); !r.Accepted {
		t.Fatal(r)
	}
	event := lifecycleObservation{SessionID: f.sessionID, TurnID: f.turnID, ToolUseID: f.toolUseID, TranscriptPath: f.transcriptPath, Event: "PostToolUse", Terminal: true}
	if r := f.core.observeLifecycle(event, f.hookPeer); !r.Accepted {
		t.Fatal(r)
	}
	if len(f.core.claimsByToolRef) != 0 {
		t.Fatal("finished unbound observation retained")
	}
}

func TestRemediationPostReturnBoundaryExcludesOldCallsButKeepsRunningRoots(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if r := f.core.registerHost(f.host, f.hookPeer); !r.Accepted {
		t.Fatal(r)
	}
	f.advance(time.Second)
	event := lifecycleObservation{SessionID: f.sessionID, TurnID: f.turnID, ToolUseID: f.toolUseID, TranscriptPath: f.transcriptPath, Event: "PostToolUse"}
	f.core.observeLifecycle(event, f.hookPeer)
	newPeer := cloneProcessChain(f.requestPeer)
	newPeer.Nodes[1].StartSeconds = uint64(f.current.Add(time.Second).Unix())
	if r := f.core.registerLatestExecutionRoot(f.sessionID, "direct", newPeer); r.Accepted {
		t.Fatal("completed observation claimed a later process")
	}
	// exec can replace the shell image without changing the execution identity.
	oldPeer := cloneProcessChain(f.requestPeer)
	oldPeer.Nodes[1].Path, oldPeer.Roles[1] = "/usr/bin/python3", "other"
	if r := f.core.registerLatestExecutionRoot(f.sessionID, "direct", oldPeer); !r.Accepted {
		t.Fatal("running root lost after exec or a nonterminal tool return")
	}
}

func TestRemediationKernelLifetimeRejectsExitedProcessAndChangedStart(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "read line")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	identity, err := inspectProcess(cmd.Process.Pid)
	if err != nil || !kernelProcessAlive(identity) {
		t.Fatalf("kernel start not observed: %v", err)
	}
	reused := identity
	reused.StartMicroseconds++
	if kernelProcessAlive(reused) {
		t.Fatal("PID without exact start time accepted")
	}
	stdin.Close()
	_ = cmd.Wait()
	if kernelProcessAlive(identity) {
		t.Fatal("exited process remained live")
	}
}

func TestRemediationKernelExitReleasesObservationAndRawToolInput(t *testing.T) {
	f := newBrokerFixture(t)
	defer f.core.close()
	if r := f.registerPrimaryHost(); !r.Accepted {
		t.Fatal(r)
	}
	f.core.processAlive = func(p processIdentity) bool { return p.PID != f.executionPeer.Nodes[1].PID }
	assertEscalated(t, f.checkPrimaryRequest(), "execution-root-unverified")
	if len(f.core.contexts.tools) != 0 {
		t.Fatal("raw tool input survived process exit")
	}
}
