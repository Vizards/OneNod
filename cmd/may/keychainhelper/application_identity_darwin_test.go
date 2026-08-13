//go:build darwin && cgo

package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const testOnePasswordLibraryConstraintPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>team-identifier</key><string>2BUA8C4S2C</string>
<key>signing-identifier</key><string>libop_sdk_ipc_client</string>
<key>validation-category</key><integer>6</integer>
</dict></plist>`

func TestApplicationIdentityDarwinRejectsCurrentUnprovisionedTestProcess(t *testing.T) {
	process, err := inspectApplicationProcessByPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if process.CodeState != applicationCodeUnsigned && process.CodeState != applicationCodeAdHoc {
		t.Fatalf("test process code state = %d, want unsigned or ad-hoc", process.CodeState)
	}
	if selectProcess, continueAncestry, err := applicationProcessDecision(process); err == nil ||
		selectProcess || continueAncestry {
		t.Fatalf("unprovisioned test process was not an ancestry barrier: select=%t continue=%t error=%v",
			selectProcess, continueAncestry, err)
	}
	if identity, err := currentHelperTransportCodeIdentity(); err == nil {
		t.Fatalf("unprovisioned test helper became a trust root: %+v", identity)
	}
	if identity, err := resolveApplicationIdentity(applicationEvidenceParent); err == nil {
		t.Fatalf("unprovisioned test helper produced verified identity: %+v", identity)
	}
}

func TestApplicationIdentityDarwinRecognizesApplePlatformCLIAsTransport(t *testing.T) {
	command := exec.Command("/bin/sleep", "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	process, err := inspectApplicationProcessByPID(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if process.CodeState != applicationCodeVerified ||
		process.SignatureClass != applicationSignatureApplePlatform ||
		process.AppBundle || process.SigningIdentifier == "" ||
		len(process.DesignatedRequirement) == 0 {
		t.Fatalf("unexpected platform CLI evidence: %+v", process)
	}
	selectProcess, continueAncestry, err := applicationProcessDecision(process)
	if err != nil || selectProcess || !continueAncestry {
		t.Fatalf("platform CLI decision = (%t, %t, %v)",
			selectProcess, continueAncestry, err)
	}
}

func TestApplicationIdentityDarwinAcceptsOnlyServerSideNamedSocket(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "onenod-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socketPath := filepath.Join(directory, "agent.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })

	acceptedFile, err := accepted.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = acceptedFile.Close() })
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(acceptedFile.Fd()), socketPath,
	); err != nil {
		t.Fatalf("accepted fixed-path server socket was rejected: %v", err)
	}
	peerPID, err := applicationEvidenceStartPID(
		applicationEvidenceSSHPeer,
		applicationProcess{PID: 42, ParentPID: 1},
		func() (int, error) {
			return acceptedSSHPeerPIDAtPathForTesting(
				int(acceptedFile.Fd()), socketPath,
			)
		},
	)
	if err != nil {
		t.Fatalf("LaunchAgent-shaped SSH transport rejected valid peer evidence: %v", err)
	}
	if peerPID != os.Getpid() {
		t.Fatalf("SSH peer PID = %d, want current test process %d", peerPID, os.Getpid())
	}
	if _, err := applicationEvidenceStartPID(
		applicationEvidenceParent,
		applicationProcess{PID: 42, ParentPID: 1},
		func() (int, error) {
			t.Fatal("parent evidence consulted the SSH peer")
			return 0, nil
		},
	); err == nil {
		t.Fatal("parent evidence accepted a transport without a stable parent")
	}
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(acceptedFile.Fd()), socketPath+"\x00forged",
	); err == nil {
		t.Fatal("socket path containing NUL was accepted")
	}
	listenerFile, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listenerFile.Close() })
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(listenerFile.Fd()), socketPath,
	); err == nil {
		t.Fatal("listening socket was accepted as an established peer")
	}

	clientFile, err := client.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientFile.Close() })
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(clientFile.Fd()), socketPath,
	); err == nil {
		t.Fatal("outbound client side of the fixed-path socket was accepted")
	}
	boundClientPath := filepath.Join(directory, "bound-client.sock")
	boundClient, err := net.DialUnix(
		"unix",
		&net.UnixAddr{Name: boundClientPath, Net: "unix"},
		&net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boundClient.Close() })
	boundAccepted, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boundAccepted.Close() })
	boundAcceptedFile, err := boundAccepted.File()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = boundAcceptedFile.Close() })
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(boundAcceptedFile.Fd()), socketPath,
	); err == nil {
		t.Fatal("accepted socket with a named peer was accepted")
	}

	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(pair[0])
		_ = unix.Close(pair[1])
	})
	for index, descriptor := range pair {
		if err := validateAcceptedSSHPeerSocketForTesting(
			descriptor, socketPath,
		); err == nil {
			t.Fatalf("socketpair endpoint %d was accepted", index)
		}
	}
	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := validateAcceptedSSHPeerSocketForTesting(
		int(acceptedFile.Fd()), socketPath,
	); err == nil {
		t.Fatal("socket path with group/world permissions was accepted")
	}
}

func TestSSHResolverAcceptsLaunchAgentTransportWhileParentEvidenceStillFails(t *testing.T) {
	helperIdentity := testTransportIdentity(transportCodeKindHelper, 0x31)
	directIdentity := testTransportIdentity(transportCodeKindMay, 0x32)
	directProcess := validAdHocTransportProcess(oneNodMaySigningIdentifier, 0x32)
	directProcess.PID = 42
	directProcess.ParentPID = 1
	application := applicationProcess{
		PID: 123, ParentPID: 1,
		Path:                  "/Applications/Verified.app/Contents/MacOS/verified",
		DisplayName:           "Verified",
		SigningIdentifier:     "com.example.verified",
		TeamIdentifier:        "TEAM123456",
		SignerName:            "Developer ID Application: Example",
		DesignatedRequirement: []byte{0xfa, 0xde, 0x0c, 0x00},
		CodeDirectoryHash:     bytes.Repeat([]byte{0x33}, minimumCodeDirectoryHashSize),
		SignatureClass:        applicationSignatureDeveloperID,
		CodeState:             applicationCodeVerified,
		AppBundle:             true,
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
	}

	previousDirectResolver := applicationDirectTransportEvidenceResolver
	previousPeerResolver := applicationSSHPeerEvidenceResolver
	t.Cleanup(func() {
		applicationDirectTransportEvidenceResolver = previousDirectResolver
		applicationSSHPeerEvidenceResolver = previousPeerResolver
	})
	peerCalls := 0
	revalidations := 0
	applicationDirectTransportEvidenceResolver = func(
		authorized authorizedTransportSet,
	) (applicationDirectTransportEvidence, error) {
		if !authorized.authorizes(directIdentity) {
			t.Fatal("resolver did not receive the current exact transport")
		}
		return applicationDirectTransportEvidence{
			helperIdentity: helperIdentity,
			process:        directProcess,
			inspectProcess: func(pid, depth int) (applicationProcess, error) {
				t.Fatalf("resolver unexpectedly used ordinary PID inspection for pid=%d depth=%d", pid, depth)
				return applicationProcess{}, nil
			},
			revalidateDirect: func() error {
				revalidations++
				return nil
			},
		}, nil
	}
	applicationSSHPeerEvidenceResolver = func() (applicationSSHPeerEvidence, error) {
		peerCalls++
		return applicationSSHPeerEvidence{
			pid: application.PID,
			inspectProcess: func() (applicationProcess, error) {
				return application, nil
			},
		}, nil
	}
	authorized := authorizedTransportSet{Current: []transportCodeIdentity{directIdentity}}
	identity, err := resolveApplicationIdentityWithAuthorizedTransports(
		applicationEvidenceSSHPeer, authorized,
	)
	if err != nil || identity.Application != application.DisplayName ||
		peerCalls != 1 || revalidations != 1 {
		t.Fatalf("LaunchAgent SSH resolver failed: identity=%+v peer=%d revalidate=%d error=%v",
			identity, peerCalls, revalidations, err)
	}
	peerCalls = 0
	if _, err := resolveApplicationIdentityWithAuthorizedTransports(
		applicationEvidenceParent, authorized,
	); err == nil || peerCalls != 0 {
		t.Fatalf("parent evidence accepted PID-1 transport or consulted SSH peer: calls=%d error=%v", peerCalls, err)
	}
}

func TestTransportCodeIdentityAtFileRequiresExplicitHardenedAdHocRole(t *testing.T) {
	directory := t.TempDir()
	templateSource := filepath.Join(directory, "template.go")
	templateBinary := filepath.Join(directory, "template")
	if err := os.WriteFile(
		templateSource, []byte("package main\nfunc main() {}\n"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(
		"go", "build", "-o", templateBinary, templateSource,
	).CombinedOutput(); err != nil {
		t.Fatalf("build thin transport candidate: %v: %s", err, output)
	}
	makeCandidate := func(name, identifier string, entitlements, libraryConstraint []byte) *os.File {
		t.Helper()
		path := filepath.Join(directory, name)
		if output, err := exec.Command("/bin/cp", templateBinary, path).CombinedOutput(); err != nil {
			t.Fatalf("copy candidate: %v: %s", err, output)
		}
		arguments := []string{
			"--force", "--sign", "-", "--options", "runtime",
			"--identifier", identifier,
		}
		if entitlements != nil {
			entitlementsPath := filepath.Join(directory, name+".entitlements.plist")
			if err := os.WriteFile(entitlementsPath, entitlements, 0o600); err != nil {
				t.Fatal(err)
			}
			arguments = append(arguments, "--entitlements", entitlementsPath)
		}
		if libraryConstraint != nil {
			constraintPath := filepath.Join(directory, name+".library-constraint.plist")
			if err := os.WriteFile(constraintPath, libraryConstraint, 0o600); err != nil {
				t.Fatal(err)
			}
			arguments = append(arguments, "--library-constraint", constraintPath)
		}
		arguments = append(arguments, path)
		if output, err := exec.Command("/usr/bin/codesign", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("sign candidate: %v: %s", err, output)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}

	mayFile := makeCandidate("may", oneNodMaySigningIdentifier, nil, nil)
	identity, err := transportCodeIdentityAtFile(mayFile, transportCodeKindMay)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Kind != transportCodeKindMay ||
		identity.SigningIdentifier != oneNodMaySigningIdentifier ||
		identity.SignatureClass != applicationSignatureAdHoc ||
		identity.TeamIdentifier != "" || !identity.HardenedRuntime ||
		identity.CodeRuntimeVersion == 0 ||
		len(identity.CodeDirectoryHash) < minimumCodeDirectoryHashSize ||
		len(identity.DesignatedRequirement) == 0 {
		t.Fatalf("unexpected static transport identity: %+v", identity)
	}
	if _, err := transportCodeIdentityAtFile(mayFile, transportCodeKindSSHSign); err == nil {
		t.Fatal("may candidate was accepted for the may-ssh-sign role")
	}
	writableMay, err := os.OpenFile(mayFile.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writableMay.Close() })
	if _, err := transportCodeIdentityAtFile(writableMay, transportCodeKindMay); err == nil {
		t.Fatal("writable staged descriptor was accepted")
	}
	helperFile := makeCandidate("helper", oneNodHelperSigningIdentifier, nil, nil)
	helperIdentity, err := transportCodeIdentityAtFile(helperFile, transportCodeKindHelper)
	if err != nil || helperIdentity.Kind != transportCodeKindHelper {
		t.Fatalf("valid helper candidate was rejected: identity=%+v error=%v", helperIdentity, err)
	}
	sshSignFile := makeCandidate("may-ssh-sign", oneNodSSHSignSigningIdentifier, nil, nil)
	sshSignIdentity, err := transportCodeIdentityAtFile(sshSignFile, transportCodeKindSSHSign)
	if err != nil || sshSignIdentity.Kind != transportCodeKindSSHSign {
		t.Fatalf("valid SSH adapter candidate was rejected: identity=%+v error=%v", sshSignIdentity, err)
	}

	disabledLibraryValidation := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>`)
	dlvMayFile := makeCandidate(
		"dlv-may", oneNodMaySigningIdentifier, disabledLibraryValidation,
		[]byte(testOnePasswordLibraryConstraintPlist),
	)
	if identity, err := transportCodeIdentityAtFile(
		dlvMayFile, transportCodeKindMay,
	); err != nil || identity.Kind != transportCodeKindMay ||
		identity.PolicyVersion != transportConstrainedDLVPolicyVersion {
		t.Fatalf("may candidate with the role-specific DLV entitlement was rejected: identity=%+v error=%v", identity, err)
	}
	dlvWithoutConstraint := makeCandidate(
		"dlv-without-constraint", oneNodMaySigningIdentifier,
		disabledLibraryValidation, nil,
	)
	if _, err := transportCodeIdentityAtFile(
		dlvWithoutConstraint, transportCodeKindMay,
	); err == nil {
		t.Fatal("DLV may candidate without the exact library constraint was accepted")
	}
	wrongConstraint := []byte(strings.ReplaceAll(
		testOnePasswordLibraryConstraintPlist,
		"libop_sdk_ipc_client", "libop_sdk_lib_core",
	))
	dlvWithWrongConstraint := makeCandidate(
		"dlv-with-wrong-constraint", oneNodMaySigningIdentifier,
		disabledLibraryValidation, wrongConstraint,
	)
	if _, err := transportCodeIdentityAtFile(
		dlvWithWrongConstraint, transportCodeKindMay,
	); err == nil {
		t.Fatal("DLV may candidate with a different library constraint was accepted")
	}
	constraintWithoutDLV := makeCandidate(
		"constraint-without-dlv", oneNodMaySigningIdentifier, nil,
		[]byte(testOnePasswordLibraryConstraintPlist),
	)
	if _, err := transportCodeIdentityAtFile(
		constraintWithoutDLV, transportCodeKindMay,
	); err == nil {
		t.Fatal("legacy may candidate with an unexpected library constraint was accepted")
	}
	dlvHelperFile := makeCandidate(
		"dlv-helper", oneNodHelperSigningIdentifier, disabledLibraryValidation,
		[]byte(testOnePasswordLibraryConstraintPlist),
	)
	if _, err := transportCodeIdentityAtFile(
		dlvHelperFile, transportCodeKindHelper,
	); err == nil {
		t.Fatal("helper candidate with the may-only DLV entitlement was accepted")
	}
	dlvSSHSignFile := makeCandidate(
		"dlv-may-ssh-sign", oneNodSSHSignSigningIdentifier,
		disabledLibraryValidation, []byte(testOnePasswordLibraryConstraintPlist),
	)
	if _, err := transportCodeIdentityAtFile(
		dlvSSHSignFile, transportCodeKindSSHSign,
	); err == nil {
		t.Fatal("SSH adapter candidate with the may-only DLV entitlement was accepted")
	}
	dlvAndGetTaskAllowFile := makeCandidate(
		"dlv-and-get-task-allow-may", oneNodMaySigningIdentifier,
		[]byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.cs.disable-library-validation</key><true/>
<key>com.apple.security.get-task-allow</key><true/>
</dict></plist>`), []byte(testOnePasswordLibraryConstraintPlist),
	)
	if _, err := transportCodeIdentityAtFile(
		dlvAndGetTaskAllowFile, transportCodeKindMay,
	); err == nil {
		t.Fatal("may candidate with DLV plus another runtime exception was accepted")
	}
	unknownExceptionFile := makeCandidate(
		"unknown-exception-may", oneNodMaySigningIdentifier,
		[]byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.cs.future-injection-exception</key><true/>
</dict></plist>`), nil,
	)
	if _, err := transportCodeIdentityAtFile(
		unknownExceptionFile, transportCodeKindMay,
	); err == nil {
		t.Fatal("candidate with an unknown runtime exception was accepted")
	}

	currentExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	linkerSigned, err := os.Open(currentExecutable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = linkerSigned.Close() })
	if _, err := transportCodeIdentityAtFile(linkerSigned, transportCodeKindHelper); err == nil {
		t.Fatal("Go linker-generated ad-hoc code was accepted as an explicit helper build")
	}
}

func TestDynamicTransportIdentityMatchesSameExplicitAdHocBuild(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "may")
	sourcePath := filepath.Join(directory, "main.go")
	if err := os.WriteFile(sourcePath, []byte(`package main
import "time"
func main() { time.Sleep(30 * time.Second) }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("go", "build", "-o", path, sourcePath).CombinedOutput(); err != nil {
		t.Fatalf("build candidate: %v: %s", err, output)
	}
	entitlementsPath := filepath.Join(directory, "may.entitlements.plist")
	if err := os.WriteFile(entitlementsPath, []byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>`), 0o600); err != nil {
		t.Fatal(err)
	}
	constraintPath := filepath.Join(directory, "may.library-constraint.plist")
	if err := os.WriteFile(
		constraintPath, []byte(testOnePasswordLibraryConstraintPlist), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(
		"/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime",
		"--identifier", oneNodMaySigningIdentifier,
		"--entitlements", entitlementsPath,
		"--library-constraint", constraintPath, path,
	).CombinedOutput(); err != nil {
		t.Fatalf("sign candidate: %v: %s", err, output)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	staticIdentity, err := transportCodeIdentityAtFile(file, transportCodeKindMay)
	if err != nil {
		t.Fatal(err)
	}

	command := exec.Command(path)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	process, err := inspectApplicationProcessByPID(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if process.DangerousEntitlements != dangerousCodeEntitlementDisableLibraryValidation {
		t.Fatalf("dynamic DLV mask = %#x, want only DLV", process.DangerousEntitlements)
	}
	dynamicIdentity, err := newTransportCodeIdentity(
		process, transportCodeKindMay, oneNodMaySigningIdentifier,
	)
	if err != nil {
		t.Fatalf("dynamic explicit ad-hoc process was rejected: %v; process=%+v", err, process)
	}
	if !sameTransportCodeIdentity(staticIdentity, dynamicIdentity) {
		t.Fatalf("static and dynamic exact identities differ:\nstatic=%+v\ndynamic=%+v",
			staticIdentity, dynamicIdentity)
	}
}

// This compatibility probe intentionally binds to a locally installed third-party
// application. It is useful during attended acceptance, not as a deterministic
// unit test or a security trust root.
func TestDarwinInspectsCodexLikeDeveloperIDRuntimePolicy(t *testing.T) {
	if os.Getenv("ONENOD_RUN_INSTALLED_APP_IDENTITY_PROBE") != "1" {
		t.Skip("installed application identity probe is opt-in")
	}
	const codexPath = "/Applications/ChatGPT.app/Contents/Resources/codex"
	if _, err := os.Stat(codexPath); err != nil {
		t.Skipf("Codex binary is unavailable: %v", err)
	}
	command := exec.Command(codexPath, "--version")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(command.Process.Pid, unix.SIGSTOP); err != nil {
		_ = command.Wait()
		t.Skipf("Codex exited before it could be stopped: %v", err)
	}
	t.Cleanup(func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	})
	process, err := inspectApplicationProcessByPID(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if process.SignatureClass != applicationSignatureDeveloperID ||
		process.TeamIdentifier != "2DC432GLL2" ||
		process.SigningIdentifier != "codex" || !process.HardenedRuntime ||
		process.DangerousEntitlements&dangerousCodeEntitlementAllowJIT == 0 ||
		process.DangerousEntitlements&dangerousCodeEntitlementAllowUnsignedExecutableMemory == 0 ||
		!applicationProcessMeetsRuntimePolicy(process) {
		t.Fatalf("unexpected Codex dynamic code policy: %+v", process)
	}
}
