package main

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestApplicationProcessDecisionSkipsOnlyApplePlatformCLI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		process    applicationProcess
		selectCode bool
		continueUp bool
		wantError  bool
	}{
		{
			name: "platform CLI is transport",
			process: applicationProcess{
				CodeState: applicationCodeVerified, SignatureClass: applicationSignatureApplePlatform,
			},
			continueUp: true,
		},
		{
			name: "platform app is a principal",
			process: applicationProcess{
				CodeState: applicationCodeVerified, SignatureClass: applicationSignatureApplePlatform,
				AppBundle: true,
			},
			selectCode: true,
		},
		{
			name: "Developer ID CLI is a principal",
			process: applicationProcess{
				CodeState: applicationCodeVerified, SignatureClass: applicationSignatureDeveloperID,
				HardenedRuntime: true, CodeRuntimeVersion: 0x10000,
			},
			selectCode: true,
		},
		{
			name: "Mac App Store app is a principal",
			process: applicationProcess{
				CodeState: applicationCodeVerified, SignatureClass: applicationSignatureMacAppStore,
				AppBundle: true, HardenedRuntime: true, CodeRuntimeVersion: 0x10000,
			},
			selectCode: true,
		},
		{name: "unsigned is a barrier", process: applicationProcess{CodeState: applicationCodeUnsigned}, wantError: true},
		{name: "ad-hoc is a barrier", process: applicationProcess{CodeState: applicationCodeAdHoc}, wantError: true},
		{name: "invalid is a barrier", process: applicationProcess{CodeState: applicationCodeInvalid}, wantError: true},
		{
			name: "untrusted CMS signature is a barrier",
			process: applicationProcess{
				CodeState: applicationCodeUnsupportedSignature, SignatureClass: applicationSignatureUnknown,
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			selectCode, continueUp, err := applicationProcessDecision(test.process)
			if selectCode != test.selectCode || continueUp != test.continueUp || (err != nil) != test.wantError {
				t.Fatalf("decision = (%t, %t, %v), want (%t, %t, error=%t)",
					selectCode, continueUp, err, test.selectCode, test.continueUp, test.wantError)
			}
		})
	}
}

func TestApplicationPrincipalUsesOnlyVerifiedSigningIdentity(t *testing.T) {
	t.Parallel()
	process := applicationProcess{
		PID:                   101,
		ParentPID:             100,
		StartSeconds:          1_700_000_000,
		StartMicroseconds:     123,
		Path:                  "/Applications/Example.app/Contents/MacOS/Example",
		DisplayName:           "Example",
		SigningIdentifier:     "com.example.app",
		TeamIdentifier:        "EXAMPLETEAM",
		SignerName:            "Developer ID Application: Example, Inc. (EXAMPLETEAM)",
		DesignatedRequirement: []byte{0xfa, 0xde, 0x0c, 0x00, 0x01, 0x02, 0x03},
		SignatureClass:        applicationSignatureDeveloperID,
		CodeState:             applicationCodeVerified,
		AppBundle:             true,
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
		CodeDirectoryHash:     bytesOf(0x11, minimumCodeDirectoryHashSize),
	}
	identity, err := identityForApplicationProcess(process)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Application != "Example" || identity.Source != "process-ancestry" ||
		identity.Assurance != "verified-code-signature" || identity.Platform != "macos" ||
		identity.PrincipalScheme != "macos-designated-requirement-v1" ||
		identity.SigningIdentifier != process.SigningIdentifier ||
		identity.TeamIdentifier != process.TeamIdentifier || identity.PrincipalID == "" {
		t.Fatalf("unexpected application identity: %+v", identity)
	}

	changedObservation := process
	changedObservation.PID++
	changedObservation.StartSeconds++
	changedObservation.Path = "/tmp/renamed"
	changedObservation.DisplayName = "Renamed"
	changedIdentity, err := identityForApplicationProcess(changedObservation)
	if err != nil {
		t.Fatal(err)
	}
	if changedIdentity.PrincipalID != identity.PrincipalID {
		t.Fatal("display or process-lifetime metadata changed the stable principal")
	}

	mutations := []applicationProcess{
		func() applicationProcess { value := process; value.TeamIdentifier = "OTHERTEAM"; return value }(),
		func() applicationProcess {
			value := process
			value.SigningIdentifier = "com.example.other"
			return value
		}(),
		func() applicationProcess {
			value := process
			value.DesignatedRequirement = []byte{1, 2, 3}
			return value
		}(),
		func() applicationProcess {
			value := process
			value.SignatureClass = applicationSignatureMacAppStore
			return value
		}(),
	}
	for index, mutation := range mutations {
		mutatedIdentity, mutationErr := identityForApplicationProcess(mutation)
		if mutationErr != nil {
			t.Fatalf("mutation %d failed unexpectedly: %v", index, mutationErr)
		}
		if mutatedIdentity.PrincipalID == identity.PrincipalID {
			t.Fatalf("security identity mutation %d retained the principal", index)
		}
	}
}

func TestApplicationPrincipalGoldenVector(t *testing.T) {
	t.Parallel()
	principal, err := applicationPrincipalID(
		applicationSignatureDeveloperID,
		"2DC432GLL2",
		"codex",
		[]byte{0xfa, 0xde, 0x0c, 0x00, 0x00, 0x01},
	)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "SDIMmLxPD9tJghJm7zwVCl0ctD5va-lafrxjwChkIN4"
	if principal != expected {
		t.Fatalf("principal = %q, want %q", principal, expected)
	}
}

func TestApplicationIdentityFailsClosedOnIncompleteOrUnsafeFields(t *testing.T) {
	t.Parallel()
	valid := applicationProcess{
		Path:                  "/usr/local/bin/example",
		SigningIdentifier:     "com.example.cli",
		TeamIdentifier:        "EXAMPLETEAM",
		DesignatedRequirement: []byte{1},
		SignatureClass:        applicationSignatureDeveloperID,
		CodeState:             applicationCodeVerified,
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
		CodeDirectoryHash:     bytesOf(0x22, minimumCodeDirectoryHashSize),
	}
	tests := []struct {
		name   string
		mutate func(*applicationProcess)
	}{
		{name: "missing signing identifier", mutate: func(value *applicationProcess) { value.SigningIdentifier = "" }},
		{name: "missing Team identifier", mutate: func(value *applicationProcess) { value.TeamIdentifier = "" }},
		{name: "missing designated requirement", mutate: func(value *applicationProcess) { value.DesignatedRequirement = nil }},
		{name: "control character", mutate: func(value *applicationProcess) { value.SigningIdentifier = "com.example\nforged" }},
		{name: "not verified", mutate: func(value *applicationProcess) { value.CodeState = applicationCodeAdHoc }},
		{name: "not hardened", mutate: func(value *applicationProcess) { value.HardenedRuntime = false }},
		{name: "missing CDHash", mutate: func(value *applicationProcess) { value.CodeDirectoryHash = nil }},
		{name: "dangerous entitlement", mutate: func(value *applicationProcess) {
			value.DangerousEntitlements = dangerousCodeEntitlementGetTaskAllow
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := valid
			test.mutate(&value)
			if identity, err := identityForApplicationProcess(value); err == nil {
				t.Fatalf("unsafe evidence produced identity %+v", identity)
			}
		})
	}

	platform := valid
	platform.SignatureClass = applicationSignatureApplePlatform
	platform.TeamIdentifier = ""
	if _, err := identityForApplicationProcess(platform); err != nil {
		t.Fatalf("Apple platform identity incorrectly required a Team identifier: %v", err)
	}
}

func TestApplicationIdentityDisplayFallbackIsAdvisoryAndSanitized(t *testing.T) {
	t.Parallel()
	process := applicationProcess{
		Path:                  "/opt/tools/example-cli",
		DisplayName:           "Bad\nName",
		SigningIdentifier:     "com.example.cli",
		TeamIdentifier:        "EXAMPLETEAM",
		DesignatedRequirement: []byte{1, 2, 3},
		SignatureClass:        applicationSignatureDeveloperID,
		CodeState:             applicationCodeVerified,
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
		CodeDirectoryHash:     bytesOf(0x33, minimumCodeDirectoryHashSize),
	}
	identity, err := identityForApplicationProcess(process)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Application != "example-cli" {
		t.Fatalf("display fallback = %q, want example-cli", identity.Application)
	}
	process.Path = ""
	identity, err = identityForApplicationProcess(process)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Application != "com.example.cli" {
		t.Fatalf("signing identifier fallback = %q", identity.Application)
	}
}

func TestOneNodTransportRequiresExactAuthorizedHardenedAdHocIdentity(t *testing.T) {
	t.Parallel()
	helperProcess := validAdHocTransportProcess(
		oneNodHelperSigningIdentifier, 0x41,
	)
	helper, err := helperCodeIdentity(helperProcess)
	if err != nil {
		t.Fatal(err)
	}
	mayProcess := validAdHocTransportProcess(oneNodMaySigningIdentifier, 0x42)
	mayProcess.Path = "/arbitrary/location/not/an/authorization/boundary"
	may, err := oneNodTransportCodeIdentity(
		mayProcess, helper, oneNodMaySigningIdentifier,
	)
	if err != nil {
		t.Fatal(err)
	}
	if may.Kind != transportCodeKindMay || may.PolicyVersion != transportRuntimePolicyVersion ||
		may.TeamIdentifier != "" || may.SignatureClass != applicationSignatureAdHoc {
		t.Fatalf("unexpected transport identity: %+v", may)
	}
	if isTransparentOneNodTransport(
		mayProcess, helper, authorizedTransportSet{},
	) {
		t.Fatal("unrecorded exact identity was trusted")
	}
	stagedOnly := authorizedTransportSet{Staged: []transportCodeIdentity{may}}
	if stagedOnly.authorizes(may) || !stagedOnly.stages(may) ||
		isTransparentOneNodTransport(mayProcess, helper, stagedOnly) {
		t.Fatal("staged identity obtained normal transport authority")
	}
	current := authorizedTransportSet{Current: []transportCodeIdentity{may}}
	if !current.authorizes(may) || !isTransparentOneNodTransport(mayProcess, helper, current) {
		t.Fatal("current exact identity was not authorized")
	}
	oversized := authorizedTransportSet{
		Current: make([]transportCodeIdentity, maximumAuthorizedTransportCount+1),
	}
	for index := range oversized.Current {
		oversized.Current[index] = may
	}
	if oversized.authorizes(may) {
		t.Fatal("oversized persisted authorization set was accepted")
	}

	changedPath := mayProcess
	changedPath.Path = "/another/path"
	if !isTransparentOneNodTransport(changedPath, helper, current) {
		t.Fatal("diagnostic path incorrectly changed exact code authorization")
	}
	changedBuild := mayProcess
	changedBuild.CodeDirectoryHash = bytesOf(0x43, minimumCodeDirectoryHashSize)
	if isTransparentOneNodTransport(changedBuild, helper, current) {
		t.Fatal("different exact build inherited transport authorization")
	}
}

func TestOneNodTransportPolicyRejectsUnsafeOrAmbiguousCode(t *testing.T) {
	t.Parallel()
	helperProcess := validAdHocTransportProcess(oneNodHelperSigningIdentifier, 0x51)
	helper, err := helperCodeIdentity(helperProcess)
	if err != nil {
		t.Fatal(err)
	}
	valid := validAdHocTransportProcess(oneNodMaySigningIdentifier, 0x52)
	if identity, err := newTransportCodeIdentity(
		valid, transportCodeKindSSHSign, oneNodMaySigningIdentifier,
	); err == nil {
		t.Fatalf("mismatched role kind produced transport identity %+v", identity)
	}
	tests := []struct {
		name   string
		mutate func(*applicationProcess)
	}{
		{name: "linker signature", mutate: func(value *applicationProcess) { value.LinkerSigned = true }},
		{name: "not hardened", mutate: func(value *applicationProcess) { value.HardenedRuntime = false }},
		{name: "missing runtime version", mutate: func(value *applicationProcess) { value.CodeRuntimeVersion = 0 }},
		{name: "get-task-allow entitlement", mutate: func(value *applicationProcess) {
			value.DangerousEntitlements = dangerousCodeEntitlementGetTaskAllow
		}},
		{name: "JIT exception", mutate: func(value *applicationProcess) {
			value.DangerousEntitlements = dangerousCodeEntitlementAllowJIT
		}},
		{name: "unsigned executable memory exception", mutate: func(value *applicationProcess) {
			value.DangerousEntitlements = dangerousCodeEntitlementAllowUnsignedExecutableMemory
		}},
		{name: "wrong identifier", mutate: func(value *applicationProcess) {
			value.SigningIdentifier = oneNodSSHSignSigningIdentifier
		}},
		{name: "Team identifier present", mutate: func(value *applicationProcess) { value.TeamIdentifier = "TEAM" }},
		{name: "Developer ID instead of ad-hoc", mutate: func(value *applicationProcess) {
			value.SignatureClass = applicationSignatureDeveloperID
			value.CodeState = applicationCodeVerified
		}},
		{name: "short CDHash", mutate: func(value *applicationProcess) { value.CodeDirectoryHash = []byte{1} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			process := valid
			test.mutate(&process)
			if identity, err := oneNodTransportCodeIdentity(
				process, helper, oneNodMaySigningIdentifier,
			); err == nil {
				t.Fatalf("unsafe code produced transport identity %+v", identity)
			}
		})
	}

	unsafeHelper := helperProcess
	unsafeHelper.DangerousEntitlements = dangerousCodeEntitlementGetTaskAllow
	if identity, err := helperCodeIdentity(unsafeHelper); err == nil {
		t.Fatalf("unsafe helper produced exact identity %+v", identity)
	}
}

func TestOneNodTransportEntitlementsAreRestrictedByRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		kind         transportCodeKind
		identifier   string
		entitlements uint32
		wantAllowed  bool
	}{
		{
			name: "helper without entitlements", kind: transportCodeKindHelper,
			identifier: oneNodHelperSigningIdentifier, wantAllowed: true,
		},
		{
			name: "helper with library validation disabled", kind: transportCodeKindHelper,
			identifier:   oneNodHelperSigningIdentifier,
			entitlements: dangerousCodeEntitlementDisableLibraryValidation,
		},
		{
			name: "may without entitlements", kind: transportCodeKindMay,
			identifier: oneNodMaySigningIdentifier, wantAllowed: true,
		},
		{
			name: "may with only library validation disabled", kind: transportCodeKindMay,
			identifier:   oneNodMaySigningIdentifier,
			entitlements: dangerousCodeEntitlementDisableLibraryValidation,
			wantAllowed:  true,
		},
		{
			name: "may with library validation and another exception", kind: transportCodeKindMay,
			identifier: oneNodMaySigningIdentifier,
			entitlements: dangerousCodeEntitlementDisableLibraryValidation |
				dangerousCodeEntitlementGetTaskAllow,
		},
		{
			name: "may with an unknown runtime exception", kind: transportCodeKindMay,
			identifier:   oneNodMaySigningIdentifier,
			entitlements: dangerousCodeEntitlementUnknownRuntimeException,
		},
		{
			name: "may with malformed entitlements", kind: transportCodeKindMay,
			identifier:   oneNodMaySigningIdentifier,
			entitlements: dangerousCodeEntitlementMalformed,
		},
		{
			name: "SSH adapter without entitlements", kind: transportCodeKindSSHSign,
			identifier: oneNodSSHSignSigningIdentifier, wantAllowed: true,
		},
		{
			name: "SSH adapter with library validation disabled", kind: transportCodeKindSSHSign,
			identifier:   oneNodSSHSignSigningIdentifier,
			entitlements: dangerousCodeEntitlementDisableLibraryValidation,
		},
		{
			name: "unknown role", kind: transportCodeKind("future-role"),
			identifier: oneNodMaySigningIdentifier,
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			process := validAdHocTransportProcess(test.identifier, byte(0x60+index))
			process.DangerousEntitlements = test.entitlements
			identity, err := newTransportCodeIdentity(process, test.kind, test.identifier)
			if test.wantAllowed {
				if err != nil {
					t.Fatalf("allowed role policy was rejected: %v", err)
				}
				wantPolicy := uint32(transportRuntimePolicyVersion)
				if test.kind == transportCodeKindMay &&
					test.entitlements == dangerousCodeEntitlementDisableLibraryValidation {
					wantPolicy = transportConstrainedDLVPolicyVersion
				}
				if identity.Kind != test.kind || identity.PolicyVersion != wantPolicy {
					t.Fatalf("identity = %+v, want kind %q policy %d", identity, test.kind, wantPolicy)
				}
				return
			}
			if err == nil {
				t.Fatalf("disallowed role policy produced identity %+v", identity)
			}
		})
	}
}

func TestOneNodTransportLibraryConstraintIsBoundToPolicyVersion(t *testing.T) {
	t.Parallel()
	legacy := testTransportIdentity(transportCodeKindMay, 0x71)
	constrained := legacy
	constrained.PolicyVersion = transportConstrainedDLVPolicyVersion
	exactBlob, err := hex.DecodeString(
		"fade8181000000a1708196020101b0819030090c0463636174020100" +
			"30090c04636f6d70020101306d0c0472657173b065302a0c127369676e696e672d" +
			"6964656e7469666965720c146c69626f705f73646b5f6970635f636c69656e74" +
			"301d0c0f7465616d2d6964656e7469666965720c0a3242554138433453324330" +
			"180c1376616c69646174696f6e2d63617465676f727902010630090c04766572" +
			"73020101",
	)
	if err != nil || len(exactBlob) != transportOnePasswordConstraintSize {
		t.Fatalf("decode canonical signed LWCR: length=%d error=%v", len(exactBlob), err)
	}

	if !transportLibraryConstraintAllowed(legacy, nil) ||
		transportLibraryConstraintAllowed(legacy, exactBlob) {
		t.Fatal("legacy transport policy did not require an absent library constraint")
	}
	if !transportLibraryConstraintAllowed(constrained, exactBlob) ||
		transportLibraryConstraintAllowed(constrained, nil) ||
		transportLibraryConstraintAllowed(constrained, exactBlob[:len(exactBlob)-1]) {
		t.Fatal("constrained transport policy accepted the wrong library constraint shape")
	}
	if !validTransportCodeIdentityShape(constrained, transportCodeKindMay) {
		t.Fatal("constrained may identity did not survive stored-state validation")
	}
	invalidPolicy := constrained
	invalidPolicy.PolicyVersion++
	if validTransportCodeIdentityShape(invalidPolicy, transportCodeKindMay) {
		t.Fatal("unknown transport policy version survived stored-state validation")
	}
	changed := append([]byte(nil), exactBlob...)
	changed[len(changed)-1] ^= 1
	if transportLibraryConstraintAllowed(constrained, changed) {
		t.Fatal("constrained transport policy accepted a different signed LWCR")
	}
	constrainedAdapter := testTransportIdentity(transportCodeKindSSHSign, 0x72)
	constrainedAdapter.PolicyVersion = transportConstrainedDLVPolicyVersion
	if transportLibraryConstraintAllowed(constrainedAdapter, exactBlob) ||
		validTransportCodeIdentityShape(constrainedAdapter, transportCodeKindSSHSign) {
		t.Fatal("SSH adapter accepted the may-only constrained policy")
	}
}

func TestThirdPartyRuntimePolicySeparatesExternalInjectionFromJIT(t *testing.T) {
	t.Parallel()
	valid := applicationProcess{
		CodeState:          applicationCodeVerified,
		SignatureClass:     applicationSignatureDeveloperID,
		HardenedRuntime:    true,
		CodeRuntimeVersion: 0x10000,
	}
	if !applicationProcessMeetsRuntimePolicy(valid) {
		t.Fatal("safe hardened Developer ID app was rejected")
	}
	for _, entitlement := range []uint32{
		dangerousCodeEntitlementGetTaskAllow,
		dangerousCodeEntitlementDisableLibraryValidation,
		dangerousCodeEntitlementAllowDYLDEnvironmentVariables,
		dangerousCodeEntitlementDisableExecutablePageProtection,
		dangerousCodeEntitlementAllowRelativeLibraryLoads,
		dangerousCodeEntitlementDebugger,
		dangerousCodeEntitlementUnknownRuntimeException,
		dangerousCodeEntitlementMalformed,
	} {
		process := valid
		process.DangerousEntitlements = entitlement
		if applicationProcessMeetsRuntimePolicy(process) {
			t.Fatalf("dangerous entitlement mask %#x was accepted", entitlement)
		}
	}
	codexLike := valid
	codexLike.DangerousEntitlements = dangerousCodeEntitlementAllowJIT |
		dangerousCodeEntitlementAllowUnsignedExecutableMemory
	if !applicationProcessMeetsRuntimePolicy(codexLike) {
		t.Fatal("Codex/Electron-style internal JIT exceptions were treated as external injection")
	}
	codexLike.Path = "/Applications/ChatGPT.app/Contents/Resources/codex"
	codexLike.SigningIdentifier = "codex"
	codexLike.TeamIdentifier = "2DC432GLL2"
	codexLike.CodeDirectoryHash = bytesOf(0x7a, minimumCodeDirectoryHashSize)
	codexLike.DesignatedRequirement = []byte{0xfa, 0xde, 0x0c, 0x00, 0x7a}
	identity, err := identityForApplicationProcess(codexLike)
	if err != nil || identity.SigningIdentifier != "codex" ||
		identity.TeamIdentifier != "2DC432GLL2" {
		t.Fatalf("Codex-like signed application was not verified: identity=%+v error=%v",
			identity, err)
	}
	platform := valid
	platform.SignatureClass = applicationSignatureApplePlatform
	platform.HardenedRuntime = false
	platform.DangerousEntitlements = dangerousCodeEntitlementDisableLibraryValidation
	if !applicationProcessMeetsRuntimePolicy(platform) {
		t.Fatal("Apple platform policy was incorrectly treated as third-party code")
	}
}

func TestApplicationEvidenceAndLineageTimingFailClosed(t *testing.T) {
	t.Parallel()
	for _, evidence := range []string{applicationEvidenceParent, applicationEvidenceSSHPeer} {
		if err := validateApplicationEvidence(evidence); err != nil {
			t.Fatalf("valid evidence %q failed: %v", evidence, err)
		}
	}
	if err := validateApplicationEvidence("pid:42"); !errors.Is(err, errApplicationEvidenceInvalid) {
		t.Fatalf("caller-supplied PID evidence error = %v", err)
	}
	child := applicationProcess{StartSeconds: 100, StartMicroseconds: 50}
	if processStartedAfter(applicationProcess{StartSeconds: 100, StartMicroseconds: 49}, child) {
		t.Fatal("older parent was rejected")
	}
	if !processStartedAfter(applicationProcess{StartSeconds: 100, StartMicroseconds: 51}, child) {
		t.Fatal("parent created after child was accepted")
	}
	if !processStartedAfter(applicationProcess{StartSeconds: 101}, child) {
		t.Fatal("newer parent was accepted")
	}
}

func TestPrincipalFieldEncodingIsUnambiguous(t *testing.T) {
	t.Parallel()
	left := appendPrincipalField(nil, []byte("AB"))
	left = appendPrincipalField(left, []byte("C"))
	right := appendPrincipalField(nil, []byte("A"))
	right = appendPrincipalField(right, []byte("BC"))
	if string(left) == string(right) {
		t.Fatal("length-prefixed principal fields were ambiguous")
	}
	if strings.Contains(string(left[:4]), "AB") {
		t.Fatal("principal field length prefix was not emitted before the value")
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func validAdHocTransportProcess(identifier string, hashByte byte) applicationProcess {
	return applicationProcess{
		SigningIdentifier:     identifier,
		CodeDirectoryHash:     bytesOf(hashByte, minimumCodeDirectoryHashSize),
		DesignatedRequirement: []byte{0xfa, 0xde, 0x0c, hashByte},
		SignatureClass:        applicationSignatureAdHoc,
		CodeState:             applicationCodeAdHoc,
		HardenedRuntime:       true,
		CodeRuntimeVersion:    0x10000,
	}
}
