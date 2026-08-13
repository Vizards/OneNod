package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	applicationEvidenceParent  = "parent"
	applicationEvidenceSSHPeer = "ssh-peer"

	applicationPrincipalScheme   = "macos-designated-requirement-v1"
	applicationIdentitySource    = "process-ancestry"
	applicationIdentityPlatform  = "macos"
	applicationIdentityAssurance = "verified-code-signature"

	maximumApplicationAncestryDepth      = 16
	maximumDesignatedRequirementSize     = 64 * 1024
	minimumCodeDirectoryHashSize         = 20
	maximumCodeDirectoryHashSize         = 64
	maximumAuthorizedTransportCount      = 8
	transportRuntimePolicyVersion        = 1
	transportConstrainedDLVPolicyVersion = 2
	transportOnePasswordConstraintSize   = 161
	transportOnePasswordConstraintSHA256 = "\x87\x7d\x4e\x04\x7e\x1a\x24\x6c" +
		"\xc3\x0f\x54\xde\xbe\x56\x6a\xf3\x07\xed\x88\x51\x87\x6b\x5d\x20" +
		"\xf9\x06\xf8\x65\xe4\x1c\xc7\x5f"

	oneNodHelperSigningIdentifier  = "com.github.vizards.onenod.keychain-helper"
	oneNodMaySigningIdentifier     = "com.github.vizards.onenod.may"
	oneNodSSHSignSigningIdentifier = "com.github.vizards.onenod.may-ssh-sign"
)

const (
	dangerousCodeEntitlementGetTaskAllow uint32 = 1 << iota
	dangerousCodeEntitlementDisableLibraryValidation
	dangerousCodeEntitlementAllowDYLDEnvironmentVariables
	dangerousCodeEntitlementAllowJIT
	dangerousCodeEntitlementAllowUnsignedExecutableMemory
	dangerousCodeEntitlementDisableExecutablePageProtection
	dangerousCodeEntitlementAllowRelativeLibraryLoads
	dangerousCodeEntitlementDebugger
	dangerousCodeEntitlementUnknownRuntimeException
	dangerousCodeEntitlementMalformed
)

const applicationRejectedCodeEntitlements = dangerousCodeEntitlementGetTaskAllow |
	dangerousCodeEntitlementDisableLibraryValidation |
	dangerousCodeEntitlementAllowDYLDEnvironmentVariables |
	dangerousCodeEntitlementDisableExecutablePageProtection |
	dangerousCodeEntitlementAllowRelativeLibraryLoads |
	dangerousCodeEntitlementDebugger |
	dangerousCodeEntitlementUnknownRuntimeException |
	dangerousCodeEntitlementMalformed

type applicationIdentity struct {
	Application       string `json:"application"`
	Source            string `json:"source"`
	Assurance         string `json:"assurance"`
	Platform          string `json:"platform"`
	PrincipalScheme   string `json:"principal_scheme"`
	PrincipalID       string `json:"principal_id"`
	SigningIdentifier string `json:"signing_identifier"`
	TeamIdentifier    string `json:"team_identifier,omitempty"`
	SignerName        string `json:"signer_name,omitempty"`
}

type applicationSignatureClass uint8

const (
	applicationSignatureUnknown applicationSignatureClass = iota
	applicationSignatureApplePlatform
	applicationSignatureDeveloperID
	applicationSignatureMacAppStore
	applicationSignatureAdHoc
)

type applicationCodeState uint8

const (
	applicationCodeUnavailable applicationCodeState = iota
	applicationCodeVerified
	applicationCodeUnsigned
	applicationCodeAdHoc
	applicationCodeInvalid
	applicationCodeUnsupportedSignature
)

type applicationProcess struct {
	PID                   int
	ParentPID             int
	StartSeconds          uint64
	StartMicroseconds     uint64
	Path                  string
	DisplayName           string
	SigningIdentifier     string
	TeamIdentifier        string
	SignerName            string
	DesignatedRequirement []byte
	CodeDirectoryHash     []byte
	SignatureClass        applicationSignatureClass
	CodeState             applicationCodeState
	AppBundle             bool
	HardenedRuntime       bool
	LinkerSigned          bool
	CodeRuntimeVersion    uint32
	DangerousEntitlements uint32
}

type transportCodeKind string

const (
	transportCodeKindHelper  transportCodeKind = "keychain-helper"
	transportCodeKindMay     transportCodeKind = "may"
	transportCodeKindSSHSign transportCodeKind = "may-ssh-sign"
)

// transportCodeIdentity is an exact identity for one running OneNod binary.
// A fixed signing identifier establishes the role, while the CDHash and binary
// designated requirement bind observations to one explicitly ad-hoc-signed
// sealed build. Authorization comes from helper-protected current state. Paths,
// filesystem ownership, and the deliberately empty Team ID do not participate.
type transportCodeIdentity struct {
	Kind                  transportCodeKind         `json:"kind"`
	PolicyVersion         uint32                    `json:"runtime_policy_version"`
	SignatureClass        applicationSignatureClass `json:"signature_class"`
	SigningIdentifier     string                    `json:"signing_identifier"`
	TeamIdentifier        string                    `json:"team_identifier"`
	CodeDirectoryHash     []byte                    `json:"code_directory_hash"`
	DesignatedRequirement []byte                    `json:"designated_requirement"`
	HardenedRuntime       bool                      `json:"hardened_runtime"`
	CodeRuntimeVersion    uint32                    `json:"code_runtime_version"`
}

// authorizedTransportSet is loaded from helper-protected state. Merely having
// the logical signing identifier is not authorization: a running transport
// must exactly match a current CDHash and DR. Staged identities are separate.
type authorizedTransportSet struct {
	Current []transportCodeIdentity `json:"current"`
	Staged  []transportCodeIdentity `json:"staged,omitempty"`
}

var (
	errApplicationEvidenceInvalid     = errors.New("application evidence is invalid")
	errApplicationIdentityUnavailable = errors.New("verified macOS application identity is unavailable")
)

func validateApplicationEvidence(evidence string) error {
	if evidence != applicationEvidenceParent && evidence != applicationEvidenceSSHPeer {
		return errApplicationEvidenceInvalid
	}
	return nil
}

func applicationProcessDecision(process applicationProcess) (selectProcess, continueAncestry bool, err error) {
	switch process.CodeState {
	case applicationCodeVerified:
		if process.SignatureClass == applicationSignatureApplePlatform && !process.AppBundle {
			return false, true, nil
		}
		if process.SignatureClass == applicationSignatureUnknown {
			return false, false, errors.New("process ancestry reached an unsupported code signature")
		}
		if !applicationProcessMeetsRuntimePolicy(process) {
			return false, false, errors.New("process ancestry reached code without the required hardened runtime policy")
		}
		return true, false, nil
	case applicationCodeUnsigned:
		return false, false, errors.New("process ancestry reached unsigned code")
	case applicationCodeAdHoc:
		return false, false, errors.New("process ancestry reached ad-hoc signed code")
	case applicationCodeInvalid:
		return false, false, errors.New("process ancestry reached invalid or debugged code")
	case applicationCodeUnsupportedSignature:
		return false, false, errors.New("process ancestry reached an unsupported code signature")
	default:
		return false, false, errApplicationIdentityUnavailable
	}
}

func identityForApplicationProcess(process applicationProcess) (applicationIdentity, error) {
	if process.CodeState != applicationCodeVerified ||
		process.SignatureClass == applicationSignatureUnknown ||
		!applicationProcessMeetsRuntimePolicy(process) ||
		process.SigningIdentifier == "" ||
		!validCodeDirectoryHash(process.CodeDirectoryHash) ||
		len(process.DesignatedRequirement) == 0 ||
		len(process.DesignatedRequirement) > maximumDesignatedRequirementSize {
		return applicationIdentity{}, errApplicationIdentityUnavailable
	}
	if process.SignatureClass != applicationSignatureApplePlatform && process.TeamIdentifier == "" {
		return applicationIdentity{}, errors.New("verified distributed code has no Team identifier")
	}
	if !safeIdentityField(process.SigningIdentifier, 1024) ||
		(process.TeamIdentifier != "" && !safeIdentityField(process.TeamIdentifier, 128)) {
		return applicationIdentity{}, errors.New("code signature identity contains an invalid field")
	}
	principalID, err := applicationPrincipalID(
		process.SignatureClass,
		process.TeamIdentifier,
		process.SigningIdentifier,
		process.DesignatedRequirement,
	)
	if err != nil {
		return applicationIdentity{}, err
	}
	application := safeDisplayField(process.DisplayName)
	if application == "" && process.Path != "" {
		base := filepath.Base(process.Path)
		if base != "." && base != string(filepath.Separator) {
			application = safeDisplayField(base)
		}
	}
	if application == "" {
		application = safeDisplayField(process.SigningIdentifier)
	}
	if application == "" {
		return applicationIdentity{}, errors.New("verified application has no safe display name")
	}
	return applicationIdentity{
		Application:       application,
		Source:            applicationIdentitySource,
		Assurance:         applicationIdentityAssurance,
		Platform:          applicationIdentityPlatform,
		PrincipalScheme:   applicationPrincipalScheme,
		PrincipalID:       principalID,
		SigningIdentifier: process.SigningIdentifier,
		TeamIdentifier:    process.TeamIdentifier,
		SignerName:        safeDisplayField(process.SignerName),
	}, nil
}

func applicationProcessMeetsRuntimePolicy(process applicationProcess) bool {
	if process.CodeState != applicationCodeVerified {
		return false
	}
	// Apple platform code is protected by Apple's platform trust boundary. Some
	// system transports predate CS_RUNTIME or carry narrowly scoped Apple-only
	// exceptions, so retain the platform policy instead of interpreting those
	// exceptions as third-party entitlements.
	if process.SignatureClass == applicationSignatureApplePlatform {
		return true
	}
	return (process.SignatureClass == applicationSignatureDeveloperID ||
		process.SignatureClass == applicationSignatureMacAppStore) &&
		process.HardenedRuntime && process.CodeRuntimeVersion != 0 &&
		(process.DangerousEntitlements&applicationRejectedCodeEntitlements) == 0
}

func helperCodeIdentity(process applicationProcess) (transportCodeIdentity, error) {
	return newTransportCodeIdentity(
		process, transportCodeKindHelper, oneNodHelperSigningIdentifier,
	)
}

func oneNodTransportCodeIdentity(
	process applicationProcess,
	helper transportCodeIdentity,
	expectedSigningIdentifier string,
) (transportCodeIdentity, error) {
	if !validTransportCodeIdentityShape(helper, transportCodeKindHelper) {
		return transportCodeIdentity{}, errors.New("helper code identity is unavailable")
	}
	kind, ok := transportKindForSigningIdentifier(expectedSigningIdentifier)
	if !ok || kind == transportCodeKindHelper {
		return transportCodeIdentity{}, errors.New("OneNod transport signing identifier is not allowed")
	}
	identity, err := newTransportCodeIdentity(
		process, kind, expectedSigningIdentifier,
	)
	if err != nil {
		return transportCodeIdentity{}, err
	}
	return identity, nil
}

func newTransportCodeIdentity(
	process applicationProcess,
	kind transportCodeKind,
	expectedSigningIdentifier string,
) (transportCodeIdentity, error) {
	identifierForKind, kindIsValid := signingIdentifierForTransportKind(kind)
	policyVersion, entitlementsAllowed := transportCodePolicyVersion(
		kind, process.DangerousEntitlements,
	)
	if process.CodeState != applicationCodeAdHoc ||
		process.SignatureClass != applicationSignatureAdHoc ||
		!process.HardenedRuntime ||
		process.LinkerSigned || process.CodeRuntimeVersion == 0 ||
		!kindIsValid || identifierForKind != expectedSigningIdentifier ||
		!entitlementsAllowed ||
		process.SigningIdentifier != expectedSigningIdentifier ||
		process.TeamIdentifier != "" ||
		!safeIdentityField(process.SigningIdentifier, 1024) ||
		!validCodeDirectoryHash(process.CodeDirectoryHash) ||
		len(process.DesignatedRequirement) == 0 ||
		len(process.DesignatedRequirement) > maximumDesignatedRequirementSize {
		return transportCodeIdentity{}, errors.New("OneNod transport code signature is not trusted")
	}
	return transportCodeIdentity{
		Kind:                  kind,
		PolicyVersion:         policyVersion,
		SignatureClass:        process.SignatureClass,
		SigningIdentifier:     process.SigningIdentifier,
		CodeDirectoryHash:     append([]byte(nil), process.CodeDirectoryHash...),
		DesignatedRequirement: append([]byte(nil), process.DesignatedRequirement...),
		HardenedRuntime:       process.HardenedRuntime,
		CodeRuntimeVersion:    process.CodeRuntimeVersion,
	}, nil
}

func transportCodePolicyVersion(kind transportCodeKind, entitlements uint32) (uint32, bool) {
	switch kind {
	case transportCodeKindHelper, transportCodeKindSSHSign:
		return transportRuntimePolicyVersion, entitlements == 0
	case transportCodeKindMay:
		switch entitlements {
		case 0:
			return transportRuntimePolicyVersion, true
		case dangerousCodeEntitlementDisableLibraryValidation:
			// Static candidate inspection additionally requires the exact signed
			// library-load constraint before this v2 identity may be staged. A
			// running parent is then bound to that inspected candidate by its exact
			// CDHash and designated requirement.
			return transportConstrainedDLVPolicyVersion, true
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func transportLibraryConstraintAllowed(
	identity transportCodeIdentity,
	constraintBlob []byte,
) bool {
	switch identity.PolicyVersion {
	case transportRuntimePolicyVersion:
		// The v1 policy has no runtime exception requiring a load constraint.
		// Rejecting unexpected slots keeps every fixed transport role on one
		// auditable signature shape.
		return len(constraintBlob) == 0
	case transportConstrainedDLVPolicyVersion:
		if identity.Kind != transportCodeKindMay ||
			len(constraintBlob) != transportOnePasswordConstraintSize {
			return false
		}
		digest := sha256.Sum256(constraintBlob)
		return bytes.Equal(digest[:], []byte(transportOnePasswordConstraintSHA256))
	default:
		return false
	}
}

func sameTransportCodeIdentity(first, second transportCodeIdentity) bool {
	return validTransportCodeIdentityShape(first, first.Kind) &&
		validTransportCodeIdentityShape(second, second.Kind) &&
		first.Kind == second.Kind &&
		first.PolicyVersion == second.PolicyVersion &&
		first.SignatureClass == second.SignatureClass &&
		first.SigningIdentifier == second.SigningIdentifier &&
		first.TeamIdentifier == second.TeamIdentifier &&
		first.HardenedRuntime == second.HardenedRuntime &&
		first.CodeRuntimeVersion == second.CodeRuntimeVersion &&
		validCodeDirectoryHash(first.CodeDirectoryHash) &&
		validCodeDirectoryHash(second.CodeDirectoryHash) &&
		bytes.Equal(first.CodeDirectoryHash, second.CodeDirectoryHash) &&
		bytes.Equal(first.DesignatedRequirement, second.DesignatedRequirement)
}

func validTransportCodeIdentityShape(
	identity transportCodeIdentity,
	expectedKind transportCodeKind,
) bool {
	expectedIdentifier, ok := signingIdentifierForTransportKind(expectedKind)
	policyIsValid := identity.PolicyVersion == transportRuntimePolicyVersion
	if expectedKind == transportCodeKindMay {
		policyIsValid = policyIsValid ||
			identity.PolicyVersion == transportConstrainedDLVPolicyVersion
	}
	return ok && identity.Kind == expectedKind &&
		policyIsValid &&
		identity.SignatureClass == applicationSignatureAdHoc &&
		identity.SigningIdentifier == expectedIdentifier &&
		identity.TeamIdentifier == "" && identity.HardenedRuntime &&
		identity.CodeRuntimeVersion != 0 &&
		validCodeDirectoryHash(identity.CodeDirectoryHash) &&
		len(identity.DesignatedRequirement) > 0 &&
		len(identity.DesignatedRequirement) <= maximumDesignatedRequirementSize
}

func transportKindForSigningIdentifier(identifier string) (transportCodeKind, bool) {
	switch identifier {
	case oneNodHelperSigningIdentifier:
		return transportCodeKindHelper, true
	case oneNodMaySigningIdentifier:
		return transportCodeKindMay, true
	case oneNodSSHSignSigningIdentifier:
		return transportCodeKindSSHSign, true
	default:
		return "", false
	}
}

func signingIdentifierForTransportKind(kind transportCodeKind) (string, bool) {
	switch kind {
	case transportCodeKindHelper:
		return oneNodHelperSigningIdentifier, true
	case transportCodeKindMay:
		return oneNodMaySigningIdentifier, true
	case transportCodeKindSSHSign:
		return oneNodSSHSignSigningIdentifier, true
	default:
		return "", false
	}
}

func validCodeDirectoryHash(hash []byte) bool {
	return len(hash) >= minimumCodeDirectoryHashSize &&
		len(hash) <= maximumCodeDirectoryHashSize
}

func isTransparentOneNodTransport(
	process applicationProcess,
	helper transportCodeIdentity,
	authorized authorizedTransportSet,
) bool {
	for _, signingIdentifier := range []string{
		oneNodMaySigningIdentifier,
		oneNodSSHSignSigningIdentifier,
	} {
		identity, err := oneNodTransportCodeIdentity(process, helper, signingIdentifier)
		if err == nil && authorized.authorizes(identity) {
			return true
		}
	}
	return false
}

func (authorized authorizedTransportSet) authorizes(identity transportCodeIdentity) bool {
	if len(authorized.Current) > maximumAuthorizedTransportCount {
		return false
	}
	for _, candidate := range authorized.Current {
		if sameTransportCodeIdentity(candidate, identity) {
			return true
		}
	}
	return false
}

// stages is intentionally separate from authorizes. Staged builds may be used
// only by an update commit state machine that also validates its stage proof;
// normal application resolution never grants them transport authority.
func (authorized authorizedTransportSet) stages(identity transportCodeIdentity) bool {
	if len(authorized.Staged) > maximumAuthorizedTransportCount {
		return false
	}
	for _, candidate := range authorized.Staged {
		if sameTransportCodeIdentity(candidate, identity) {
			return true
		}
	}
	return false
}

func applicationPrincipalID(
	class applicationSignatureClass,
	teamIdentifier string,
	signingIdentifier string,
	designatedRequirement []byte,
) (string, error) {
	className := applicationSignatureClassName(class)
	if className == "" || signingIdentifier == "" ||
		len(designatedRequirement) == 0 ||
		len(designatedRequirement) > maximumDesignatedRequirementSize ||
		!safeIdentityField(signingIdentifier, 1024) ||
		(teamIdentifier != "" && !safeIdentityField(teamIdentifier, 128)) {
		return "", errApplicationIdentityUnavailable
	}
	if class != applicationSignatureApplePlatform && teamIdentifier == "" {
		return "", errApplicationIdentityUnavailable
	}
	material := make([]byte, 0, len(designatedRequirement)+256)
	// The externally named v1 principal scheme begins with this first generic
	// code-signature resolver. A distinct domain prevents collisions with the
	// legacy command/bundle enumeration scopes.
	material = append(material, "onenod-macos-application-principal-v1\x00"...)
	material = appendPrincipalField(material, []byte(className))
	material = appendPrincipalField(material, []byte(teamIdentifier))
	material = appendPrincipalField(material, []byte(signingIdentifier))
	material = appendPrincipalField(material, designatedRequirement)
	digest := sha256.Sum256(material)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func appendPrincipalField(target []byte, field []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(field)))
	target = append(target, length[:]...)
	return append(target, field...)
}

func applicationSignatureClassName(class applicationSignatureClass) string {
	switch class {
	case applicationSignatureApplePlatform:
		return "apple-platform"
	case applicationSignatureDeveloperID:
		return "developer-id"
	case applicationSignatureMacAppStore:
		return "mac-app-store"
	default:
		return ""
	}
}

func safeIdentityField(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func safeDisplayField(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || !utf8.ValidString(value) {
		return ""
	}
	count := 0
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
		count++
		if count > 128 {
			return ""
		}
	}
	return value
}

func processStartedAfter(parent applicationProcess, child applicationProcess) bool {
	if parent.StartSeconds != child.StartSeconds {
		return parent.StartSeconds > child.StartSeconds
	}
	return parent.StartMicroseconds > child.StartMicroseconds
}
