//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <stdlib.h>
#include "application_identity_darwin.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

const inheritedSSHPeerDescriptor = 3

// validateAcceptedSSHPeerSocketForTesting is a narrow test seam for exercising
// accepted/client/socketpair role checks at a temporary socket path. Production
// evidence never accepts a caller-provided path; resolveApplicationIdentity
// always calls helper_peer_audit_token, which derives ~/.onenod/agent.sock from
// the account database and checks its accepted-socket shape. The path and
// inode are not an authentication boundary; exact caller SecCode authorization
// is required separately before this evidence can produce a verified result.
func validateAcceptedSSHPeerSocketForTesting(descriptor int, expectedPath string) error {
	if descriptor < 0 || expectedPath == "" || !filepath.IsAbs(expectedPath) ||
		filepath.Clean(expectedPath) != expectedPath || strings.IndexByte(expectedPath, 0) >= 0 {
		return errors.New("test SSH peer socket path is invalid")
	}
	cPath := C.CString(expectedPath)
	defer C.free(unsafe.Pointer(cPath))
	var token C.audit_token_t
	var peerPID C.pid_t
	var systemError C.int
	if C.helper_peer_audit_token_at_path(
		C.int(descriptor), C.uid_t(os.Geteuid()), cPath, C.size_t(len(expectedPath)),
		&token, &peerPID, &systemError,
	) != 0 {
		return fmt.Errorf("SSH peer socket is not an accepted fixed-path connection (system status %d)", int(systemError))
	}
	return nil
}

func resolveApplicationIdentity(evidence string) (applicationIdentity, error) {
	return resolveApplicationIdentityWithAuthorizedTransports(
		evidence, authorizedTransportSet{},
	)
}

// resolveApplicationIdentityWithAuthorizedTransports grants transparency only
// to exact identities in authorized.Current. Staged candidates deliberately do
// not participate in normal application resolution.
func resolveApplicationIdentityWithAuthorizedTransports(
	evidence string,
	authorized authorizedTransportSet,
) (applicationIdentity, error) {
	if err := validateApplicationEvidence(evidence); err != nil {
		return applicationIdentity{}, err
	}
	expectedEUID := C.uid_t(os.Geteuid())
	helperIdentity, err := currentHelperTransportCodeIdentity()
	if err != nil {
		return applicationIdentity{}, fmt.Errorf("helper code identity is unavailable: %w", err)
	}
	startPID := 0
	directTransportPID := os.Getppid()
	directTransport, directTransportIdentity, err := inspectOneNodTransportProcess(
		directTransportPID, nil, expectedEUID, helperIdentity,
		transportCodeKindMay, authorized,
	)
	if err != nil {
		return applicationIdentity{}, fmt.Errorf(
			"application evidence transport is unavailable: %w", err,
		)
	}
	if directTransport.ParentPID <= 1 || directTransport.ParentPID == directTransport.PID {
		return applicationIdentity{}, errors.New("application evidence transport has no stable parent")
	}
	var peerToken C.audit_token_t
	usePeerToken := false
	var systemError C.int

	switch evidence {
	case applicationEvidenceParent:
		startPID = directTransport.ParentPID
	case applicationEvidenceSSHPeer:
		var peerPID C.pid_t
		if result := C.helper_peer_audit_token(
			C.int(inheritedSSHPeerDescriptor), expectedEUID,
			&peerToken, &peerPID, &systemError,
		); result != 0 || peerPID <= 1 {
			return applicationIdentity{}, fmt.Errorf(
				"SSH peer application evidence is unavailable (system status %d)", int(systemError),
			)
		}
		startPID = int(peerPID)
		usePeerToken = true
	}

	visited := make(map[int]struct{}, maximumApplicationAncestryDepth)
	var child *applicationProcess
	for depth, pid := 0, startPID; depth < maximumApplicationAncestryDepth && pid > 1; depth++ {
		if _, repeated := visited[pid]; repeated {
			return applicationIdentity{}, errors.New("process ancestry contains a cycle")
		}
		visited[pid] = struct{}{}
		var token *C.audit_token_t
		if usePeerToken && depth == 0 {
			token = &peerToken
		}
		process, err := inspectApplicationProcess(pid, token, expectedEUID)
		if err != nil {
			return applicationIdentity{}, err
		}
		if child != nil {
			var systemError C.int
			if processStartedAfter(process, *child) || C.helper_validate_process_link(
				C.pid_t(child.PID), C.pid_t(process.PID),
				C.uint64_t(child.StartSeconds), C.uint64_t(child.StartMicroseconds),
				expectedEUID, &systemError,
			) != 0 {
				return applicationIdentity{}, errors.New("process ancestry changed during application verification")
			}
		}
		if evidence == applicationEvidenceSSHPeer &&
			isTransparentOneNodTransport(process, helperIdentity, authorized) {
			if process.ParentPID <= 1 || process.ParentPID == process.PID {
				return applicationIdentity{}, errors.New("OneNod SSH transport has no stable parent")
			}
			if err := revalidateDirectTransport(
				directTransport, directTransportIdentity, helperIdentity, authorized,
			); err != nil {
				return applicationIdentity{}, err
			}
			child = &process
			pid = process.ParentPID
			continue
		}
		if err := revalidateDirectTransport(
			directTransport, directTransportIdentity, helperIdentity, authorized,
		); err != nil {
			return applicationIdentity{}, err
		}
		selectProcess, continueAncestry, err := applicationProcessDecision(process)
		if err != nil {
			return applicationIdentity{}, err
		}
		if selectProcess {
			return identityForApplicationProcess(process)
		}
		if !continueAncestry || process.ParentPID <= 1 || process.ParentPID == process.PID {
			break
		}
		child = &process
		pid = process.ParentPID
	}
	return applicationIdentity{}, errApplicationIdentityUnavailable
}

// currentHelperTransportCodeIdentity returns the exact identity of this
// running helper. Callers must compare it with helper-protected state when an
// operation requires an already-enrolled helper.
func currentHelperTransportCodeIdentity() (transportCodeIdentity, error) {
	process, err := inspectApplicationProcessByPID(os.Getpid())
	if err != nil {
		return transportCodeIdentity{}, err
	}
	return helperCodeIdentity(process)
}

// directParentTransportCodeIdentity observes a structurally valid fixed-role
// parent but does not authorize it. Update operations may compare the result to
// Current or, with an independent stage proof, Staged; ordinary operations must
// compare it only to Current.
func directParentTransportCodeIdentity(
	expectedKind transportCodeKind,
) (transportCodeIdentity, error) {
	helperIdentity, err := currentHelperTransportCodeIdentity()
	if err != nil {
		return transportCodeIdentity{}, err
	}
	process, err := inspectApplicationProcessByPID(os.Getppid())
	if err != nil {
		return transportCodeIdentity{}, err
	}
	identifier, ok := signingIdentifierForTransportKind(expectedKind)
	if !ok || expectedKind == transportCodeKindHelper {
		return transportCodeIdentity{}, errors.New("direct parent transport kind is invalid")
	}
	return oneNodTransportCodeIdentity(process, helperIdentity, identifier)
}

// transportCodeIdentityAtFile validates an inherited read-only descriptor as
// a sealed, explicit ad-hoc OneNod build. The descriptor's F_GETPATH is used
// only because Security.framework accepts file URLs rather than file
// descriptors; C verifies the URL resolves to the same stable vnode before and
// after strict signature validation. Authorization is still the returned exact
// CDHash/DR plus a separate stage proof, never the path.
func transportCodeIdentityAtFile(
	file *os.File,
	expectedKind transportCodeKind,
) (transportCodeIdentity, error) {
	identifier, ok := signingIdentifierForTransportKind(expectedKind)
	if !ok || file == nil {
		return transportCodeIdentity{}, errors.New("static transport candidate is invalid")
	}
	descriptor := file.Fd()
	if descriptor > uintptr(^uint32(0)>>1) {
		return transportCodeIdentity{}, errors.New("static transport descriptor is out of range")
	}
	var raw C.helper_application_process
	if result := C.helper_inspect_static_transport_fd(C.int(descriptor), &raw); result != 0 {
		// The C helper frees partial results on failure; retain only the scalar
		// statuses before returning rather than attempting a second free here.
		return transportCodeIdentity{}, fmt.Errorf(
			"static transport code identity is unavailable (security status %d, system status %d)",
			int(raw.security_status), int(raw.system_error),
		)
	}
	defer C.helper_application_process_free(&raw)
	process, err := applicationProcessFromRaw(&raw)
	if err != nil {
		return transportCodeIdentity{}, err
	}
	return newTransportCodeIdentity(process, expectedKind, identifier)
}

func inspectOneNodTransportProcess(
	pid int,
	token *C.audit_token_t,
	expectedEUID C.uid_t,
	helperIdentity transportCodeIdentity,
	expectedKind transportCodeKind,
	authorized authorizedTransportSet,
) (applicationProcess, transportCodeIdentity, error) {
	identifier, ok := signingIdentifierForTransportKind(expectedKind)
	if !ok || expectedKind == transportCodeKindHelper {
		return applicationProcess{}, transportCodeIdentity{}, errors.New("transport kind is invalid")
	}
	process, err := inspectApplicationProcess(pid, token, expectedEUID)
	if err != nil {
		return applicationProcess{}, transportCodeIdentity{}, err
	}
	identity, err := oneNodTransportCodeIdentity(process, helperIdentity, identifier)
	if err != nil {
		return applicationProcess{}, transportCodeIdentity{}, err
	}
	if !authorized.authorizes(identity) {
		return applicationProcess{}, transportCodeIdentity{}, errors.New("transport exact identity is not authorized")
	}
	return process, identity, nil
}

func revalidateDirectTransport(
	original applicationProcess,
	originalIdentity transportCodeIdentity,
	helperIdentity transportCodeIdentity,
	authorized authorizedTransportSet,
) error {
	current, identity, err := inspectOneNodTransportProcess(
		original.PID, nil, C.uid_t(os.Geteuid()), helperIdentity,
		transportCodeKindMay, authorized,
	)
	if err != nil || current.ParentPID != original.ParentPID ||
		current.StartSeconds != original.StartSeconds ||
		current.StartMicroseconds != original.StartMicroseconds ||
		!sameTransportCodeIdentity(identity, originalIdentity) {
		return errors.New("parent application evidence changed during verification")
	}
	return nil
}

func inspectApplicationProcess(
	pid int,
	token *C.audit_token_t,
	expectedEUID C.uid_t,
) (applicationProcess, error) {
	var raw C.helper_application_process
	if result := C.helper_inspect_process(
		C.pid_t(pid), token, expectedEUID, &raw,
	); result != 0 {
		return applicationProcess{}, fmt.Errorf(
			"process identity changed or became unavailable (system status %d)", int(raw.system_error),
		)
	}
	defer C.helper_application_process_free(&raw)
	return applicationProcessFromRaw(&raw)
}

func applicationProcessFromRaw(raw *C.helper_application_process) (applicationProcess, error) {
	if raw == nil {
		return applicationProcess{}, errors.New("code identity result is unavailable")
	}
	process := applicationProcess{
		PID:                   int(raw.pid),
		ParentPID:             int(raw.parent_pid),
		StartSeconds:          uint64(raw.start_seconds),
		StartMicroseconds:     uint64(raw.start_microseconds),
		SignatureClass:        applicationSignatureClass(raw.signature_class),
		CodeState:             applicationCodeState(raw.code_state),
		AppBundle:             raw.app_bundle != 0,
		HardenedRuntime:       raw.hardened_runtime != 0,
		LinkerSigned:          raw.linker_signed != 0,
		CodeRuntimeVersion:    uint32(raw.code_runtime_version),
		DangerousEntitlements: uint32(raw.dangerous_entitlements),
		Path:                  copyOptionalCString(raw.path),
		DisplayName:           copyOptionalCString(raw.display_name),
		SigningIdentifier:     copyOptionalCString(raw.signing_identifier),
		TeamIdentifier:        copyOptionalCString(raw.team_identifier),
		SignerName:            copyOptionalCString(raw.signer_name),
	}
	if raw.code_directory_hash != nil && raw.code_directory_hash_length > 0 {
		if uint64(raw.code_directory_hash_length) > maximumCodeDirectoryHashSize {
			return applicationProcess{}, errors.New("code directory hash exceeds the identity limit")
		}
		process.CodeDirectoryHash = C.GoBytes(
			unsafe.Pointer(raw.code_directory_hash), C.int(raw.code_directory_hash_length),
		)
	}
	if raw.designated_requirement != nil && raw.designated_requirement_length > 0 {
		if uint64(raw.designated_requirement_length) > maximumDesignatedRequirementSize {
			return applicationProcess{}, errors.New("designated requirement exceeds the identity limit")
		}
		process.DesignatedRequirement = C.GoBytes(
			unsafe.Pointer(raw.designated_requirement), C.int(raw.designated_requirement_length),
		)
	}
	return process, nil
}

func inspectApplicationProcessByPID(pid int) (applicationProcess, error) {
	return inspectApplicationProcess(pid, nil, C.uid_t(os.Geteuid()))
}

func copyOptionalCString(value *C.char) string {
	if value == nil {
		return ""
	}
	return C.GoString(value)
}
