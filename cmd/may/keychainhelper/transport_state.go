package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"debug/macho"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

const (
	transportStateVersion      = 1
	commitCapabilitySize       = 32
	maximumTransportBinarySize = 128 << 20
)

var (
	transportTransactionID = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	transportSHA256        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	transportCDHash        = regexp.MustCompile(`^[A-Za-z0-9_-]{27,86}$`)

	currentHelperIdentityResolver = currentHelperTransportCodeIdentity
	directParentIdentityResolver  = directParentTransportCodeIdentity
	staticTransportIdentity       = transportCodeIdentityAtFile
	transportArchitectureVerifier = verifyTransportArchitecture
	authorizedApplicationResolver = resolveApplicationIdentityWithAuthorizedTransports
	transportRandomReader         = rand.Reader
	openInheritedTransportFile    = inheritedTransportFile
)

type storedTransportTrust struct {
	Version                       int                         `json:"version"`
	BootstrapPending              bool                        `json:"bootstrap_pending,omitempty"`
	ACLConvergencePending         bool                        `json:"acl_convergence_pending,omitempty"`
	CurrentHelper                 transportCodeIdentity       `json:"current_helper"`
	Current                       []transportCodeIdentity     `json:"current"`
	Staged                        *storedTransportTransaction `json:"staged,omitempty"`
	LastFinalizedTransactionID    string                      `json:"last_finalized_transaction_id,omitempty"`
	LastFinalizedTransactionState string                      `json:"last_finalized_transaction_state,omitempty"`
}

type storedTransportTransaction struct {
	TransactionID       string                  `json:"transaction_id"`
	CommitCapabilitySHA string                  `json:"commit_capability_sha256"`
	Helper              transportCodeIdentity   `json:"helper"`
	Transports          []transportCodeIdentity `json:"transports"`
}

type transportCandidate struct {
	File     *os.File
	Identity transportCodeIdentity
}

func inheritedTransportFile(descriptor uintptr) (*os.File, error) {
	file := os.NewFile(descriptor, fmt.Sprintf("transport-fd-%d", descriptor))
	if file == nil {
		return nil, errors.New("required transport file descriptor is unavailable")
	}
	return file, nil
}

func inspectTransportCandidate(
	descriptor uintptr,
	digest string,
	expectedArchitecture string,
	expectedCDHash string,
	expectedDRSHA256 string,
	kind transportCodeKind,
) (transportCandidate, error) {
	if (expectedArchitecture != "arm64" && expectedArchitecture != "amd64") ||
		expectedArchitecture != runtime.GOARCH || !transportSHA256.MatchString(digest) ||
		!transportCDHash.MatchString(expectedCDHash) ||
		!transportSHA256.MatchString(expectedDRSHA256) {
		return transportCandidate{}, errors.New("candidate transport release identity is invalid")
	}
	file, err := openInheritedTransportFile(descriptor)
	if err != nil {
		return transportCandidate{}, err
	}
	candidate := transportCandidate{File: file}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maximumTransportBinarySize {
		return transportCandidate{}, errors.New("candidate transport file is invalid")
	}
	firstHash, err := hashTransportFile(file, info.Size())
	if err != nil {
		return transportCandidate{}, errors.New("candidate transport could not be hashed")
	}
	if subtle.ConstantTimeCompare([]byte(firstHash), []byte(digest)) != 1 {
		return transportCandidate{}, errors.New("candidate transport digest does not match its file descriptor")
	}
	if err := transportArchitectureVerifier(file, expectedArchitecture); err != nil {
		return transportCandidate{}, err
	}
	identity, err := staticTransportIdentity(file, kind)
	if err != nil {
		return transportCandidate{}, errors.New("candidate transport exact code identity is invalid")
	}
	actualCDHash := base64.RawURLEncoding.EncodeToString(identity.CodeDirectoryHash)
	designatedRequirementHash := sha256.Sum256(identity.DesignatedRequirement)
	actualDRSHA256 := fmt.Sprintf("sha256:%x", designatedRequirementHash[:])
	if subtle.ConstantTimeCompare([]byte(actualCDHash), []byte(expectedCDHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(actualDRSHA256), []byte(expectedDRSHA256)) != 1 {
		return transportCandidate{}, errors.New("candidate transport does not match release exact code identity")
	}
	infoAfter, err := file.Stat()
	if err != nil || !sameTransportFileSnapshot(info, infoAfter) {
		return transportCandidate{}, errors.New("candidate transport changed during verification")
	}
	secondHash, err := hashTransportFile(file, infoAfter.Size())
	if err != nil || subtle.ConstantTimeCompare([]byte(firstHash), []byte(secondHash)) != 1 ||
		subtle.ConstantTimeCompare([]byte(secondHash), []byte(digest)) != 1 {
		return transportCandidate{}, errors.New("candidate transport changed during verification")
	}
	finalInfo, err := file.Stat()
	if err != nil || !sameTransportFileSnapshot(infoAfter, finalInfo) {
		return transportCandidate{}, errors.New("candidate transport changed during verification")
	}
	candidate.Identity = identity
	failed = false
	return candidate, nil
}

func verifyTransportArchitecture(file *os.File, expected string) error {
	expectedCPU := macho.CpuArm64
	if expected == "amd64" {
		expectedCPU = macho.CpuAmd64
	}
	if fat, err := macho.NewFatFile(file); err == nil {
		for _, architecture := range fat.Arches {
			if architecture.Cpu == expectedCPU {
				return nil
			}
		}
		return errors.New("candidate transport does not contain the expected architecture slice")
	}
	thin, err := macho.NewFile(file)
	if err != nil || thin.Cpu != expectedCPU {
		return errors.New("candidate transport architecture does not match release metadata")
	}
	return nil
}

func hashTransportFile(file *os.File, size int64) (string, error) {
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, size)); err != nil {
		return "", err
	}
	return "sha256:" + fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func closeTransportCandidates(candidates ...transportCandidate) {
	for _, candidate := range candidates {
		if candidate.File != nil {
			_ = candidate.File.Close()
		}
	}
}

func exactCurrentTransportSet(
	may transportCodeIdentity,
	adapter transportCodeIdentity,
) ([]transportCodeIdentity, error) {
	if !validTransportCodeIdentityShape(may, transportCodeKindMay) ||
		!validTransportCodeIdentityShape(adapter, transportCodeKindSSHSign) {
		return nil, errors.New("OneNod transport set is invalid")
	}
	return []transportCodeIdentity{may, adapter}, nil
}

func validateStoredTransportTrust(trust *storedTransportTrust) error {
	if trust == nil {
		return errors.New("requester identity has no transport trust state")
	}
	if trust.Version != transportStateVersion ||
		!validTransportCodeIdentityShape(trust.CurrentHelper, transportCodeKindHelper) ||
		!validTransportSet(trust.Current) {
		return errors.New("requester transport trust state is invalid")
	}
	if trust.ACLConvergencePending &&
		(trust.BootstrapPending || trust.Staged != nil) {
		return errors.New("requester Keychain ACL convergence state is invalid")
	}
	if trust.Staged != nil {
		if !transportTransactionID.MatchString(trust.Staged.TransactionID) ||
			!validCapabilityHash(trust.Staged.CommitCapabilitySHA) ||
			!validTransportCodeIdentityShape(trust.Staged.Helper, transportCodeKindHelper) ||
			!validTransportSet(trust.Staged.Transports) {
			return errors.New("requester staged transport state is invalid")
		}
	}
	if trust.LastFinalizedTransactionID == "" {
		if trust.LastFinalizedTransactionState != "" {
			return errors.New("requester finalized transport state is invalid")
		}
	} else if !transportTransactionID.MatchString(trust.LastFinalizedTransactionID) ||
		(trust.LastFinalizedTransactionState != "committed" &&
			trust.LastFinalizedTransactionState != "aborted") {
		return errors.New("requester finalized transport state is invalid")
	}
	return nil
}

func validTransportSet(transports []transportCodeIdentity) bool {
	if len(transports) != 2 {
		return false
	}
	seenMay, seenAdapter := false, false
	for _, identity := range transports {
		switch identity.Kind {
		case transportCodeKindMay:
			if seenMay || !validTransportCodeIdentityShape(identity, transportCodeKindMay) {
				return false
			}
			seenMay = true
		case transportCodeKindSSHSign:
			if seenAdapter || !validTransportCodeIdentityShape(identity, transportCodeKindSSHSign) {
				return false
			}
			seenAdapter = true
		default:
			return false
		}
	}
	return seenMay && seenAdapter
}

func sameTransportSet(first, second []transportCodeIdentity) bool {
	if !validTransportSet(first) || !validTransportSet(second) {
		return false
	}
	for _, identity := range first {
		candidate, found := transportIdentityForKind(second, identity.Kind)
		if !found || !sameTransportCodeIdentity(identity, candidate) {
			return false
		}
	}
	return true
}

func validCapabilityHash(encoded string) bool {
	value, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	valid := err == nil && len(value) == sha256.Size
	zero(value)
	return valid
}

func currentAuthorizedSet(trust *storedTransportTrust) authorizedTransportSet {
	set := authorizedTransportSet{Current: cloneTransportIdentities(trust.Current)}
	if trust.Staged != nil {
		set.Staged = cloneTransportIdentities(trust.Staged.Transports)
	}
	return set
}

func cloneTransportIdentities(source []transportCodeIdentity) []transportCodeIdentity {
	cloned := make([]transportCodeIdentity, len(source))
	for index, identity := range source {
		cloned[index] = identity
		cloned[index].CodeDirectoryHash = append([]byte(nil), identity.CodeDirectoryHash...)
		cloned[index].DesignatedRequirement = append([]byte(nil), identity.DesignatedRequirement...)
	}
	return cloned
}

func transportIdentityForKind(
	identities []transportCodeIdentity,
	kind transportCodeKind,
) (transportCodeIdentity, bool) {
	for _, identity := range identities {
		if identity.Kind == kind {
			return identity, true
		}
	}
	return transportCodeIdentity{}, false
}

func authenticateCurrentTransport(trust *storedTransportTrust) error {
	if err := validateStoredTransportTrust(trust); err != nil {
		return err
	}
	if trust.BootstrapPending {
		return errors.New("requester transport trust bootstrap is incomplete")
	}
	helper, err := currentHelperIdentityResolver()
	if err != nil || !sameTransportCodeIdentity(helper, trust.CurrentHelper) {
		return errors.New("running helper is not the authorized exact build")
	}
	parent, err := directParentIdentityResolver(transportCodeKindMay)
	if err != nil || !currentAuthorizedSet(trust).authorizes(parent) {
		return errors.New("direct parent is not the authorized current OneNod transport")
	}
	return nil
}

func transportCallerRole(trust *storedTransportTrust) (string, error) {
	if err := validateStoredTransportTrust(trust); err != nil {
		return "", err
	}
	if trust.BootstrapPending {
		return "", errors.New("requester transport trust bootstrap is incomplete")
	}
	helper, helperErr := currentHelperIdentityResolver()
	parent, parentErr := directParentIdentityResolver(transportCodeKindMay)
	if helperErr != nil || parentErr != nil {
		return "", errors.New("transport caller exact code identity is unavailable")
	}
	if sameTransportCodeIdentity(helper, trust.CurrentHelper) &&
		currentAuthorizedSet(trust).authorizes(parent) {
		return "current", nil
	}
	if trust.Staged != nil && sameTransportCodeIdentity(helper, trust.Staged.Helper) &&
		currentAuthorizedSet(trust).stages(parent) {
		return "staged", nil
	}
	return "", errors.New("transport caller is not authorized by exact build state")
}

func newCommitCapability() (plain []byte, hash string, err error) {
	value := make([]byte, commitCapabilitySize)
	if _, err := io.ReadFull(transportRandomReader, value); err != nil {
		zero(value)
		return nil, "", err
	}
	digest := sha256.Sum256(value)
	return value, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validateTransactionID(value string) error {
	if !transportTransactionID.MatchString(value) {
		return errors.New("transaction_id is invalid")
	}
	return nil
}

func noTransportRequestPayload(request helperRequest) bool {
	return request.ApplicationEvidence == "" && request.CanonicalBody == "" &&
		request.DisplayName == "" && request.Message == "" &&
		request.CandidateMaySHA256 == "" && request.CandidateAdapterSHA256 == "" &&
		request.CandidateHelperSHA256 == "" && request.CandidateMayArchitecture == "" &&
		request.CandidateAdapterArchitecture == "" && request.CandidateHelperArchitecture == "" &&
		request.CandidateMayCDHash == "" && request.CandidateAdapterCDHash == "" &&
		request.CandidateHelperCDHash == "" && request.CandidateMayDRSHA256 == "" &&
		request.CandidateAdapterDRSHA256 == "" && request.CandidateHelperDRSHA256 == "" &&
		request.TransactionID == ""
}

func readCommitCapability() ([]byte, error) {
	file, err := openInheritedTransportFile(3)
	if err != nil {
		return nil, errors.New("commit capability file descriptor is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !isAnonymousCapabilityPipe(file, info) {
		return nil, errors.New("commit capability must arrive through an anonymous pipe")
	}
	value := make([]byte, commitCapabilitySize+1)
	count, err := io.ReadFull(file, value)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		zero(value)
		return nil, errors.New("commit capability file descriptor could not be read")
	}
	if count != commitCapabilitySize {
		zero(value)
		return nil, errors.New("commit capability must contain exactly 32 bytes")
	}
	one := []byte{0}
	extra, readErr := file.Read(one)
	zero(one)
	if extra != 0 || (readErr != nil && !errors.Is(readErr, io.EOF)) {
		zero(value)
		return nil, errors.New("commit capability must contain exactly 32 bytes")
	}
	return value[:commitCapabilitySize], nil
}

func writeCommitCapability(value []byte) error {
	if len(value) != commitCapabilitySize {
		return errors.New("commit capability is invalid")
	}
	file, err := openInheritedTransportFile(6)
	if err != nil {
		return errors.New("commit capability output pipe is unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !isAnonymousCapabilityPipe(file, info) {
		return errors.New("commit capability output must be an anonymous pipe")
	}
	written := 0
	for written < len(value) {
		count, err := file.Write(value[written:])
		if err != nil || count <= 0 {
			return errors.New("commit capability output pipe write failed")
		}
		written += count
	}
	return nil
}

func verifyRawCommitCapability(value []byte, expectedHash string) bool {
	if len(value) != commitCapabilitySize {
		return false
	}
	digest := sha256.Sum256(value)
	expected, err := base64.RawURLEncoding.Strict().DecodeString(expectedHash)
	if err != nil || len(expected) != sha256.Size {
		zero(expected)
		return false
	}
	defer zero(expected)
	return subtle.ConstantTimeCompare(digest[:], expected) == 1
}

func sameDynamicAndStaticMay(dynamic, static transportCodeIdentity) error {
	if !sameTransportCodeIdentity(dynamic, static) {
		return errors.New("direct parent does not match candidate may file descriptor")
	}
	return nil
}

func digestFieldPresentOnlyFor(request helperRequest, allowed ...string) error {
	present := map[string]bool{
		"may": request.CandidateMaySHA256 != "" && request.CandidateMayArchitecture != "" &&
			request.CandidateMayCDHash != "" && request.CandidateMayDRSHA256 != "",
		"adapter": request.CandidateAdapterSHA256 != "" &&
			request.CandidateAdapterArchitecture != "" && request.CandidateAdapterCDHash != "" &&
			request.CandidateAdapterDRSHA256 != "",
		"helper": request.CandidateHelperSHA256 != "" &&
			request.CandidateHelperArchitecture != "" && request.CandidateHelperCDHash != "" &&
			request.CandidateHelperDRSHA256 != "",
	}
	partial := map[string]bool{
		"may": request.CandidateMaySHA256 != "" || request.CandidateMayArchitecture != "" ||
			request.CandidateMayCDHash != "" || request.CandidateMayDRSHA256 != "",
		"adapter": request.CandidateAdapterSHA256 != "" ||
			request.CandidateAdapterArchitecture != "" || request.CandidateAdapterCDHash != "" ||
			request.CandidateAdapterDRSHA256 != "",
		"helper": request.CandidateHelperSHA256 != "" ||
			request.CandidateHelperArchitecture != "" || request.CandidateHelperCDHash != "" ||
			request.CandidateHelperDRSHA256 != "",
	}
	allow := make(map[string]bool, len(allowed))
	for _, field := range allowed {
		allow[field] = true
	}
	for field, exists := range present {
		if exists != allow[field] || partial[field] != allow[field] {
			return errors.New("transport candidate digest fields do not match the operation")
		}
	}
	return nil
}

func transportOperationHasNoApplicationFields(request helperRequest) error {
	if request.ApplicationEvidence != "" || request.CanonicalBody != "" ||
		request.DisplayName != "" || request.Message != "" {
		return errors.New("transport operation does not accept application, identity, or signing fields")
	}
	return nil
}

func safeTransportError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(err.Error())
	if message == "" {
		return errors.New("transport trust operation failed")
	}
	return errors.New(message)
}
