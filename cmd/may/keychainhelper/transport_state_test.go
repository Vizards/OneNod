package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type inheritedFileFixture struct {
	descriptors map[uintptr]string
	pipes       map[uintptr]*os.File
	identities  map[byte]transportCodeIdentity
}

func useInheritedFileFixture(t *testing.T) *inheritedFileFixture {
	t.Helper()
	fixture := &inheritedFileFixture{
		descriptors: make(map[uintptr]string),
		pipes:       make(map[uintptr]*os.File),
		identities:  make(map[byte]transportCodeIdentity),
	}
	previousOpen := openInheritedTransportFile
	previousStatic := staticTransportIdentity
	previousArchitecture := transportArchitectureVerifier
	openInheritedTransportFile = func(descriptor uintptr) (*os.File, error) {
		if file, ok := fixture.pipes[descriptor]; ok {
			delete(fixture.pipes, descriptor)
			return file, nil
		}
		path, ok := fixture.descriptors[descriptor]
		if !ok {
			return nil, errors.New("descriptor is absent")
		}
		return os.Open(path)
	}
	staticTransportIdentity = func(
		file *os.File,
		kind transportCodeKind,
	) (transportCodeIdentity, error) {
		marker := []byte{0}
		if _, err := file.ReadAt(marker, 0); err != nil {
			return transportCodeIdentity{}, err
		}
		identity, ok := fixture.identities[marker[0]]
		if !ok || identity.Kind != kind {
			return transportCodeIdentity{}, errors.New("fixture identity kind mismatch")
		}
		return identity, nil
	}
	transportArchitectureVerifier = func(*os.File, string) error { return nil }
	t.Cleanup(func() {
		openInheritedTransportFile = previousOpen
		staticTransportIdentity = previousStatic
		transportArchitectureVerifier = previousArchitecture
	})
	return fixture
}

func (fixture *inheritedFileFixture) candidate(
	t *testing.T,
	descriptor uintptr,
	marker byte,
	identity transportCodeIdentity,
) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), fmt.Sprintf("candidate-%d", descriptor))
	content := bytes.Repeat([]byte{marker}, 4096)
	if err := os.WriteFile(path, content, 0o500); err != nil {
		t.Fatal(err)
	}
	fixture.descriptors[descriptor] = path
	fixture.identities[marker] = identity
	digest := sha256.Sum256(content)
	return fmt.Sprintf("sha256:%x", digest[:])
}

func (fixture *inheritedFileFixture) capability(
	t *testing.T,
	value []byte,
) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	delete(fixture.descriptors, 3)
	fixture.pipes[3] = reader
}

func (fixture *inheritedFileFixture) capabilityOutput(
	t *testing.T,
) func() []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	fixture.pipes[6] = writer
	return func() []byte {
		_ = writer.Close()
		value, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func decodeStoredIdentity(t *testing.T, store *memoryStore) storedIdentity {
	t.Helper()
	var identity storedIdentity
	if err := json.Unmarshal(store.value, &identity); err != nil {
		t.Fatal(err)
	}
	return identity
}

func stageRequest(
	origin string,
	transactionID string,
	mayDigest string,
	adapterDigest string,
	helperDigest string,
	mayIdentity,
	adapterIdentity,
	helperIdentity transportCodeIdentity,
) helperRequest {
	request := helperRequest{
		Operation:              "transport-stage",
		Origin:                 origin,
		TransactionID:          transactionID,
		CandidateMaySHA256:     mayDigest,
		CandidateAdapterSHA256: adapterDigest,
		CandidateHelperSHA256:  helperDigest,
	}
	populateExpectedCandidateIdentity(&request, "may", mayIdentity)
	populateExpectedCandidateIdentity(&request, "adapter", adapterIdentity)
	populateExpectedCandidateIdentity(&request, "helper", helperIdentity)
	return request
}

func populateExpectedCandidateIdentity(
	request *helperRequest,
	role string,
	identity transportCodeIdentity,
) {
	digest := sha256.Sum256(identity.DesignatedRequirement)
	drSHA256 := fmt.Sprintf("sha256:%x", digest[:])
	cdHash := base64.RawURLEncoding.EncodeToString(identity.CodeDirectoryHash)
	switch role {
	case "may":
		request.CandidateMayArchitecture = runtime.GOARCH
		request.CandidateMayCDHash = cdHash
		request.CandidateMayDRSHA256 = drSHA256
	case "adapter":
		request.CandidateAdapterArchitecture = runtime.GOARCH
		request.CandidateAdapterCDHash = cdHash
		request.CandidateAdapterDRSHA256 = drSHA256
	case "helper":
		request.CandidateHelperArchitecture = runtime.GOARCH
		request.CandidateHelperCDHash = cdHash
		request.CandidateHelperDRSHA256 = drSHA256
	default:
		panic("unknown candidate role")
	}
}

func TestTransportStageAllowsDifferentExactBuildAndKeepsOldCurrent(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	oldRuntime := newTestTransportRuntime(20)
	newRuntime := newTestTransportRuntime(40)
	useTestTransportRuntime(t, oldRuntime)
	store, _ := authenticatedMemoryStore(t, "MacBook", oldRuntime)
	fixture := useInheritedFileFixture(t)
	mayDigest := fixture.candidate(t, 3, 71, newRuntime.may)
	adapterDigest := fixture.candidate(t, 4, 72, newRuntime.adapter)
	helperDigest := fixture.candidate(t, 5, 73, newRuntime.helper)
	transactionID := strings.Repeat("A", 32)
	readCapability := fixture.capabilityOutput(t)

	_, err := handleRequest(stageRequest(
		origin,
		transactionID,
		mayDigest,
		adapterDigest,
		helperDigest,
		newRuntime.may,
		newRuntime.adapter,
		newRuntime.helper,
	), store)
	if err != nil {
		t.Fatal(err)
	}
	capability := readCapability()
	if len(capability) != commitCapabilitySize {
		t.Fatalf("invalid stage capability length: %d", len(capability))
	}
	identity := decodeStoredIdentity(t, store)
	if identity.Transport.Staged == nil ||
		identity.Transport.Staged.TransactionID != transactionID ||
		!sameTransportSet(identity.Transport.Staged.Transports, []transportCodeIdentity{
			newRuntime.may, newRuntime.adapter,
		}) ||
		!sameTransportCodeIdentity(identity.Transport.Staged.Helper, newRuntime.helper) {
		t.Fatalf("staged state does not contain candidate exact builds: %+v", identity.Transport)
	}
	if !sameTransportSet(identity.Transport.Current, []transportCodeIdentity{
		oldRuntime.may, oldRuntime.adapter,
	}) || !sameTransportCodeIdentity(identity.Transport.CurrentHelper, oldRuntime.helper) {
		t.Fatal("stage replaced current trust before commit")
	}
	if store.access != keychainAccessSelfOnly || bytes.Contains(store.value, capability) {
		t.Fatal("stage persisted plaintext capability or broadened the helper ACL")
	}
}

func TestChangedHelperCommitRequiresStagedParentCapabilityAndConverges(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	oldRuntime := newTestTransportRuntime(60)
	newRuntime := newTestTransportRuntime(90)
	useTestTransportRuntime(t, oldRuntime)
	store, _ := authenticatedMemoryStore(t, "MacBook", oldRuntime)
	fixture := useInheritedFileFixture(t)
	transactionID := strings.Repeat("B", 32)
	readCapability := fixture.capabilityOutput(t)
	staged, err := handleRequest(stageRequest(
		origin,
		transactionID,
		fixture.candidate(t, 3, 81, newRuntime.may),
		fixture.candidate(t, 4, 82, newRuntime.adapter),
		fixture.candidate(t, 5, 83, newRuntime.helper),
		newRuntime.may,
		newRuntime.adapter,
		newRuntime.helper,
	), store)
	if err != nil {
		t.Fatal(err)
	}
	_ = staged
	capability := readCapability()
	fixture.capability(t, capability)
	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return newRuntime.helper, nil
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return newRuntime.may, nil
	}

	if _, err := handleRequest(helperRequest{
		Operation:     "transport-bootstrap-helper",
		Origin:        origin,
		TransactionID: transactionID,
	}, store); err != nil {
		t.Fatal(err)
	}
	identity := decodeStoredIdentity(t, store)
	if identity.Transport.Staged != nil ||
		!sameTransportSet(identity.Transport.Current, []transportCodeIdentity{
			newRuntime.may, newRuntime.adapter,
		}) || !sameTransportCodeIdentity(identity.Transport.CurrentHelper, newRuntime.helper) ||
		identity.Transport.LastFinalizedTransactionState != "committed" ||
		store.access != keychainAccessSelfOnly {
		t.Fatalf("commit did not atomically advance exact trust state: %+v", identity.Transport)
	}
	status, err := handleRequest(helperRequest{
		Operation: "transport-status", Origin: origin,
	}, store)
	if err != nil || status.Role != "current" || status.TransactionID != transactionID ||
		status.TransactionState != "committed" {
		t.Fatalf("commit-aware status = %+v, %v", status, err)
	}
	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return oldRuntime.helper, nil
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return oldRuntime.may, nil
	}
	if _, err := handleRequest(helperRequest{
		Operation: "public", Origin: origin,
	}, store); err == nil {
		t.Fatal("old exact helper and may remained authorized after commit")
	}
}

func TestChangedHelperAuthenticatesSignedEnvelopeBeforePrivateLoad(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	current := newTestTransportRuntime(12)
	staged := newTestTransportRuntime(32)
	store, identity := authenticatedMemoryStore(t, "MacBook", current)
	capability := bytes.Repeat([]byte{0x73}, commitCapabilitySize)
	digest := sha256.Sum256(capability)
	transactionID := strings.Repeat("H", 32)
	identity.Transport.Staged = &storedTransportTransaction{
		TransactionID:       transactionID,
		CommitCapabilitySHA: base64.RawURLEncoding.EncodeToString(digest[:]),
		Helper:              staged.helper,
		Transports: []transportCodeIdentity{
			staged.may, staged.adapter,
		},
	}
	store.value, store.metadata, _ = encodeCredentialRecord(identity)
	fixture := useInheritedFileFixture(t)
	request := helperRequest{
		Operation: "transport-bootstrap-helper", Origin: origin, TransactionID: transactionID,
	}
	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return staged.helper, nil
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return staged.may, nil
	}

	fixture.capability(t, bytes.Repeat([]byte{0x7f}, commitCapabilitySize))
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("wrong capability was accepted")
	}
	if store.loadCount != 0 {
		t.Fatal("wrong capability triggered private Keychain data load")
	}

	tampered := append([]byte(nil), store.metadata...)
	tampered[len(tampered)/2] ^= 1
	store.metadata = tampered
	fixture.capability(t, capability)
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("tampered public envelope was accepted")
	}
	if store.loadCount != 0 {
		t.Fatal("tampered envelope triggered private Keychain data load")
	}

	store.value, store.metadata, _ = encodeCredentialRecord(identity)
	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return testTransportIdentity(transportCodeKindHelper, 52), nil
	}
	fixture.capability(t, capability)
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("wrong replacement helper exact build was accepted")
	}
	if store.loadCount != 0 {
		t.Fatal("wrong replacement helper triggered private Keychain data load")
	}

	currentHelperIdentityResolver = func() (transportCodeIdentity, error) {
		return staged.helper, nil
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return testTransportIdentity(transportCodeKindMay, 53), nil
	}
	fixture.capability(t, capability)
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("wrong staged may exact build was accepted")
	}
	if store.loadCount != 0 {
		t.Fatal("wrong staged may triggered private Keychain data load")
	}
}

func TestStageRejectsWrongCurrentParent(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	current := newTestTransportRuntime(15)
	candidate := newTestTransportRuntime(35)
	wrongParent := testTransportIdentity(transportCodeKindMay, 55)
	useTestTransportRuntime(t, testTransportRuntime{
		helper: current.helper, parent: wrongParent,
		may: current.may, adapter: current.adapter,
	})
	store, _ := authenticatedMemoryStore(t, "MacBook", current)
	fixture := useInheritedFileFixture(t)
	if _, err := handleRequest(stageRequest(
		origin,
		strings.Repeat("E", 32),
		fixture.candidate(t, 3, 41, candidate.may),
		fixture.candidate(t, 4, 42, candidate.adapter),
		fixture.candidate(t, 5, 43, candidate.helper),
		candidate.may,
		candidate.adapter,
		candidate.helper,
	), store); err == nil {
		t.Fatal("stage accepted a direct parent outside stored current trust")
	}
	if decodeStoredIdentity(t, store).Transport.Staged != nil {
		t.Fatal("rejected stage mutated trust state")
	}
}

func TestStageRejectsReleaseExactIdentityMismatchBeforeStateMutation(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	current := newTestTransportRuntime(54)
	candidate := newTestTransportRuntime(74)
	useTestTransportRuntime(t, current)
	store, _ := authenticatedMemoryStore(t, "MacBook", current)
	fixture := useInheritedFileFixture(t)
	request := stageRequest(
		origin,
		strings.Repeat("I", 32),
		fixture.candidate(t, 3, 51, candidate.may),
		fixture.candidate(t, 4, 52, candidate.adapter),
		fixture.candidate(t, 5, 53, candidate.helper),
		candidate.may,
		candidate.adapter,
		candidate.helper,
	)
	request.CandidateMayCDHash = base64.RawURLEncoding.EncodeToString(
		testTransportIdentity(transportCodeKindMay, 99).CodeDirectoryHash,
	)
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("stage accepted candidate CDHash that disagreed with release metadata")
	}
	if decodeStoredIdentity(t, store).Transport.Staged != nil {
		t.Fatal("release exact identity mismatch mutated transport state")
	}
}

func TestUnchangedHelperCommitRequiresStagedParentAndStatusReportsStage(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	current := newTestTransportRuntime(45)
	candidate := newTestTransportRuntime(65)
	candidate.helper = current.helper
	useTestTransportRuntime(t, current)
	store, _ := authenticatedMemoryStore(t, "MacBook", current)
	fixture := useInheritedFileFixture(t)
	transactionID := strings.Repeat("F", 32)
	readCapability := fixture.capabilityOutput(t)
	staged, err := handleRequest(stageRequest(
		origin,
		transactionID,
		fixture.candidate(t, 3, 61, candidate.may),
		fixture.candidate(t, 4, 62, candidate.adapter),
		fixture.candidate(t, 5, 63, candidate.helper),
		candidate.may,
		candidate.adapter,
		candidate.helper,
	), store)
	if err != nil {
		t.Fatal(err)
	}
	_ = staged
	status, err := handleRequest(helperRequest{
		Operation: "transport-status", Origin: origin,
	}, store)
	if err != nil || status.Role != "current" || status.TransactionID != transactionID ||
		status.TransactionState != "staged" {
		t.Fatalf("current staged status = %+v, %v", status, err)
	}
	capability := readCapability()
	fixture.capability(t, capability)
	unauthorized := testTransportIdentity(transportCodeKindMay, 85)
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return unauthorized, nil
	}
	request := helperRequest{
		Operation: "transport-commit", Origin: origin, TransactionID: transactionID,
	}
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("commit accepted a parent outside the staged exact transport set")
	}
	if decodeStoredIdentity(t, store).Transport.Staged == nil {
		t.Fatal("rejected commit cleared staged state")
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return candidate.may, nil
	}
	fixture.capability(t, capability)
	status, err = handleRequest(helperRequest{
		Operation: "transport-status", Origin: origin,
	}, store)
	if err != nil || status.Role != "staged" || status.TransactionState != "staged" {
		t.Fatalf("staged caller status = %+v, %v", status, err)
	}
	fixture.capability(t, capability)
	if _, err := handleRequest(request, store); err != nil {
		t.Fatalf("unchanged-helper commit failed: %v", err)
	}
	identity := decodeStoredIdentity(t, store)
	if identity.Transport.Staged != nil ||
		!sameTransportCodeIdentity(identity.Transport.CurrentHelper, current.helper) ||
		!sameTransportSet(identity.Transport.Current, []transportCodeIdentity{
			candidate.may, candidate.adapter,
		}) {
		t.Fatal("unchanged-helper commit did not advance transports only")
	}
}

func TestAbortRequiresCurrentCallerAndIsIdempotent(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	current := newTestTransportRuntime(95)
	candidate := newTestTransportRuntime(115)
	useTestTransportRuntime(t, current)
	store, _ := authenticatedMemoryStore(t, "MacBook", current)
	fixture := useInheritedFileFixture(t)
	transactionID := strings.Repeat("G", 32)
	readCapability := fixture.capabilityOutput(t)
	if _, err := handleRequest(stageRequest(
		origin,
		transactionID,
		fixture.candidate(t, 3, 111, candidate.may),
		fixture.candidate(t, 4, 112, candidate.adapter),
		fixture.candidate(t, 5, 113, candidate.helper),
		candidate.may,
		candidate.adapter,
		candidate.helper,
	), store); err != nil {
		t.Fatal(err)
	}
	zero(readCapability())
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return candidate.may, nil
	}
	abort := helperRequest{
		Operation: "transport-abort", Origin: origin, TransactionID: transactionID,
	}
	if _, err := handleRequest(abort, store); err == nil {
		t.Fatal("staged parent was allowed to abort current trust")
	}
	directParentIdentityResolver = func(transportCodeKind) (transportCodeIdentity, error) {
		return current.may, nil
	}
	if _, err := handleRequest(abort, store); err != nil {
		t.Fatalf("current parent could not abort: %v", err)
	}
	accessMutations := len(store.accesses)
	status, err := handleRequest(helperRequest{
		Operation: "transport-status", Origin: origin,
	}, store)
	if err != nil || status.Role != "current" || status.TransactionID != transactionID ||
		status.TransactionState != "aborted" || store.access != keychainAccessSelfOnly {
		t.Fatalf("aborted status = %+v, %v", status, err)
	}
	if len(store.accesses) != accessMutations {
		t.Fatal("ordinary abort status rewrote the unchanged helper ACL")
	}
	if _, err := handleRequest(abort, store); err != nil {
		t.Fatalf("idempotent abort failed: %v", err)
	}
	if len(store.accesses) != accessMutations || store.access != keychainAccessSelfOnly {
		t.Fatal("idempotent abort rewrote the unchanged helper ACL")
	}
}

func TestCommitCapabilityFDRejectsMissingShortLongAndWrongProof(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	runtime := newTestTransportRuntime(110)
	stagedRuntime := newTestTransportRuntime(130)
	useTestTransportRuntime(t, testTransportRuntime{
		helper: runtime.helper, parent: stagedRuntime.may,
		may: runtime.may, adapter: runtime.adapter,
	})
	fixture := useInheritedFileFixture(t)
	capability := bytes.Repeat([]byte{0x5a}, commitCapabilitySize)
	digest := sha256.Sum256(capability)
	transactionID := strings.Repeat("C", 32)
	baseStore, identity := authenticatedMemoryStore(t, "MacBook", runtime)
	identity.Transport.Staged = &storedTransportTransaction{
		TransactionID:       transactionID,
		CommitCapabilitySHA: base64.RawURLEncoding.EncodeToString(digest[:]),
		Helper:              runtime.helper,
		Transports: []transportCodeIdentity{
			stagedRuntime.may, stagedRuntime.adapter,
		},
	}
	baseStore.value, baseStore.metadata, _ = encodeCredentialRecord(identity)

	for _, test := range []struct {
		name  string
		value []byte
		setFD bool
	}{
		{name: "missing"},
		{name: "short", value: capability[:31], setFD: true},
		{name: "long", value: append(append([]byte(nil), capability...), 0), setFD: true},
		{name: "wrong", value: bytes.Repeat([]byte{0x4b}, 32), setFD: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &memoryStore{
				value:    append([]byte(nil), baseStore.value...),
				metadata: append([]byte(nil), baseStore.metadata...),
				access:   keychainAccessSelfOnly,
			}
			delete(fixture.descriptors, 3)
			if oldPipe, ok := fixture.pipes[3]; ok {
				_ = oldPipe.Close()
				delete(fixture.pipes, 3)
			}
			if test.setFD {
				fixture.capability(t, test.value)
			}
			if _, err := handleRequest(helperRequest{
				Operation:     "transport-commit",
				Origin:        origin,
				TransactionID: transactionID,
			}, store); err == nil {
				t.Fatal("invalid commit capability FD was accepted")
			}
			if decodeStoredIdentity(t, store).Transport.Staged == nil {
				t.Fatal("failed commit cleared staged state")
			}
		})
	}
}

func TestCommitRetryRepairsACLAfterContentWasPersisted(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	runtime := newTestTransportRuntime(150)
	stagedRuntime := newTestTransportRuntime(170)
	useTestTransportRuntime(t, testTransportRuntime{
		helper: stagedRuntime.helper, parent: stagedRuntime.may,
		may: runtime.may, adapter: runtime.adapter,
	})
	store, identity := authenticatedMemoryStore(t, "MacBook", runtime)
	capability := bytes.Repeat([]byte{0x6c}, commitCapabilitySize)
	digest := sha256.Sum256(capability)
	transactionID := strings.Repeat("D", 32)
	identity.Transport.Staged = &storedTransportTransaction{
		TransactionID:       transactionID,
		CommitCapabilitySHA: base64.RawURLEncoding.EncodeToString(digest[:]),
		Helper:              stagedRuntime.helper,
		Transports: []transportCodeIdentity{
			stagedRuntime.may, stagedRuntime.adapter,
		},
	}
	store.value, store.metadata, _ = encodeCredentialRecord(identity)
	fixture := useInheritedFileFixture(t)
	fixture.capability(t, capability)
	failACL := true
	store.replaceHook = func(_, _ []byte, access keychainAccessPolicy) error {
		if failACL {
			failACL = false
			return errors.New("simulated ACL convergence failure")
		}
		return nil
	}
	request := helperRequest{
		Operation: "transport-bootstrap-helper", Origin: origin, TransactionID: transactionID,
	}
	if _, err := handleRequest(request, store); err == nil {
		t.Fatal("initial ACL convergence failure was hidden")
	}
	committed := decodeStoredIdentity(t, store)
	if committed.Transport.Staged != nil ||
		committed.Transport.LastFinalizedTransactionState != "committed" ||
		!committed.Transport.ACLConvergencePending {
		t.Fatal("content did not remain committed after ACL failure")
	}
	store.access = keychainAccessInvalid
	status, err := handleRequest(helperRequest{
		Operation: "transport-status", Origin: origin,
	}, store)
	if err != nil || status.TransactionState != "committed" ||
		store.access != keychainAccessSelfOnly ||
		decodeStoredIdentity(t, store).Transport.ACLConvergencePending {
		t.Fatalf("status did not repair committed ACL without capability: %+v, %v", status, err)
	}
	fixture.capability(t, capability)
	if _, err := handleRequest(request, store); err != nil {
		t.Fatalf("idempotent commit did not repair ACL: %v", err)
	}
	if store.access != keychainAccessSelfOnly {
		t.Fatal("idempotent commit did not converge self-only ACL")
	}
}

func TestBootstrapUsesPromptThenSelfOnlyAndPublicAbsentIsNotAnError(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	runtime := newTestTransportRuntime(190)
	useTestTransportRuntime(t, runtime)
	store := &memoryStore{}
	absent, err := handleRequest(helperRequest{
		Operation: "public", Origin: origin,
	}, store)
	if err != nil || absent.Found == nil || *absent.Found {
		t.Fatalf("absent public response = %+v, %v", absent, err)
	}
	if _, err := handleRequest(helperRequest{
		Operation: "ensure", Origin: origin, DisplayName: "MacBook",
	}, store); err == nil {
		t.Fatal("ensure silently bootstrapped a missing transport trust root")
	}
	fixture := useInheritedFileFixture(t)
	bootstrapRequest := helperRequest{
		Operation:              "transport-bootstrap",
		Origin:                 origin,
		DisplayName:            "MacBook",
		CandidateMaySHA256:     fixture.candidate(t, 3, 201, runtime.may),
		CandidateAdapterSHA256: fixture.candidate(t, 4, 202, runtime.adapter),
	}
	populateExpectedCandidateIdentity(&bootstrapRequest, "may", runtime.may)
	populateExpectedCandidateIdentity(&bootstrapRequest, "adapter", runtime.adapter)
	response, err := handleRequest(bootstrapRequest, store)
	if err != nil || response.Identity == nil {
		t.Fatalf("transport bootstrap failed: %+v, %v", response, err)
	}
	identity := decodeStoredIdentity(t, store)
	if identity.Transport == nil || identity.Transport.BootstrapPending ||
		store.access != keychainAccessSelfOnly {
		t.Fatalf("bootstrap did not converge durable self-only trust: %+v", identity.Transport)
	}
	if len(store.accesses) != 2 || store.accesses[0] != keychainAccessPromptRequired ||
		store.accesses[1] != keychainAccessSelfOnly {
		t.Fatalf("bootstrap access ceremony = %v", store.accesses)
	}
}

func TestBootstrapNeverAdoptsPreexistingPendingItem(t *testing.T) {
	origin := "https://onenod.example.workers.dev"
	runtime := newTestTransportRuntime(210)
	useTestTransportRuntime(t, runtime)
	store, planted := authenticatedMemoryStore(t, "Attacker requester", runtime)
	planted.Transport.BootstrapPending = true
	store.value, store.metadata, _ = encodeCredentialRecord(planted)
	original := append([]byte(nil), store.value...)
	fixture := useInheritedFileFixture(t)
	bootstrapRequest := helperRequest{
		Operation:              "transport-bootstrap",
		Origin:                 origin,
		DisplayName:            "Victim requester",
		CandidateMaySHA256:     fixture.candidate(t, 3, 211, runtime.may),
		CandidateAdapterSHA256: fixture.candidate(t, 4, 212, runtime.adapter),
	}
	populateExpectedCandidateIdentity(&bootstrapRequest, "may", runtime.may)
	populateExpectedCandidateIdentity(&bootstrapRequest, "adapter", runtime.adapter)
	if _, err := handleRequest(bootstrapRequest, store); err == nil {
		t.Fatal("fresh bootstrap adopted a preexisting pending Keychain record")
	}
	if !bytes.Equal(store.value, original) || store.access != keychainAccessSelfOnly {
		t.Fatal("rejected bootstrap mutated the planted Keychain record")
	}
}
