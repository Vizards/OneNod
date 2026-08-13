package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	keychainHelperBinaryName      = "onenod-keychain-helper"
	keychainHelperProtocol        = 3
	maxHelperResponseBytes        = 64 * 1024
	keychainHelperTimeout         = 15 * time.Second
	keychainHelperCeremonyTimeout = 5 * time.Minute
)

var currentExecutablePath = os.Executable

type keychainHelperRequest struct {
	ApplicationEvidence               string `json:"application_evidence,omitempty"`
	CandidateAdapterArchitecture      string `json:"candidate_adapter_architecture,omitempty"`
	CandidateAdapterCDHash            string `json:"candidate_adapter_cdhash,omitempty"`
	CandidateAdapterRequirementSHA256 string `json:"candidate_adapter_designated_requirement_data_sha256,omitempty"`
	CandidateAdapterSHA256            string `json:"candidate_adapter_sha256,omitempty"`
	CandidateHelperArchitecture       string `json:"candidate_helper_architecture,omitempty"`
	CandidateHelperCDHash             string `json:"candidate_helper_cdhash,omitempty"`
	CandidateHelperRequirementSHA256  string `json:"candidate_helper_designated_requirement_data_sha256,omitempty"`
	CandidateHelperSHA256             string `json:"candidate_helper_sha256,omitempty"`
	CandidateMayArchitecture          string `json:"candidate_may_architecture,omitempty"`
	CandidateMayCDHash                string `json:"candidate_may_cdhash,omitempty"`
	CandidateMayRequirementSHA256     string `json:"candidate_may_designated_requirement_data_sha256,omitempty"`
	CandidateMaySHA256                string `json:"candidate_may_sha256,omitempty"`
	CanonicalBody                     string `json:"canonical_body,omitempty"`
	DisplayName                       string `json:"display_name,omitempty"`
	Message                           string `json:"message,omitempty"`
	Operation                         string `json:"operation"`
	Origin                            string `json:"origin,omitempty"`
	Slot                              string `json:"slot,omitempty"`
	TransactionID                     string `json:"transaction_id,omitempty"`
}

type keychainHelperResponse struct {
	Application            *clientObservation `json:"application,omitempty"`
	ApplicationAttestation string             `json:"application_attestation,omitempty"`
	Error                  string             `json:"error,omitempty"`
	Found                  *bool              `json:"found,omitempty"`
	Identity               *struct {
		DeviceID    string `json:"device_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
		Version     int    `json:"version"`
	} `json:"identity,omitempty"`
	OK               bool   `json:"ok"`
	Protocol         int    `json:"protocol,omitempty"`
	Role             string `json:"role,omitempty"`
	Signature        string `json:"signature,omitempty"`
	Source           string `json:"source_commit,omitempty"`
	Version          string `json:"version,omitempty"`
	TransactionID    string `json:"transaction_id,omitempty"`
	TransactionState string `json:"transaction_state,omitempty"`
}

type transportHelperStatus struct {
	Role             string `json:"role"`
	TransactionID    string `json:"transaction_id,omitempty"`
	TransactionState string `json:"transaction_state,omitempty"`
}

func installedKeychainHelperPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for Keychain helper failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "libexec", keychainHelperBinaryName), nil
}

func callKeychainHelper(
	request keychainHelperRequest,
	evidence ...applicationEvidence,
) (keychainHelperResponse, error) {
	if len(evidence) > 1 {
		return keychainHelperResponse{}, errors.New("Keychain helper accepts at most one application evidence source")
	}
	var files []*os.File
	if len(evidence) == 1 && evidence[0].PeerFile != nil {
		files = []*os.File{evidence[0].PeerFile}
	}
	return callKeychainHelperWithFiles(request, files)
}

// callKeychainHelperWithFiles maps files in order to the helper's inherited
// descriptors beginning at FD 3. Callers must use a dedicated operation: FD 3
// is application socket evidence for application/sign, may for bootstrap/stage,
// and the one-time capability for commit. Those routes are never combined.
func callKeychainHelperWithFiles(
	request keychainHelperRequest,
	files []*os.File,
) (keychainHelperResponse, error) {
	timeout := keychainHelperTimeout
	if request.Operation == "transport-bootstrap" || request.Operation == "transport-bootstrap-helper" {
		timeout = keychainHelperCeremonyTimeout
	}
	return callKeychainHelperWithFilesTimeout(request, files, timeout)
}

func callKeychainHelperWithFilesTimeout(
	request keychainHelperRequest,
	files []*os.File,
	timeout time.Duration,
) (keychainHelperResponse, error) {
	path, err := installedKeychainHelperPath()
	if err != nil {
		return keychainHelperResponse{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o100 == 0 || info.Mode().Perm()&0o022 != 0 {
		return keychainHelperResponse{}, errors.New("Keychain helper path must be an owner-executable, non-writable regular file, not a symlink")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return keychainHelperResponse{}, errors.New("Keychain helper must be owned by the current macOS user")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return keychainHelperResponse{}, errors.New("encode Keychain helper request failed")
	}
	defer zeroBytes(encoded)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path)
	// The helper needs no ambient configuration. An empty environment keeps its
	// stable executable identity from being weakened by loader, language-runtime,
	// credential, proxy, or tool-specific variables inherited from the caller.
	command.Env = []string{}
	command.ExtraFiles = files
	command.Stdin = bytes.NewReader(encoded)
	command.Stderr = io.Discard
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return keychainHelperResponse{}, errors.New("create private Keychain helper response pipe failed")
	}
	if err := command.Start(); err != nil {
		return keychainHelperResponse{}, errors.New("Keychain helper failed to start")
	}
	responseBytes, readErr := io.ReadAll(io.LimitReader(stdoutPipe, maxHelperResponseBytes+1))
	waitErr := command.Wait()
	if ctx.Err() != nil {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper timed out")
	}
	if readErr != nil || waitErr != nil {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper failed")
	}
	if len(responseBytes) == 0 || len(responseBytes) > maxHelperResponseBytes {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper returned an invalid response size")
	}
	defer zeroBytes(responseBytes)
	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()
	var response keychainHelperResponse
	if err := decoder.Decode(&response); err != nil {
		return keychainHelperResponse{}, errors.New("Keychain helper returned invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return keychainHelperResponse{}, errors.New("Keychain helper returned trailing data")
	}
	if !response.OK {
		if response.Error == "" {
			return keychainHelperResponse{}, errors.New("Keychain helper rejected the operation")
		}
		return keychainHelperResponse{}, fmt.Errorf("Keychain helper: %s", response.Error)
	}
	return response, nil
}

func openExactTransportCandidates(paths ...string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			for _, opened := range files {
				_ = opened.Close()
			}
			return nil, errors.New("open exact-build transport candidate failed")
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			_ = file.Close()
			for _, opened := range files {
				_ = opened.Close()
			}
			return nil, errors.New("exact-build transport candidate must be a regular file")
		}
		files = append(files, file)
	}
	return files, nil
}

func closeExactTransportCandidates(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func currentTransportCandidatePaths() (string, string, error) {
	mayPath, err := currentExecutablePath()
	if err != nil {
		return "", "", errors.New("resolve running may executable failed")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", errors.New("resolve home for may SSH adapter failed")
	}
	return mayPath, filepath.Join(home, userAgentDirectoryName, "bin", gitSignAdapterBinaryName), nil
}

func transportCandidateDigest(file *os.File) (string, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxReleaseArtifactBytes {
		return "", errors.New("exact-build transport candidate is not a bounded regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(file, 0, info.Size())); err != nil {
		return "", errors.New("hash exact-build transport candidate failed")
	}
	infoAfter, err := file.Stat()
	if err != nil || !os.SameFile(info, infoAfter) || info.Size() != infoAfter.Size() ||
		info.ModTime() != infoAfter.ModTime() {
		return "", errors.New("exact-build transport candidate changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func bootstrapRequesterTransport(origin, slot, displayName string) (*requesterCredential, error) {
	mayPath, adapterPath, err := currentTransportCandidatePaths()
	if err != nil {
		return nil, err
	}
	files, err := openExactTransportCandidates(mayPath, adapterPath)
	if err != nil {
		return nil, err
	}
	defer closeExactTransportCandidates(files)
	mayDigest, err := transportCandidateDigest(files[0])
	if err != nil {
		return nil, err
	}
	adapterDigest, err := transportCandidateDigest(files[1])
	if err != nil {
		return nil, err
	}
	receipt, found, err := readLocalInstallReceipt()
	if err != nil || !found {
		return nil, errors.New("verified local install receipt is required for requester transport bootstrap")
	}
	if mayDigest != receipt.Files["bin/may"] ||
		adapterDigest != receipt.Files["bin/"+gitSignAdapterBinaryName] {
		return nil, errors.New("running requester transport differs from its verified install receipt")
	}
	response, err := callKeychainHelperWithFiles(keychainHelperRequest{
		Operation: "transport-bootstrap", Origin: origin, Slot: slot,
		DisplayName: displayName, CandidateMaySHA256: mayDigest,
		CandidateAdapterSHA256:            adapterDigest,
		CandidateMayArchitecture:          receipt.ExactCodeIdentities.May.Architecture,
		CandidateMayCDHash:                receipt.ExactCodeIdentities.May.CodeDirectoryHash,
		CandidateMayRequirementSHA256:     receipt.ExactCodeIdentities.May.DesignatedRequirementDataSHA256,
		CandidateAdapterArchitecture:      receipt.ExactCodeIdentities.MaySSHSign.Architecture,
		CandidateAdapterCDHash:            receipt.ExactCodeIdentities.MaySSHSign.CodeDirectoryHash,
		CandidateAdapterRequirementSHA256: receipt.ExactCodeIdentities.MaySSHSign.DesignatedRequirementDataSHA256,
	}, files)
	if err != nil {
		return nil, err
	}
	return helperResponseCredential(response)
}

func queryTransportHelperStatus(origin, slot string) (transportHelperStatus, error) {
	response, err := callKeychainHelper(keychainHelperRequest{
		Operation: "transport-status", Origin: origin, Slot: slot,
	})
	if err != nil {
		return transportHelperStatus{}, err
	}
	status := transportHelperStatus{
		Role: response.Role, TransactionID: response.TransactionID,
		TransactionState: response.TransactionState,
	}
	if status.Role != "none" && status.Role != "current" && status.Role != "staged" {
		return transportHelperStatus{}, errors.New("Keychain helper returned an invalid transport role")
	}
	if status.TransactionID != "" && !transportTransactionPattern.MatchString(status.TransactionID) {
		return transportHelperStatus{}, errors.New("Keychain helper returned an invalid transport transaction")
	}
	if status.TransactionState != "" && status.TransactionState != "staged" &&
		status.TransactionState != "committed" && status.TransactionState != "aborted" {
		return transportHelperStatus{}, errors.New("Keychain helper returned an invalid transport state")
	}
	return status, nil
}

func stageTransportUpdateExpected(
	origin, slot, transactionID, mayPath, adapterPath, helperPath,
	mayDigest, adapterDigest, helperDigest string,
	mayIdentity, adapterIdentity, helperIdentity exactBuildRuntimeIdentity,
) ([]byte, error) {
	if !digestPattern.MatchString(mayDigest) || !digestPattern.MatchString(adapterDigest) ||
		!digestPattern.MatchString(helperDigest) {
		return nil, errors.New("verified exact-build transport digests are invalid")
	}
	files, err := openExactTransportCandidates(mayPath, adapterPath, helperPath)
	if err != nil {
		return nil, err
	}
	defer closeExactTransportCandidates(files)
	capabilityRead, capabilityWrite, err := os.Pipe()
	if err != nil {
		return nil, errors.New("create exact-build transport capability pipe failed")
	}
	defer capabilityRead.Close()
	files = append(files, capabilityWrite)
	_, err = callKeychainHelperWithFiles(keychainHelperRequest{
		Operation: "transport-stage", Origin: origin, Slot: slot,
		TransactionID: transactionID, CandidateMaySHA256: mayDigest,
		CandidateAdapterSHA256: adapterDigest, CandidateHelperSHA256: helperDigest,
		CandidateMayArchitecture:          mayIdentity.Architecture,
		CandidateMayCDHash:                mayIdentity.CodeDirectoryHash,
		CandidateMayRequirementSHA256:     mayIdentity.DesignatedRequirementDataSHA256,
		CandidateAdapterArchitecture:      adapterIdentity.Architecture,
		CandidateAdapterCDHash:            adapterIdentity.CodeDirectoryHash,
		CandidateAdapterRequirementSHA256: adapterIdentity.DesignatedRequirementDataSHA256,
		CandidateHelperArchitecture:       helperIdentity.Architecture,
		CandidateHelperCDHash:             helperIdentity.CodeDirectoryHash,
		CandidateHelperRequirementSHA256:  helperIdentity.DesignatedRequirementDataSHA256,
	}, files)
	_ = capabilityWrite.Close()
	if err != nil {
		return nil, err
	}
	capability, err := io.ReadAll(io.LimitReader(capabilityRead, 33))
	if err != nil || len(capability) != 32 {
		zeroBytes(capability)
		return nil, errors.New("Keychain helper returned an invalid one-time transport capability pipe")
	}
	return capability, nil
}

func finalizeTransportUpdate(
	origin, slot, transactionID, operation string, capabilityFile *os.File,
) error {
	if operation != "transport-commit" && operation != "transport-bootstrap-helper" {
		return errors.New("invalid exact-build transport finalize operation")
	}
	if capabilityFile == nil {
		return errors.New("exact-build transport capability is unavailable")
	}
	_, err := callKeychainHelperWithFiles(keychainHelperRequest{
		Operation: operation, Origin: origin, Slot: slot, TransactionID: transactionID,
	}, []*os.File{capabilityFile})
	return err
}

func abortTransportUpdateWithHelper(origin, slot, transactionID string) error {
	_, err := callKeychainHelper(keychainHelperRequest{
		Operation: "transport-abort", Origin: origin, Slot: slot,
		TransactionID: transactionID,
	})
	return err
}

func runInternalTransportFinalize(args []string) error {
	if len(args) != 4 {
		return errors.New("invalid internal exact-build transport invocation")
	}
	operation, origin, slot, transactionID := args[0], args[1], args[2], args[3]
	parsed, err := parseGatewayOrigin(origin)
	if err != nil || parsed.String() != origin || !requesterSlotPattern.MatchString(slot) ||
		!transportTransactionPattern.MatchString(transactionID) {
		return errors.New("invalid internal exact-build transport invocation")
	}
	if operation == "abort" {
		return abortTransportUpdateWithHelper(origin, slot, transactionID)
	}
	if operation == "status" {
		status, err := queryTransportHelperStatus(origin, slot)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	if operation != "commit" && operation != "bootstrap-helper" {
		return errors.New("invalid internal exact-build transport operation")
	}
	capability := os.NewFile(3, "onenod-transport-capability")
	if capability == nil {
		return errors.New("exact-build transport capability pipe is unavailable")
	}
	defer capability.Close()
	info, err := capability.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("exact-build transport capability must arrive through an anonymous pipe")
	}
	helperOperation := "transport-" + operation
	return finalizeTransportUpdate(origin, slot, transactionID, helperOperation, capability)
}

func runExactTransportStatus(
	mayPath, origin, slot, transactionID string,
) (transportHelperStatus, error) {
	command, err := newExactBuildMayCommand(
		mayPath, "__transport-finalize", "status", origin, slot, transactionID,
	)
	if err != nil {
		return transportHelperStatus{}, err
	}
	command.Stdin = nil
	command.Stderr = io.Discard
	output, err := command.Output()
	if err != nil || len(output) == 0 || len(output) > 4096 {
		zeroBytes(output)
		return transportHelperStatus{}, errors.New("exact-build may could not authenticate transport status")
	}
	defer zeroBytes(output)
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	var status transportHelperStatus
	if decoder.Decode(&status) != nil || ensureDecoderEOF(decoder) != nil ||
		(status.Role != "current" && status.Role != "staged") ||
		status.TransactionID != transactionID ||
		(status.TransactionState != "staged" && status.TransactionState != "committed" &&
			status.TransactionState != "aborted") {
		return transportHelperStatus{}, errors.New("exact-build may returned invalid transport status")
	}
	return status, nil
}

func runStagedTransportFinalize(
	mayPath, origin, slot, transactionID string,
	helperChanged bool,
	capability []byte,
) error {
	if len(capability) != 32 {
		return errors.New("exact-build transport capability is invalid")
	}
	operation := "commit"
	if helperChanged {
		operation = "bootstrap-helper"
	}
	command, err := newExactBuildMayCommand(
		mayPath, "__transport-finalize", operation, origin, slot, transactionID,
	)
	if err != nil {
		return err
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return errors.New("create exact-build transport capability pipe failed")
	}
	defer readPipe.Close()
	if _, err := writePipe.Write(capability); err != nil {
		_ = writePipe.Close()
		return errors.New("write exact-build transport capability pipe failed")
	}
	if err := writePipe.Close(); err != nil {
		return errors.New("seal exact-build transport capability pipe failed")
	}
	command.ExtraFiles = []*os.File{readPipe}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("staged exact-build may could not finalize transport trust")
	}
	return nil
}

func runCurrentTransportAbort(mayPath, origin, slot, transactionID string) error {
	command, err := newExactBuildMayCommand(
		mayPath, "__transport-finalize", "abort", origin, slot, transactionID,
	)
	if err != nil {
		return err
	}
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		return errors.New("current exact-build may could not abort transport trust")
	}
	return nil
}

func newExactBuildMayCommand(mayPath string, arguments ...string) (*exec.Cmd, error) {
	environment, err := exactBuildMayEnvironment()
	if err != nil {
		return nil, err
	}
	command := exec.Command(mayPath, arguments...)
	command.Env = environment
	return command, nil
}

func exactBuildMayEnvironment() ([]string, error) {
	if os.Getuid() != os.Geteuid() {
		return nil, errors.New("resolve canonical account home for exact-build may failed")
	}
	current, err := user.Current()
	if err != nil || current == nil || current.Uid != strconv.Itoa(os.Geteuid()) ||
		current.HomeDir == "" || !filepath.IsAbs(current.HomeDir) ||
		filepath.Clean(current.HomeDir) != current.HomeDir ||
		strings.IndexByte(current.HomeDir, 0) >= 0 {
		return nil, errors.New("resolve canonical account home for exact-build may failed")
	}
	return []string{"HOME=" + current.HomeDir}, nil
}

func helperResponseCredential(
	response keychainHelperResponse,
) (*requesterCredential, error) {
	if response.Identity == nil {
		return nil, errors.New("Keychain helper omitted public identity metadata")
	}
	return &requesterCredential{
		DeviceID: response.Identity.DeviceID, DisplayName: response.Identity.DisplayName,
		PublicKey: response.Identity.PublicKey, Version: response.Identity.Version,
	}, nil
}

func ensureRequesterWithHelper(origin, slot, displayName string) (*requesterCredential, bool, error) {
	status, err := queryTransportHelperStatus(origin, slot)
	if err != nil {
		return nil, false, err
	}
	if status.Role == "none" {
		credential, err := bootstrapRequesterTransport(origin, slot, displayName)
		return credential, err == nil, err
	}
	if status.Role != "current" {
		return nil, false, errors.New("requester transport update is incomplete; finish or recover the verified update first")
	}
	existing, found, err := loadRequesterFromHelperCurrent(origin, slot)
	if err != nil {
		return nil, false, err
	}
	if found {
		if existing.DisplayName != displayName {
			return nil, false, fmt.Errorf(
				"Keychain already contains requester %q; refusing to overwrite it",
				existing.DisplayName,
			)
		}
		return existing, false, nil
	}
	return nil, false, errors.New("Keychain helper transport exists without requester identity metadata")
}

func loadRequesterFromHelper(origin, slot string) (*requesterCredential, bool, error) {
	status, err := queryTransportHelperStatus(origin, slot)
	if err != nil {
		return nil, false, err
	}
	if status.Role == "none" {
		return nil, false, nil
	}
	if status.Role != "current" {
		return nil, false, errors.New("requester transport update is incomplete; finish or recover the verified update first")
	}
	return loadRequesterFromHelperCurrent(origin, slot)
}

func loadRequesterFromHelperCurrent(origin, slot string) (*requesterCredential, bool, error) {
	response, err := callKeychainHelper(keychainHelperRequest{
		Operation: "public", Origin: origin, Slot: slot,
	})
	if err != nil {
		return nil, false, err
	}
	if response.Found == nil || !*response.Found {
		return nil, false, nil
	}
	credential, err := helperResponseCredential(response)
	return credential, true, err
}

func signRequesterWithHelper(
	origin,
	slot string,
	message,
	canonicalBody []byte,
	evidence *applicationEvidence,
) ([]byte, []byte, error) {
	request := keychainHelperRequest{
		Operation: "sign", Origin: origin, Slot: slot,
		Message: base64.RawURLEncoding.EncodeToString(message),
	}
	var evidenceArgs []applicationEvidence
	if evidence != nil {
		request.ApplicationEvidence = evidence.Kind
		request.CanonicalBody = base64.RawURLEncoding.EncodeToString(canonicalBody)
		evidenceArgs = append(evidenceArgs, *evidence)
	}
	response, err := callKeychainHelper(request, evidenceArgs...)
	if err != nil {
		return nil, nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(response.Signature)
	if err != nil || len(signature) != 64 {
		return nil, nil, errors.New("Keychain helper returned an invalid signature")
	}
	var attestation []byte
	if response.ApplicationAttestation != "" {
		attestation, err = base64.RawURLEncoding.Strict().DecodeString(
			response.ApplicationAttestation,
		)
		if err != nil || len(attestation) != 64 {
			zeroBytes(signature)
			return nil, nil, errors.New("Keychain helper returned an invalid application attestation")
		}
	}
	return signature, attestation, nil
}

func observeApplicationWithHelper(
	origin string,
	slot string,
	evidence applicationEvidence,
) (clientObservation, error) {
	response, err := callKeychainHelper(keychainHelperRequest{
		ApplicationEvidence: evidence.Kind,
		Operation:           "application",
		Origin:              origin,
		Slot:                slot,
	}, evidence)
	if err != nil {
		return clientObservation{}, err
	}
	if response.Application == nil {
		return clientObservation{}, errors.New("Keychain helper omitted application identity")
	}
	observation := *response.Application
	if observation.Application == "" || observation.Source == "" ||
		(observation.Identity.Assurance != applicationAssuranceVerified &&
			observation.Identity.Assurance != applicationAssuranceUnverified) {
		return clientObservation{}, errors.New("Keychain helper returned an invalid application identity")
	}
	return observation, nil
}

func inspectInstalledKeychainHelper() (keychainHelperResponse, error) {
	response, err := callKeychainHelper(keychainHelperRequest{Operation: "hello"})
	if err != nil {
		return keychainHelperResponse{}, err
	}
	if response.Protocol != keychainHelperProtocol || response.Version == "" {
		return keychainHelperResponse{}, errors.New("installed Keychain helper protocol is unsupported")
	}
	return response, nil
}
