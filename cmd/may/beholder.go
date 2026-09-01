package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	beholderProtocolSchemaVersion = 1
	beholderCoreSocketPath        = "/Library/Application Support/Beholder/run/core.sock"
	beholderBindingExtensionName  = "beholder-bind@github.com/Vizards/OneNod"
	beholderBindingVersion        = 1
	beholderMaximumWireSize       = 2 * 1024 * 1024
	beholderRoundTripTimeout      = 2 * time.Second
	beholderLeasePurposeSSH       = "ssh"
	beholderLeasePurposeGit       = "git-sign"
	beholderSSHShimBinaryName     = "ssh"
)

type beholderRoundTripFunc func(beholderWireRequest) (beholderWireResponse, error)

type beholderOperationTarget struct {
	SchemaVersion      int    `json:"schema_version"`
	Surface            string `json:"surface"`
	Operation          string `json:"operation"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id,omitempty"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	RemoteUser         string `json:"remote_user,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	PayloadDigest      string `json:"payload_digest"`
}

type beholderWireRequest struct {
	SchemaVersion int                      `json:"schema_version"`
	Kind          string                   `json:"kind"`
	ThreadID      string                   `json:"thread_id,omitempty"`
	Purpose       string                   `json:"purpose,omitempty"`
	Nonce         string                   `json:"nonce,omitempty"`
	Binding       string                   `json:"binding,omitempty"`
	Operation     *beholderOperationTarget `json:"operation_target,omitempty"`
}

type beholderWireResponse struct {
	SchemaVersion int     `json:"schema_version"`
	Accepted      bool    `json:"accepted"`
	Disposition   string  `json:"disposition,omitempty"`
	AgentSocket   string  `json:"agent_socket,omitempty"`
	Binding       string  `json:"binding,omitempty"`
	ErrorCode     *string `json:"error_code"`
}

type beholderSSHLease struct {
	AgentSocket string
}

func defaultBeholderRoundTrip(request beholderWireRequest) (beholderWireResponse, error) {
	connection, err := net.DialTimeout("unix", beholderCoreSocketPath, beholderRoundTripTimeout)
	if err != nil {
		return beholderWireResponse{}, errors.New("Beholder Core is unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(beholderRoundTripTimeout))
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return beholderWireResponse{}, errors.New("send Beholder request failed")
	}
	var response beholderWireResponse
	decoder := json.NewDecoder(io.LimitReader(connection, beholderMaximumWireSize+1))
	if decoder.Decode(&response) != nil || response.SchemaVersion != beholderProtocolSchemaVersion {
		return beholderWireResponse{}, errors.New("Beholder Core returned an invalid response")
	}
	return response, nil
}

func requestBeholderSSHLease(deps dependencies, purpose string) (beholderSSHLease, error) {
	if purpose != beholderLeasePurposeSSH && purpose != beholderLeasePurposeGit {
		return beholderSSHLease{}, errors.New("invalid Beholder SSH lease purpose")
	}
	threadID := os.Getenv("CODEX_THREAD_ID")
	if !safeBeholderToken(threadID, 8, 128) || deps.beholder == nil {
		return beholderSSHLease{}, errors.New("Beholder task binding is unavailable")
	}
	response, err := deps.beholder(beholderWireRequest{
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "ssh-proxy-lease",
		ThreadID:      threadID,
		Purpose:       purpose,
	})
	threadID = ""
	if err != nil || !response.Accepted || response.ErrorCode != nil ||
		!validBeholderAgentSocket(response.AgentSocket) {
		return beholderSSHLease{}, errors.New("Beholder SSH lease is unavailable")
	}
	return beholderSSHLease{AgentSocket: response.AgentSocket}, nil
}

func consumeBeholderAgentBinding(deps dependencies, nonce []byte) (string, error) {
	if deps.beholder == nil || len(nonce) < 16 || len(nonce) > 128 {
		return "", errors.New("Beholder Agent binding is unavailable")
	}
	encodedNonce := base64.RawURLEncoding.EncodeToString(nonce)
	response, err := deps.beholder(beholderWireRequest{
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "agent-binding-consume",
		Nonce:         encodedNonce,
	})
	if err != nil || !response.Accepted || response.ErrorCode != nil ||
		!safeBeholderToken(response.Binding, 32, 256) {
		return "", errors.New("Beholder Agent binding was rejected")
	}
	return response.Binding, nil
}

func observeBeholderAgentOperation(
	deps dependencies,
	binding string,
	target beholderOperationTarget,
) (string, error) {
	if deps.beholder == nil || !safeBeholderToken(binding, 32, 256) || !validBeholderOperationTarget(target) {
		return "escalate", errors.New("Beholder Agent operation binding is unavailable")
	}
	response, err := deps.beholder(beholderWireRequest{
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "agent-operation",
		Binding:       binding,
		Operation:     &target,
	})
	if err != nil || !response.Accepted || response.ErrorCode != nil ||
		(response.Disposition != "allow" && response.Disposition != "escalate") {
		return "escalate", errors.New("Beholder Agent operation was not decided")
	}
	return response.Disposition, nil
}

// observeBeholderDirectRequest sends only structured identifiers and a digest
// of the exact canonical outbound body. Credential values remain in the may
// process and never cross the local Beholder boundary.
func observeBeholderDirectRequest(deps dependencies, body any) {
	threadID := os.Getenv("CODEX_THREAD_ID")
	if deps.beholder == nil || !safeBeholderToken(threadID, 8, 128) {
		return
	}
	canonical, err := canonicalJSON(body)
	if err != nil {
		return
	}
	target, ok := directBeholderOperationTarget(body, canonical)
	clear(canonical)
	if !ok {
		return
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	encodedNonce := hex.EncodeToString(nonce)
	clear(nonce)
	_, _ = deps.beholder(beholderWireRequest{
		SchemaVersion: beholderProtocolSchemaVersion,
		Kind:          "direct-operation",
		ThreadID:      threadID,
		Nonce:         encodedNonce,
		Operation:     &target,
	})
	threadID = ""
}

func directBeholderOperationTarget(body any, canonical []byte) (beholderOperationTarget, bool) {
	operation := ""
	targetKind := "onepassword-item"
	itemID := ""
	fieldIDs := []string{}
	expectedVersion := int64(0)
	switch request := body.(type) {
	case createRequest:
		operation = request.Action
		itemID = request.ItemID
		fieldIDs = []string{request.FieldID}
		expectedVersion = request.ExpectedVersion
	case credentialUseRequest:
		operation = request.Action
		itemID = request.ItemID
		fieldIDs = append(fieldIDs, request.FieldIDs...)
		expectedVersion = request.ExpectedVersion
	case itemCreateRequest:
		operation = request.Action
		targetKind = "onepassword-item-create"
		for _, field := range request.Fields {
			fieldIDs = append(fieldIDs, field.FieldID)
		}
	case itemPatchRequest:
		operation = request.Action
		itemID = request.ItemID
		expectedVersion = request.ExpectedVersion
		for _, mutation := range request.Operations {
			fieldIDs = append(fieldIDs, mutation.FieldID)
		}
	case itemArchiveRequest:
		operation = request.Action
		itemID = request.ItemID
		expectedVersion = request.ExpectedVersion
	default:
		return beholderOperationTarget{}, false
	}
	if operation == "" || len(canonical) == 0 {
		return beholderOperationTarget{}, false
	}
	sort.Strings(fieldIDs)
	descriptor, err := json.Marshal(struct {
		ItemID          string   `json:"item_id,omitempty"`
		FieldIDs        []string `json:"field_ids,omitempty"`
		ExpectedVersion int64    `json:"expected_version,omitempty"`
	}{ItemID: itemID, FieldIDs: fieldIDs, ExpectedVersion: expectedVersion})
	if err != nil || len(descriptor) > 1024 {
		return beholderOperationTarget{}, false
	}
	digest := sha256.Sum256(canonical)
	target := beholderOperationTarget{
		SchemaVersion: beholderProtocolSchemaVersion,
		Surface:       "direct-may",
		Operation:     operation,
		TargetKind:    targetKind,
		TargetID:      string(descriptor),
		PayloadDigest: hex.EncodeToString(digest[:]),
	}
	return target, validBeholderOperationTarget(target)
}

func sshBeholderOperationTarget(
	operation sshOperation,
	identity servedSSHIdentity,
	data []byte,
) beholderOperationTarget {
	digest := sha256.Sum256(data)
	return beholderOperationTarget{
		SchemaVersion:      beholderProtocolSchemaVersion,
		Surface:            "ssh-agent",
		Operation:          operation.Kind,
		TargetKind:         "ssh-key",
		TargetID:           identity.catalog.ItemID,
		KeyFingerprint:     identity.catalog.Metadata.Fingerprint,
		RemoteUser:         operation.RemoteUsername,
		HostKeyFingerprint: operation.ServerHostKeyFingerprint,
		PayloadDigest:      hex.EncodeToString(digest[:]),
	}
}

func parseBeholderBindingExtension(contents []byte) ([]byte, error) {
	reader := wireReader{value: contents}
	version, err := reader.uint32()
	if err != nil || version != beholderBindingVersion {
		return nil, errors.New("invalid Beholder binding extension version")
	}
	nonce, err := reader.string()
	if err != nil || len(nonce) < 16 || len(nonce) > 128 || !reader.done() {
		return nil, errors.New("invalid Beholder binding extension nonce")
	}
	return append([]byte(nil), nonce...), nil
}

func validBeholderAgentSocket(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 103 {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode()&os.ModeSymlink == 0
}

func validBeholderOperationTarget(target beholderOperationTarget) bool {
	if target.SchemaVersion != beholderProtocolSchemaVersion ||
		!safeBeholderField(target.Surface, 96, false) ||
		!safeBeholderField(target.Operation, 96, false) ||
		!safeBeholderField(target.TargetKind, 96, false) ||
		!safeBeholderField(target.TargetID, 1024, true) ||
		!safeBeholderField(target.KeyFingerprint, 256, true) ||
		!safeBeholderField(target.RemoteUser, 256, true) ||
		!safeBeholderField(target.HostKeyFingerprint, 256, true) ||
		len(target.PayloadDigest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(target.PayloadDigest)
	return err == nil
}

func safeBeholderField(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func safeBeholderToken(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:-", character) {
			continue
		}
		return false
	}
	return true
}
