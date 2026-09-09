package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

type directMayTargetDescriptor struct {
	ItemID          string   `json:"item_id"`
	FieldIDs        []string `json:"field_ids,omitempty"`
	ExpectedVersion int64    `json:"expected_version,omitempty"`
}

// directMayOperationTarget is the thin direct-may adapter fixture. It is
// called only after may has constructed the exact outbound request. The raw
// payload may contain values for mutation operations, so only its SHA-256
// digest crosses into the binding contract.
func directMayOperationTarget(
	operation, itemID string,
	fieldIDs []string,
	expectedVersion int64,
	exactPayload []byte,
) (operationTarget, error) {
	if !safeDecisionField(operation, 96, false) ||
		!safeDecisionField(itemID, 256, false) || expectedVersion < 0 ||
		len(fieldIDs) > 32 || len(exactPayload) == 0 {
		return operationTarget{}, errors.New("invalid direct may request")
	}
	fields := append([]string(nil), fieldIDs...)
	for _, fieldID := range fields {
		if !safeDecisionField(fieldID, 256, false) {
			return operationTarget{}, errors.New("invalid direct may field")
		}
	}
	if !sort.StringsAreSorted(fields) {
		return operationTarget{}, errors.New("direct may fields are not canonical")
	}
	for index := 1; index < len(fields); index++ {
		if fields[index-1] == fields[index] {
			return operationTarget{}, errors.New("duplicate direct may field")
		}
	}
	targetID, err := json.Marshal(directMayTargetDescriptor{
		ItemID: itemID, FieldIDs: fields, ExpectedVersion: expectedVersion,
	})
	if err != nil || len(targetID) > 512 {
		return operationTarget{}, errors.New("direct may target is too large")
	}
	request := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion,
		Surface:       "direct-may",
		Operation:     operation,
		TargetKind:    "onepassword-item-fields",
		TargetID:      string(targetID),
		PayloadDigest: exactPayloadDigest(exactPayload),
	}
	if !validOperationTarget(request) {
		return operationTarget{}, errors.New("invalid direct may operation target")
	}
	return request, nil
}

// sshAgentOperationTarget is the shared semantic adapter fixture for ordinary
// SSH and Git signing. OneNod's Agent already derives these facts from the
// actual SSH Agent signing payload; wrappers do not supply or interpret them.
func sshAgentOperationTarget(
	operation, itemID, keyFingerprint, remoteUser, hostKeyFingerprint string,
	exactPayload []byte,
) (operationTarget, error) {
	request := operationTarget{
		SchemaVersion:      decisionBindingSchemaVersion,
		Surface:            "ssh-agent",
		Operation:          operation,
		TargetKind:         "ssh-key",
		TargetID:           itemID,
		KeyFingerprint:     keyFingerprint,
		RemoteUser:         remoteUser,
		HostKeyFingerprint: hostKeyFingerprint,
		PayloadDigest:      exactPayloadDigest(exactPayload),
	}
	if len(exactPayload) == 0 || !validOperationTarget(request) {
		return operationTarget{}, errors.New("invalid SSH Agent operation target")
	}
	return request, nil
}

func exactPayloadDigest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
