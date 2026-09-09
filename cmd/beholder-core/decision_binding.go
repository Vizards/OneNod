package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

const (
	decisionBindingSchemaVersion = 1
	decisionCapabilitySize       = 32
)

// operationTarget is the exact request identity observed at a trusted entry
// point. It contains no credential value or private key material. PayloadDigest
// is a SHA-256 digest of the exact in-flight protocol payload, not the payload.
type operationTarget struct {
	SchemaVersion      int    `json:"schema_version"`
	Surface            string `json:"surface"`
	Operation          string `json:"operation"`
	TargetKind         string `json:"target_kind"`
	TargetID           string `json:"target_id,omitempty"`
	KeyFingerprint     string `json:"key_fingerprint,omitempty"`
	RemoteUser         string `json:"remote_user,omitempty"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	RequestContext     string `json:"request_context,omitempty"`
	RequesterContext   string `json:"requester_context,omitempty"`
	PayloadDigest      string `json:"payload_digest"`
}

// gatekeeperDecisionFixture represents an already completed Gatekeeper result.
// It never calls a model. Beholder Core may issue a one-time capability only for
// an allow result and only for the exact operation/target it supplied to that
// decision.
type gatekeeperDecisionFixture struct {
	Disposition string
	Request     operationTarget
}

type decisionBindingStore struct {
	mu      sync.Mutex
	key     []byte
	ttl     time.Duration
	now     func() time.Time
	pending map[string]decisionBinding
	used    map[string]time.Time
}

type decisionBinding struct {
	requestRef string
	expiresAt  time.Time
}

type decisionCapability struct {
	raw []byte
}

type decisionConsumption struct {
	Matched   bool
	ErrorCode string
}

func newDecisionBindingStore(ttl time.Duration) (*decisionBindingStore, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return newDecisionBindingStoreWithKey(ttl, key, time.Now)
}

func newDecisionBindingStoreWithKey(
	ttl time.Duration,
	key []byte,
	now func() time.Time,
) (*decisionBindingStore, error) {
	if ttl <= 0 || ttl > 5*time.Minute || len(key) < 32 || now == nil {
		return nil, errors.New("invalid decision binding configuration")
	}
	return &decisionBindingStore{
		key: append([]byte(nil), key...), ttl: ttl, now: now,
		pending: map[string]decisionBinding{}, used: map[string]time.Time{},
	}, nil
}

func (store *decisionBindingStore) issue(
	decision gatekeeperDecisionFixture,
) (decisionCapability, decisionConsumption) {
	if store == nil || decision.Disposition != "allow" {
		return decisionCapability{}, decisionConsumption{ErrorCode: "gatekeeper-escalated"}
	}
	requestRef, err := store.requestRef(decision.Request)
	if err != nil {
		return decisionCapability{}, decisionConsumption{ErrorCode: "decision-request-invalid"}
	}
	capability := make([]byte, decisionCapabilitySize)
	if _, err := rand.Read(capability); err != nil {
		return decisionCapability{}, decisionConsumption{ErrorCode: "decision-capability-unavailable"}
	}
	now := store.now().UTC()
	capabilityRef := store.capabilityRef(capability)
	store.mu.Lock()
	store.expireLocked(now)
	store.pending[capabilityRef] = decisionBinding{requestRef: requestRef, expiresAt: now.Add(store.ttl)}
	store.mu.Unlock()
	return decisionCapability{raw: capability}, decisionConsumption{}
}

func (store *decisionBindingStore) consume(
	capability decisionCapability,
	actual operationTarget,
) decisionConsumption {
	if store == nil || len(capability.raw) != decisionCapabilitySize {
		return decisionConsumption{ErrorCode: "decision-binding-missing"}
	}
	actualRef, err := store.requestRef(actual)
	if err != nil {
		clear(capability.raw)
		return decisionConsumption{ErrorCode: "actual-request-invalid"}
	}
	now := store.now().UTC()
	capabilityRef := store.capabilityRef(capability.raw)
	clear(capability.raw)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	if _, replayed := store.used[capabilityRef]; replayed {
		return decisionConsumption{ErrorCode: "decision-replay"}
	}
	binding, found := store.pending[capabilityRef]
	if !found {
		return decisionConsumption{ErrorCode: "decision-binding-missing"}
	}
	delete(store.pending, capabilityRef)
	store.used[capabilityRef] = now.Add(store.ttl)
	if !hmac.Equal([]byte(binding.requestRef), []byte(actualRef)) {
		return decisionConsumption{ErrorCode: "operation-target-mismatch"}
	}
	return decisionConsumption{Matched: true}
}

func (store *decisionBindingStore) requestRef(request operationTarget) (string, error) {
	if !validOperationTarget(request) {
		return "", errors.New("invalid operation target")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := hmac.New(sha256.New, store.key)
	_, _ = digest.Write([]byte("operation-target"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(encoded)
	return "request-" + hex.EncodeToString(digest.Sum(nil)), nil
}

func (store *decisionBindingStore) capabilityRef(capability []byte) string {
	digest := hmac.New(sha256.New, store.key)
	_, _ = digest.Write([]byte("decision-capability"))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(capability)
	return "capability-" + hex.EncodeToString(digest.Sum(nil))
}

func (store *decisionBindingStore) expireLocked(now time.Time) {
	for ref, binding := range store.pending {
		if !binding.expiresAt.After(now) {
			delete(store.pending, ref)
		}
	}
	for ref, expiresAt := range store.used {
		if !expiresAt.After(now) {
			delete(store.used, ref)
		}
	}
}

func validOperationTarget(request operationTarget) bool {
	if request.SchemaVersion != decisionBindingSchemaVersion ||
		!safeDecisionField(request.Surface, 96, false) ||
		!safeDecisionField(request.Operation, 96, false) ||
		!safeDecisionField(request.TargetKind, 96, false) ||
		!safeDecisionField(request.TargetID, 1024, true) ||
		!safeDecisionField(request.KeyFingerprint, 256, true) ||
		!safeDecisionField(request.RemoteUser, 256, true) ||
		!safeDecisionField(request.HostKeyFingerprint, 256, true) ||
		!safeDecisionField(request.RequestContext, 16*1024, true) ||
		!safeDecisionField(request.RequesterContext, 1024*1024, true) ||
		len(request.PayloadDigest) != sha256.Size*2 {
		return false
	}
	if request.RequestContext != "" && !json.Valid([]byte(request.RequestContext)) {
		return false
	}
	if request.RequesterContext != "" && !json.Valid([]byte(request.RequesterContext)) {
		return false
	}
	_, err := hex.DecodeString(request.PayloadDigest)
	return err == nil
}

func safeDecisionField(value string, maximum int, optional bool) bool {
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
