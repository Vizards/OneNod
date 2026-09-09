package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBeholderAuthorityInitializesOnceAndBindsExactTarget(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "authority.json")
	first, err := initializeBeholderAuthority(path, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := initializeBeholderAuthority(path, false)
	if err != nil || first != second {
		t.Fatalf("authority initialization was not idempotent: first=%+v second=%+v err=%v", first, second, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || !info.Mode().IsRegular() {
		t.Fatalf("authority key permissions are invalid: info=%+v err=%v", info, err)
	}
	authority, err := loadBeholderAuthority(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.close()
	authority.now = func() time.Time { return time.Unix(1_800_000_000, 0).UTC() }
	targetDigest := strings.Repeat("a", 64)
	authorization, err := authority.authorize(
		"shadow-authority-00112233445566778899",
		"33333333-3333-4333-8333-333333333333",
		targetDigest,
	)
	if err != nil || !validAuthorizationForTarget(
		authorization,
		authority,
		"shadow-authority-00112233445566778899",
		"33333333-3333-4333-8333-333333333333",
		targetDigest,
	) {
		t.Fatalf("exact target authorization failed: authorization=%+v err=%v", authorization, err)
	}
	if validAuthorizationForTarget(
		authorization,
		authority,
		"shadow-authority-00112233445566778899",
		"33333333-3333-4333-8333-333333333333",
		strings.Repeat("b", 64),
	) || validAuthorizationForTarget(
		authorization,
		authority,
		"shadow-authority-00112233445566778899",
		"another-requester",
		targetDigest,
	) {
		t.Fatal("authority signature was reusable for a different target or requester")
	}
}

func TestBeholderAuthorityMatchesGatewayInteroperabilityVector(t *testing.T) {
	seed, err := base64.RawURLEncoding.Strict().DecodeString(
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(publicKey)
	authority := &beholderAuthority{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      base64.RawURLEncoding.EncodeToString(digest[:]),
		now:        func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
	defer authority.close()
	if got, want := base64.RawURLEncoding.EncodeToString(authority.publicKey),
		"A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"; got != want {
		t.Fatalf("public key mismatch: got %q want %q", got, want)
	}
	if got, want := authority.keyID,
		"Vkdap1RjR0wChd9dvyvKtz2mUTWIOem3dIGy6rEHcIw"; got != want {
		t.Fatalf("key ID mismatch: got %q want %q", got, want)
	}
	authorization, err := authority.authorize(
		"shadow-vector-00112233445566778899",
		"0199ad30-f672-7449-933e-968aa84f0342",
		"08b31c4def69da6356b06665207399b4540d06797b70ceb47467ab5cc155ac62",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := authorization.Signature,
		"yKeTMU2ZEkc9W2E-PSaevQBpTtYnst5BUxgzECrAekLJrNzgZlY7T7zCmcwYZX0dLvqEfXzYJgDp7VfPy8sHCQ"; got != want {
		t.Fatalf("signature mismatch: got %q want %q", got, want)
	}
}

func TestAuthoritativeGatekeeperAllowProducesBoundAuthorization(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-authority-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableDigest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(executableDigest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(executableDigest[:]),
	}
	serverError := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		if request.Mode != "authoritative" {
			serverError <- &unexpectedAuthorityMode{mode: request.Mode}
			return
		}
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion,
			RequestID:     request.RequestID, EvidenceID: request.RequestID,
			Decision: "allow", Reason: "The exact request is task-consistent.",
			ModelCalled: true, ModelUsed: true,
		})
	}()

	authorityPath := filepath.Join(root, "authority.json")
	if _, err := initializeBeholderAuthority(authorityPath, false); err != nil {
		t.Fatal(err)
	}
	authority, err := loadBeholderAuthority(authorityPath, false)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newBrokerFixture(t)
	broker := fixture.core
	if r := fixture.registerPrimaryHost(); !r.Accepted {
		t.Fatal(r)
	}
	response := fixture.checkPrimaryRequest()
	broker.trustMode, broker.gatekeeper, broker.authority = "production", client, authority
	defer broker.close()
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may",
		Operation: "secret.read", TargetKind: "onepassword-item-fields",
		TargetID:      `{"item_id":"fixture","field_ids":["credential"]}`,
		PayloadDigest: strings.Repeat("c", 64),
	}
	requesterDeviceID := "33333333-3333-4333-8333-333333333333"
	disposition, evidenceID, authorization := broker.runGatekeeperWithEvidence(
		&response,
		target,
		requesterDeviceID,
	)
	if serverErr := <-serverError; serverErr != nil {
		t.Fatal(serverErr)
	}
	if disposition != "allow" || evidenceID == "" ||
		!validAuthorizationForTarget(
			authorization,
			authority,
			evidenceID,
			requesterDeviceID,
			target.PayloadDigest,
		) {
		t.Fatalf("authoritative allow did not produce a bound authorization: disposition=%q evidence=%q authorization=%+v", disposition, evidenceID, authorization)
	}
	if response.Envelope.Gatekeeper.Disposition != "allow" ||
		!response.Envelope.Gatekeeper.Executed || !response.Envelope.Gatekeeper.ModelUsed ||
		!response.Envelope.Gatekeeper.ProductionAuthoritative {
		t.Fatalf("authoritative evidence was incomplete: %+v", response.Envelope.Gatekeeper)
	}
}

func TestInterruptedContextCannotReceiveAuthorizationAfterModelAllow(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "bh-authority-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	socketPath := filepath.Join(root, "gatekeeper.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	executableDigest := sha256.Sum256(executableBytes)
	clear(executableBytes)
	identity, err := captureTrustedExecutable(executable, hex.EncodeToString(executableDigest[:]), false)
	if err != nil {
		t.Fatal(err)
	}
	client := &shadowGatekeeperClient{
		socketPath: socketPath, timeout: 2 * time.Second,
		allowedUID: uint32(os.Geteuid()), trustedProcess: identity,
		coreBinarySHA256: hex.EncodeToString(executableDigest[:]),
	}
	serverError := make(chan error, 1)
	beforeReply := make(chan func(), 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverError <- acceptErr
			return
		}
		defer connection.Close()
		var request gatekeeperLocalRequest
		if decodeErr := json.NewDecoder(connection).Decode(&request); decodeErr != nil {
			serverError <- decodeErr
			return
		}
		if request.Mode != "authoritative" {
			serverError <- &unexpectedAuthorityMode{mode: request.Mode}
			return
		}
		(<-beforeReply)()
		serverError <- json.NewEncoder(connection).Encode(gatekeeperLocalResponse{
			SchemaVersion: gatekeeperWireSchemaVersion,
			RequestID:     request.RequestID, EvidenceID: request.RequestID,
			Decision: "allow", Reason: "The exact request is task-consistent.",
			ModelCalled: true, ModelUsed: true,
		})
	}()

	authorityPath := filepath.Join(root, "authority.json")
	if _, err := initializeBeholderAuthority(authorityPath, false); err != nil {
		t.Fatal(err)
	}
	authority, err := loadBeholderAuthority(authorityPath, false)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newBrokerFixture(t)
	broker := fixture.core
	if r := fixture.registerPrimaryHost(); !r.Accepted {
		t.Fatal(r)
	}
	response := fixture.checkPrimaryRequest()
	broker.trustMode, broker.gatekeeper, broker.authority = "production", client, authority
	defer broker.close()
	target := operationTarget{
		SchemaVersion: decisionBindingSchemaVersion, Surface: "direct-may",
		Operation: "secret.read", TargetKind: "onepassword-item-fields",
		TargetID:      `{"item_id":"fixture","field_ids":["credential"]}`,
		PayloadDigest: strings.Repeat("c", 64),
	}
	requesterDeviceID := "33333333-3333-4333-8333-333333333333"
	beforeReply <- func() {
		broker.mu.Lock()
		claim := broker.claimsByToolRef[broker.claimRefByTool[response.contextToolUseRef]]
		broker.removeClaimLocked(claim)
		broker.mu.Unlock()
	}
	disposition, evidenceID, authorization := broker.runGatekeeperWithEvidence(
		&response,
		target,
		requesterDeviceID,
	)
	if serverErr := <-serverError; serverErr != nil {
		t.Fatal(serverErr)
	}
	if disposition != "escalate" || evidenceID == "" || authorization != nil || response.Envelope.Gatekeeper.ErrorCode == nil || *response.Envelope.Gatekeeper.ErrorCode != "execution-context-ended" {
		t.Fatalf("ended context received authority: disposition=%s authorization=%v", disposition, authorization)
	}
}

type unexpectedAuthorityMode struct{ mode string }

func (failure *unexpectedAuthorityMode) Error() string {
	return "unexpected Gatekeeper mode: " + failure.mode
}
