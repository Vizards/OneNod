package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const sessionBindExtensionName = "session-bind@openssh.com"

type sshSignRequest struct {
	Action               string                   `json:"action"`
	Algorithm            string                   `json:"algorithm"`
	AuthorizationSession *sshAuthorizationSession `json:"authorization_session,omitempty"`
	Client               clientObservation        `json:"client"`
	Data                 string                   `json:"data"`
	ExpectedFingerprint  string                   `json:"expected_fingerprint"`
	ExpectedVersion      int64                    `json:"expected_version"`
	IdempotencyKey       string                   `json:"idempotency_key"`
	ItemID               string                   `json:"item_id"`
	Operation            sshOperation             `json:"operation"`
}

type sshAuthorizationSession struct {
	AgentInstancePublicKey string `json:"agent_instance_public_key"`
	Proof                  string `json:"proof,omitempty"`
	ScopeID                string `json:"scope_id"`
	ScopeKind              string `json:"scope_kind"`
}

type localClientContext struct {
	Evidence    applicationEvidence
	Observation clientObservation
	ScopeID     string
	ScopeKind   string
}

type sshOperation struct {
	AuthenticationMethod     string `json:"authentication_method,omitempty"`
	Kind                     string `json:"kind"`
	Namespace                string `json:"namespace,omitempty"`
	RemoteUsername           string `json:"remote_username,omitempty"`
	ServerHostKeyFingerprint string `json:"server_host_key_fingerprint,omitempty"`
	Service                  string `json:"service,omitempty"`
	SessionBinding           string `json:"session_binding,omitempty"`
	SessionIDFingerprint     string `json:"session_id_fingerprint,omitempty"`
}

type sshSessionBinding struct {
	hostKeyBlob []byte
	sessionID   []byte
}

type sshUserauthRequest struct {
	authenticationMethod string
	keyBlob              []byte
	remoteUsername       string
	service              string
	sessionID            []byte
	serverHostKeyBlob    []byte
}

type sshSignConsumeResponse struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	ItemID        string `json:"item_id"`
	OK            bool   `json:"ok"`
	PublicKeyBlob string `json:"public_key_blob"`
	RequestID     string `json:"request_id"`
	SignatureBlob string `json:"signature_blob"`
	Status        string `json:"status"`
	Version       int64  `json:"version"`
}

func sshOperationForPayload(
	data []byte,
	keyBlob []byte,
	binding *sshSessionBinding,
) sshOperation {
	if namespace, ok := parseSSHSIGNamespace(data); ok && namespace == "git" {
		return sshOperation{Kind: "git.ssh-signature", Namespace: "git"}
	}
	request, err := parseSSHUserauthRequest(data)
	if err != nil || !bytes.Equal(request.keyBlob, keyBlob) {
		return sshOperation{Kind: "ssh.opaque-signature"}
	}
	operation := sshOperation{
		AuthenticationMethod: request.authenticationMethod,
		Kind:                 "ssh.authentication",
		RemoteUsername:       request.remoteUsername,
		Service:              request.service,
		SessionBinding:       "unavailable",
		SessionIDFingerprint: byteFingerprint(request.sessionID),
	}
	if binding != nil && verifySSHUserauthBinding(request, *binding, keyBlob) == nil {
		hostKey, err := ssh.ParsePublicKey(binding.hostKeyBlob)
		if err == nil {
			operation.ServerHostKeyFingerprint = ssh.FingerprintSHA256(hostKey)
			operation.SessionBinding = "verified"
		}
	}
	return operation
}

func parseSSHSIGNamespace(data []byte) (string, bool) {
	if !bytes.HasPrefix(data, []byte("SSHSIG")) {
		return "", false
	}
	reader := wireReader{value: data[6:]}
	namespace, err := reader.string()
	if err != nil || len(namespace) == 0 || len(namespace) > 64 {
		return "", false
	}
	if _, err := reader.string(); err != nil {
		return "", false
	}
	hashAlgorithm, err := reader.string()
	if err != nil || (string(hashAlgorithm) != "sha256" && string(hashAlgorithm) != "sha512") {
		return "", false
	}
	digest, err := reader.string()
	if err != nil || len(digest) == 0 || !reader.done() {
		return "", false
	}
	return string(namespace), true
}

func attachSshAuthorizationSession(
	request *sshSignRequest,
	localClient localClientContext,
	sessionKey ed25519.PrivateKey,
) error {
	if len(sessionKey) != ed25519.PrivateKeySize ||
		localClient.ScopeID == "" ||
		localClient.ScopeKind != "application" {
		return nil
	}
	request.AuthorizationSession = &sshAuthorizationSession{
		AgentInstancePublicKey: base64.RawURLEncoding.EncodeToString(
			sessionKey.Public().(ed25519.PublicKey),
		),
		ScopeID:   localClient.ScopeID,
		ScopeKind: localClient.ScopeKind,
	}
	proofMaterial, err := canonicalJSON(request)
	if err != nil {
		return errors.New("encode SSH authorization session proof failed")
	}
	request.AuthorizationSession.Proof = base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(sessionKey, proofMaterial),
	)
	return nil
}

func signatureAlgorithm(keyAlgorithm string, flags uint32) (string, error) {
	if keyAlgorithm == "ssh-rsa" {
		switch sshagent.SignatureFlags(flags) {
		case sshagent.SignatureFlagRsaSha256:
			return "rsa-sha2-256", nil
		case sshagent.SignatureFlagRsaSha512:
			return "rsa-sha2-512", nil
		default:
			return "", errors.New("RSA-SHA1 and ambiguous RSA signature flags are not supported")
		}
	}
	if flags != 0 {
		return "", errors.New("signature flags do not match the SSH key algorithm")
	}
	if keyAlgorithm == "ssh-ed25519" {
		return keyAlgorithm, nil
	}
	return "", errors.New("SSH key algorithm is not supported")
}

func parseSessionBindExtension(payload []byte) (sshSessionBinding, error) {
	reader := wireReader{value: payload}
	hostKeyBlob, err := reader.string()
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind host key")
	}
	sessionID, err := reader.string()
	if err != nil || len(sessionID) == 0 {
		return sshSessionBinding{}, errors.New("invalid session-bind identifier")
	}
	signatureBlob, err := reader.string()
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind signature")
	}
	forwarded, err := reader.byte()
	if err != nil || forwarded != 0 || !reader.done() {
		return sshSessionBinding{}, errors.New("forwarded or malformed session binding is not allowed")
	}
	hostKey, err := ssh.ParsePublicKey(hostKeyBlob)
	if err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind public key")
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(signatureBlob, &signature); err != nil {
		return sshSessionBinding{}, errors.New("invalid session-bind signature encoding")
	}
	if err := hostKey.Verify(sessionID, &signature); err != nil {
		return sshSessionBinding{}, errors.New("session-bind signature did not verify")
	}
	return sshSessionBinding{
		hostKeyBlob: append([]byte(nil), hostKeyBlob...),
		sessionID:   append([]byte(nil), sessionID...),
	}, nil
}

func verifySessionBindExtension(payload []byte) bool {
	_, err := parseSessionBindExtension(payload)
	return err == nil
}

func parseSSHUserauthRequest(data []byte) (sshUserauthRequest, error) {
	reader := wireReader{value: data}
	sessionID, err := reader.string()
	if err != nil || len(sessionID) == 0 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth session identifier")
	}
	message, err := reader.byte()
	if err != nil || message != 50 {
		return sshUserauthRequest{}, errors.New("SSH signing payload is not a userauth request")
	}
	username, err := reader.string()
	if err != nil || len(username) == 0 || len(username) > 256 || containsControl(string(username)) {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth username")
	}
	service, err := reader.string()
	if err != nil || string(service) != "ssh-connection" {
		return sshUserauthRequest{}, errors.New("unsupported SSH userauth service")
	}
	method, err := reader.string()
	if err != nil || (string(method) != "publickey" &&
		string(method) != "publickey-hostbound-v00@openssh.com") {
		return sshUserauthRequest{}, errors.New("unsupported SSH userauth method")
	}
	hasSignature, err := reader.byte()
	if err != nil || hasSignature != 1 {
		return sshUserauthRequest{}, errors.New("SSH userauth request did not ask for a signature")
	}
	publicKeyAlgorithm, err := reader.string()
	if err != nil || len(publicKeyAlgorithm) == 0 || len(publicKeyAlgorithm) > 128 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth public-key algorithm")
	}
	keyBlob, err := reader.string()
	if err != nil || len(keyBlob) == 0 || len(keyBlob) > 8*1024 {
		return sshUserauthRequest{}, errors.New("invalid SSH userauth public key")
	}
	key, err := ssh.ParsePublicKey(keyBlob)
	if err != nil || !userauthAlgorithmMatchesKey(string(publicKeyAlgorithm), key.Type()) {
		return sshUserauthRequest{}, errors.New("SSH userauth algorithm did not match its public key")
	}
	var serverHostKeyBlob []byte
	if string(method) == "publickey-hostbound-v00@openssh.com" {
		serverHostKeyBlob, err = reader.string()
		if err != nil || len(serverHostKeyBlob) == 0 || len(serverHostKeyBlob) > 8*1024 {
			return sshUserauthRequest{}, errors.New("invalid host-bound SSH server key")
		}
	}
	if !reader.done() {
		return sshUserauthRequest{}, errors.New("SSH userauth request contained trailing data")
	}
	return sshUserauthRequest{
		authenticationMethod: string(method),
		keyBlob:              append([]byte(nil), keyBlob...),
		remoteUsername:       string(username),
		service:              string(service),
		sessionID:            append([]byte(nil), sessionID...),
		serverHostKeyBlob:    append([]byte(nil), serverHostKeyBlob...),
	}, nil
}

func userauthAlgorithmMatchesKey(algorithm, keyType string) bool {
	if keyType == "ssh-rsa" {
		return algorithm == "ssh-rsa" || algorithm == "rsa-sha2-256" || algorithm == "rsa-sha2-512"
	}
	return algorithm == keyType
}

func verifySSHUserauthBinding(
	request sshUserauthRequest,
	binding sshSessionBinding,
	requestedKeyBlob []byte,
) error {
	if !bytes.Equal(request.sessionID, binding.sessionID) {
		return errors.New("SSH userauth session did not match its verified session binding")
	}
	if !bytes.Equal(request.keyBlob, requestedKeyBlob) {
		return errors.New("SSH userauth payload selected a different key")
	}
	if request.authenticationMethod == "publickey-hostbound-v00@openssh.com" &&
		!bytes.Equal(request.serverHostKeyBlob, binding.hostKeyBlob) {
		return errors.New("host-bound SSH userauth payload selected a different server")
	}
	return nil
}

func byteFingerprint(value []byte) string {
	digest := sha256.Sum256(value)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}
