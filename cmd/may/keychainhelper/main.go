package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	applicationAttestationProtocol = "onenod-application-attestation-v1"
	helperProtocol                 = 3
	maxRequestBytes                = 128 * 1024
	maxCanonicalMessageSize        = 64 * 1024
	keychainAccount                = "may"
	keychainServicePrefix          = "com.github.vizards.onenod.requester.target."
)

var (
	helperVersion = "0.0.0-dev"
	sourceCommit  = "unknown"
	workersHost   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.workers\.dev$`)
)

type helperRequest struct {
	ApplicationEvidence          string `json:"application_evidence,omitempty"`
	CandidateAdapterArchitecture string `json:"candidate_adapter_architecture,omitempty"`
	CandidateAdapterCDHash       string `json:"candidate_adapter_cdhash,omitempty"`
	CandidateAdapterDRSHA256     string `json:"candidate_adapter_designated_requirement_data_sha256,omitempty"`
	CandidateAdapterSHA256       string `json:"candidate_adapter_sha256,omitempty"`
	CandidateHelperArchitecture  string `json:"candidate_helper_architecture,omitempty"`
	CandidateHelperCDHash        string `json:"candidate_helper_cdhash,omitempty"`
	CandidateHelperDRSHA256      string `json:"candidate_helper_designated_requirement_data_sha256,omitempty"`
	CandidateHelperSHA256        string `json:"candidate_helper_sha256,omitempty"`
	CandidateMayArchitecture     string `json:"candidate_may_architecture,omitempty"`
	CandidateMayCDHash           string `json:"candidate_may_cdhash,omitempty"`
	CandidateMayDRSHA256         string `json:"candidate_may_designated_requirement_data_sha256,omitempty"`
	CandidateMaySHA256           string `json:"candidate_may_sha256,omitempty"`
	CanonicalBody                string `json:"canonical_body,omitempty"`
	DisplayName                  string `json:"display_name,omitempty"`
	Message                      string `json:"message,omitempty"`
	Operation                    string `json:"operation"`
	Origin                       string `json:"origin,omitempty"`
	Slot                         string `json:"slot,omitempty"`
	TransactionID                string `json:"transaction_id,omitempty"`
}

type publicIdentity struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
	Version     int    `json:"version"`
}

type storedIdentity struct {
	publicIdentity
	PrivateKey string                `json:"private_key"`
	Transport  *storedTransportTrust `json:"transport,omitempty"`
}

type helperResponse struct {
	Application            *helperClientObservation `json:"application,omitempty"`
	ApplicationAttestation string                   `json:"application_attestation,omitempty"`
	Error                  string                   `json:"error,omitempty"`
	Found                  *bool                    `json:"found,omitempty"`
	Identity               *publicIdentity          `json:"identity,omitempty"`
	OK                     bool                     `json:"ok"`
	Protocol               int                      `json:"protocol,omitempty"`
	Role                   string                   `json:"role,omitempty"`
	Signature              string                   `json:"signature,omitempty"`
	Source                 string                   `json:"source_commit,omitempty"`
	Version                string                   `json:"version,omitempty"`
	TransactionID          string                   `json:"transaction_id,omitempty"`
	TransactionState       string                   `json:"transaction_state,omitempty"`
}

type helperClientObservation struct {
	Application string                    `json:"application"`
	Identity    helperApplicationIdentity `json:"identity"`
	Source      string                    `json:"source"`
}

type helperApplicationIdentity struct {
	Assurance         string `json:"assurance"`
	Platform          string `json:"platform"`
	PrincipalScheme   string `json:"principal_scheme,omitempty"`
	PrincipalID       string `json:"principal_id,omitempty"`
	SignerName        string `json:"signer_name,omitempty"`
	SigningIdentifier string `json:"signing_identifier,omitempty"`
	TeamIdentifier    string `json:"team_identifier,omitempty"`
}

type credentialStore interface {
	Create(account, service string, value, metadata []byte, access keychainAccessPolicy) error
	Inspect(account, service string) ([]byte, bool, error)
	Load(account, service string) ([]byte, bool, error)
	Replace(
		account,
		service string,
		expectedMetadata,
		value,
		metadata []byte,
		access keychainAccessPolicy,
	) error
	Constrain(account, service string, expectedMetadata []byte, access keychainAccessPolicy) error
}

type keychainAccessPolicy uint8

const (
	keychainAccessInvalid keychainAccessPolicy = iota
	keychainAccessPreserve
	keychainAccessPromptRequired
	keychainAccessSelfOnly
)

var (
	errIdentityChanged = errors.New("requester identity changed concurrently")
	errIdentityExists  = errors.New("requester identity already exists")
)

func main() {
	versionJSON := flag.Bool("json", false, "print machine-readable version information")
	version := flag.Bool("version", false, "print version information")
	flag.Parse()
	if *version {
		response := helperResponse{
			OK: true, Protocol: helperProtocol, Source: sourceCommit, Version: helperVersion,
		}
		if *versionJSON {
			_ = json.NewEncoder(os.Stdout).Encode(response)
		} else {
			fmt.Fprintf(os.Stdout, "onenod-keychain-helper %s (protocol %d)\n", helperVersion, helperProtocol)
		}
		return
	}
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "onenod-keychain-helper: no positional arguments are accepted")
		os.Exit(2)
	}
	if err := serveOne(os.Stdin, os.Stdout, systemCredentialStore{}); err != nil {
		fmt.Fprintf(os.Stderr, "onenod-keychain-helper: %v\n", err)
		os.Exit(1)
	}
}

func serveOne(input io.Reader, output io.Writer, store credentialStore) error {
	limited := io.LimitReader(input, maxRequestBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > maxRequestBytes {
		return errors.New("request exceeds the helper protocol limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var request helperRequest
	if err := decoder.Decode(&request); err != nil {
		return errors.New("request is not valid helper protocol JSON")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return err
	}
	response, err := handleRequest(request, store)
	if err != nil {
		response = helperResponse{OK: false, Error: err.Error()}
	}
	return json.NewEncoder(output).Encode(response)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("helper request contains trailing JSON")
	}
	return nil
}

func handleRequest(request helperRequest, store credentialStore) (helperResponse, error) {
	if store == nil {
		return helperResponse{}, errors.New("credential store is unavailable")
	}
	if request.Operation == "hello" {
		if request.Origin != "" || request.Slot != "" || !noTransportRequestPayload(request) {
			return helperResponse{}, errors.New("hello does not accept identity fields")
		}
		return helperResponse{
			OK: true, Protocol: helperProtocol, Source: sourceCommit, Version: helperVersion,
		}, nil
	}
	origin, err := normalizedOrigin(request.Origin)
	if err != nil {
		return helperResponse{}, err
	}
	service, err := credentialService(origin, request.Slot)
	if err != nil {
		return helperResponse{}, err
	}
	switch request.Operation {
	case "transport-bootstrap":
		return handleTransportBootstrap(request, store, service)
	case "transport-stage":
		return handleTransportStage(request, store, service)
	case "transport-status":
		return handleTransportStatus(request, store, service)
	case "transport-commit":
		return handleTransportFinalize(request, store, service, false)
	case "transport-bootstrap-helper":
		return handleTransportFinalize(request, store, service, true)
	case "transport-abort":
		return handleTransportAbort(request, store, service)
	case "application":
		if request.DisplayName != "" || request.Message != "" || request.CanonicalBody != "" ||
			request.TransactionID != "" {
			return helperResponse{}, errors.New("application does not accept signing or identity fields")
		}
		if err := digestFieldPresentOnlyFor(request); err != nil {
			return helperResponse{}, err
		}
		_, authorized, err := loadAuthenticatedMetadata(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		observation := observeApplication(request.ApplicationEvidence, authorized)
		return helperResponse{OK: true, Application: &observation}, nil
	case "ensure":
		if request.ApplicationEvidence != "" || request.CanonicalBody != "" || request.Message != "" ||
			request.TransactionID != "" {
			return helperResponse{}, errors.New("ensure does not accept application or signing fields")
		}
		if err := digestFieldPresentOnlyFor(request); err != nil {
			return helperResponse{}, err
		}
		if err := validateDisplayName(request.DisplayName); err != nil {
			return helperResponse{}, err
		}
		identity, _, err := loadAuthenticatedIdentity(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		if identity.DisplayName != request.DisplayName {
			return helperResponse{}, errors.New("the identity slot already has a different display name")
		}
		return helperResponse{OK: true, Identity: &identity.publicIdentity}, nil
	case "public":
		if request.ApplicationEvidence != "" || request.CanonicalBody != "" ||
			request.DisplayName != "" || request.Message != "" || request.TransactionID != "" {
			return helperResponse{}, errors.New("public does not accept application or signing fields")
		}
		if err := digestFieldPresentOnlyFor(request); err != nil {
			return helperResponse{}, err
		}
		metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		defer zero(encodedMetadata)
		if !found {
			return helperResponse{OK: true, Found: boolPointer(false)}, nil
		}
		if metadata.Transport.BootstrapPending {
			return helperResponse{}, errors.New("requester transport trust requires explicit bootstrap")
		}
		if err := authenticateCurrentTransport(&metadata.Transport); err != nil {
			return helperResponse{}, err
		}
		identity := metadata.Identity
		return helperResponse{OK: true, Found: boolPointer(true), Identity: &identity}, nil
	case "sign":
		if request.DisplayName != "" || request.TransactionID != "" {
			return helperResponse{}, errors.New("sign does not accept identity or transport transaction fields")
		}
		if err := digestFieldPresentOnlyFor(request); err != nil {
			return helperResponse{}, err
		}
		identity, authorized, err := loadAuthenticatedIdentity(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		message, err := base64.RawURLEncoding.Strict().DecodeString(request.Message)
		if err != nil || len(message) == 0 || len(message) > maxCanonicalMessageSize {
			return helperResponse{}, errors.New("message is invalid or exceeds the signing limit")
		}
		defer zero(message)
		fields, err := canonicalRequestFields(message, origin)
		if err != nil {
			return helperResponse{}, err
		}
		if fields[5] != identity.DeviceID {
			return helperResponse{}, errors.New("canonical OneNod request selected a different requester identity")
		}
		var observation *helperClientObservation
		if request.ApplicationEvidence == "" {
			if request.CanonicalBody != "" {
				return helperResponse{}, errors.New("canonical_body requires application evidence")
			}
		} else {
			canonicalBody, err := decodeCanonicalApplicationBody(
				request.CanonicalBody,
				fields,
			)
			if err != nil {
				return helperResponse{}, err
			}
			defer zero(canonicalBody)
			resolved := observeApplication(request.ApplicationEvidence, authorized)
			if err := validateApplicationRequestBody(canonicalBody, resolved); err != nil {
				return helperResponse{}, err
			}
			observation = &resolved
		}
		privateKey, err := decodePrivateKey(identity)
		if err != nil {
			return helperResponse{}, err
		}
		defer zero(privateKey)
		signature := ed25519.Sign(privateKey, message)
		defer zero(signature)
		response := helperResponse{
			OK: true, Signature: base64.RawURLEncoding.EncodeToString(signature),
		}
		if observation != nil && observation.Identity.Assurance == applicationIdentityAssurance {
			material := applicationAttestationMaterial(
				message,
				observation.Identity.PrincipalScheme,
				observation.Identity.PrincipalID,
			)
			attestation := ed25519.Sign(privateKey, material)
			defer zero(attestation)
			response.ApplicationAttestation =
				base64.RawURLEncoding.EncodeToString(attestation)
		}
		return response, nil
	default:
		return helperResponse{}, errors.New("unsupported helper operation")
	}
}

func normalizedOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.Hostname() != parsed.Host || parsed.Path != "" || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.User != nil || !workersHost.MatchString(parsed.Host) ||
		parsed.String() != raw {
		return "", errors.New("origin must be a normalized workers.dev HTTPS origin")
	}
	return raw, nil
}

func credentialService(origin, slot string) (string, error) {
	if slot == "" {
		slot = "active"
	}
	if len(slot) > 64 || strings.Trim(slot, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") != "" {
		return "", errors.New("identity slot is invalid")
	}
	digest := sha256.Sum256([]byte(origin + "\n" + slot))
	return keychainServicePrefix + hex.EncodeToString(digest[:16]), nil
}

func newIdentity(displayName string) (storedIdentity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return storedIdentity{}, err
	}
	defer zero(privateKey)
	deviceID, err := randomUUID()
	if err != nil {
		return storedIdentity{}, err
	}
	return storedIdentity{
		publicIdentity: publicIdentity{
			DeviceID: deviceID, DisplayName: displayName,
			PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Version: 1,
		},
		PrivateKey: base64.RawURLEncoding.EncodeToString(privateKey),
	}, nil
}

func randomUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

func loadAuthenticatedIdentity(
	store credentialStore,
	service string,
) (storedIdentity, authorizedTransportSet, error) {
	metadata, authorized, err := loadAuthenticatedMetadata(store, service)
	if err != nil {
		return storedIdentity{}, authorizedTransportSet{}, err
	}
	identity, encoded, err := loadIdentityForMetadata(store, service, metadata)
	defer zero(encoded)
	if err != nil {
		return storedIdentity{}, authorizedTransportSet{}, err
	}
	return identity, authorized, nil
}

func loadAuthenticatedMetadata(
	store credentialStore,
	service string,
) (credentialMetadata, authorizedTransportSet, error) {
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	defer zero(encodedMetadata)
	if err != nil {
		return credentialMetadata{}, authorizedTransportSet{}, err
	}
	if !found {
		return credentialMetadata{}, authorizedTransportSet{},
			errors.New("requester identity was not found; explicit transport bootstrap is required")
	}
	if metadata.Transport.BootstrapPending {
		return credentialMetadata{}, authorizedTransportSet{},
			errors.New("requester transport trust requires explicit bootstrap")
	}
	if err := authenticateCurrentTransport(&metadata.Transport); err != nil {
		return credentialMetadata{}, authorizedTransportSet{}, err
	}
	return metadata, currentAuthorizedSet(&metadata.Transport), nil
}

func decodePrivateKey(identity storedIdentity) (ed25519.PrivateKey, error) {
	if identity.Version != 1 || identity.DeviceID == "" || identity.DisplayName == "" {
		return nil, errors.New("requester identity in Keychain is invalid")
	}
	privateKey, err := base64.RawURLEncoding.Strict().DecodeString(identity.PrivateKey)
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("requester identity in Keychain is invalid")
	}
	publicKey := privateKey[ed25519.SeedSize:]
	if base64.RawURLEncoding.EncodeToString(publicKey) != identity.PublicKey {
		zero(privateKey)
		return nil, errors.New("requester identity in Keychain is invalid")
	}
	return ed25519.PrivateKey(privateKey), nil
}

func validateCanonicalRequest(message []byte, origin string) error {
	_, err := canonicalRequestFields(message, origin)
	return err
}

func canonicalRequestFields(message []byte, origin string) ([]string, error) {
	parsed, err := url.Parse(origin)
	if err != nil || len(message) > maxCanonicalMessageSize ||
		!strings.HasPrefix(string(message), "onenod-request-v1\n"+parsed.Host+"\n") {
		return nil, errors.New("helper signs only canonical OneNod requests for its Origin")
	}
	lines := strings.Split(string(message), "\n")
	if len(lines) != 8 {
		return nil, errors.New("canonical OneNod request has an invalid field count")
	}
	for _, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\x00") {
			return nil, errors.New("canonical OneNod request contains an invalid field")
		}
	}
	return lines, nil
}

func observeApplication(
	evidence string,
	authorized authorizedTransportSet,
) helperClientObservation {
	resolved, err := authorizedApplicationResolver(evidence, authorized)
	if err != nil {
		platform := "unsupported"
		if runtime.GOOS == "darwin" {
			platform = "macos"
		}
		return helperClientObservation{
			Application: "Unknown local client",
			Identity: helperApplicationIdentity{
				Assurance: "unverified",
				Platform:  platform,
			},
			Source: "unavailable",
		}
	}
	return helperClientObservation{
		Application: resolved.Application,
		Identity: helperApplicationIdentity{
			Assurance:         resolved.Assurance,
			Platform:          resolved.Platform,
			PrincipalScheme:   resolved.PrincipalScheme,
			PrincipalID:       resolved.PrincipalID,
			SignerName:        resolved.SignerName,
			SigningIdentifier: resolved.SigningIdentifier,
			TeamIdentifier:    resolved.TeamIdentifier,
		},
		Source: resolved.Source,
	}
}

func decodeCanonicalApplicationBody(
	encoded string,
	canonicalFields []string,
) ([]byte, error) {
	if len(canonicalFields) != 8 || canonicalFields[2] != "POST" ||
		canonicalFields[3] != "/v1/requests" {
		return nil, errors.New("application evidence is valid only for request creation")
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(body) == 0 || len(body) > maxCanonicalMessageSize {
		return nil, errors.New("canonical_body is invalid or exceeds the signing limit")
	}
	canonical, err := jsoncanonicalizer.Transform(body)
	if err != nil || !bytes.Equal(canonical, body) {
		zero(body)
		return nil, errors.New("canonical_body is not canonical JSON")
	}
	digest := sha256.Sum256(body)
	if base64.RawURLEncoding.EncodeToString(digest[:]) != canonicalFields[4] {
		zero(body)
		return nil, errors.New("canonical_body does not match the signed request")
	}
	return body, nil
}

func validateApplicationRequestBody(
	canonicalBody []byte,
	observed helperClientObservation,
) error {
	type scope struct {
		ScopeID   string `json:"scope_id"`
		ScopeKind string `json:"scope_kind"`
	}
	var body struct {
		Action               string                   `json:"action"`
		AuthorizationScope   *scope                   `json:"authorization_scope"`
		AuthorizationSession *scope                   `json:"authorization_session"`
		Client               *helperClientObservation `json:"client"`
	}
	if err := json.Unmarshal(canonicalBody, &body); err != nil ||
		body.Client == nil || body.Action == "" {
		return errors.New("canonical_body has no application-bound request")
	}
	if !sameClientObservation(*body.Client, observed) {
		return errors.New("request application identity does not match verified process evidence")
	}
	verified := observed.Identity.Assurance == applicationIdentityAssurance
	for _, authorization := range []*scope{
		body.AuthorizationScope,
		body.AuthorizationSession,
	} {
		if authorization == nil {
			continue
		}
		if !verified || authorization.ScopeKind != "application" ||
			authorization.ScopeID != observed.Identity.PrincipalID {
			return errors.New("request authorization scope does not match verified application identity")
		}
	}
	return nil
}

func sameClientObservation(left, right helperClientObservation) bool {
	return left.Application == right.Application &&
		left.Source == right.Source &&
		left.Identity.Assurance == right.Identity.Assurance &&
		left.Identity.Platform == right.Identity.Platform &&
		left.Identity.PrincipalScheme == right.Identity.PrincipalScheme &&
		left.Identity.PrincipalID == right.Identity.PrincipalID &&
		left.Identity.SignerName == right.Identity.SignerName &&
		left.Identity.SigningIdentifier == right.Identity.SigningIdentifier &&
		left.Identity.TeamIdentifier == right.Identity.TeamIdentifier
}

func applicationAttestationMaterial(
	requesterCanonical []byte,
	principalScheme,
	principalID string,
) []byte {
	material := make([]byte, 0, len(requesterCanonical)+len(principalScheme)+len(principalID)+64)
	material = append(material, applicationAttestationProtocol...)
	material = append(material, '\n')
	material = append(material, requesterCanonical...)
	material = append(material, '\n')
	material = append(material, principalScheme...)
	material = append(material, '\n')
	return append(material, principalID...)
}

func boolPointer(value bool) *bool { return &value }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
