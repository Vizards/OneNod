package main

import (
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
	"strings"
)

const (
	helperProtocol          = 1
	maxRequestBytes         = 128 * 1024
	maxCanonicalMessageSize = 64 * 1024
	keychainAccount         = "may"
	keychainServicePrefix   = "com.github.vizards.onenod.requester.target."
)

var (
	helperVersion = "0.0.0-dev"
	sourceCommit  = "unknown"
	workersHost   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.workers\.dev$`)
)

type helperRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Message     string `json:"message,omitempty"`
	Operation   string `json:"operation"`
	Origin      string `json:"origin,omitempty"`
	Slot        string `json:"slot,omitempty"`
}

type publicIdentity struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
	Version     int    `json:"version"`
}

type storedIdentity struct {
	publicIdentity
	PrivateKey string `json:"private_key"`
}

type helperResponse struct {
	Error     string          `json:"error,omitempty"`
	Found     *bool           `json:"found,omitempty"`
	Identity  *publicIdentity `json:"identity,omitempty"`
	OK        bool            `json:"ok"`
	Protocol  int             `json:"protocol,omitempty"`
	Signature string          `json:"signature,omitempty"`
	Source    string          `json:"source_commit,omitempty"`
	Version   string          `json:"version,omitempty"`
}

type credentialStore interface {
	Create(account, service string, value []byte) error
	Load(account, service string) ([]byte, bool, error)
}

var errIdentityExists = errors.New("requester identity already exists")

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
		if request.Origin != "" || request.DisplayName != "" || request.Message != "" || request.Slot != "" {
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
	case "ensure":
		if strings.TrimSpace(request.DisplayName) == "" || len(request.DisplayName) > 128 ||
			strings.ContainsAny(request.DisplayName, "\x00\r\n") {
			return helperResponse{}, errors.New("display_name is invalid")
		}
		identity, found, err := loadIdentity(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		if found {
			if identity.DisplayName != request.DisplayName {
				return helperResponse{}, errors.New("the identity slot already has a different display name")
			}
			return helperResponse{OK: true, Identity: &identity.publicIdentity}, nil
		}
		identity, err = newIdentity(request.DisplayName)
		if err != nil {
			return helperResponse{}, errors.New("requester identity generation failed")
		}
		encoded, err := json.Marshal(identity)
		if err != nil {
			return helperResponse{}, errors.New("requester identity encoding failed")
		}
		defer zero(encoded)
		if err := store.Create(keychainAccount, service, encoded); errors.Is(err, errIdentityExists) {
			identity, found, loadErr := loadIdentity(store, service)
			if loadErr != nil || !found {
				return helperResponse{}, errors.New("concurrent requester identity creation could not be reconciled")
			}
			if identity.DisplayName != request.DisplayName {
				return helperResponse{}, errors.New("the identity slot was concurrently created with a different display name")
			}
			return helperResponse{OK: true, Identity: &identity.publicIdentity}, nil
		} else if err != nil {
			return helperResponse{}, errors.New("requester identity Keychain write failed")
		}
		return helperResponse{OK: true, Identity: &identity.publicIdentity}, nil
	case "public":
		identity, found, err := loadIdentity(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		if !found {
			return helperResponse{OK: true, Found: boolPointer(false)}, nil
		}
		return helperResponse{OK: true, Found: boolPointer(true), Identity: &identity.publicIdentity}, nil
	case "sign":
		message, err := base64.RawURLEncoding.Strict().DecodeString(request.Message)
		if err != nil || len(message) == 0 || len(message) > maxCanonicalMessageSize {
			return helperResponse{}, errors.New("message is invalid or exceeds the signing limit")
		}
		defer zero(message)
		if err := validateCanonicalRequest(message, origin); err != nil {
			return helperResponse{}, err
		}
		identity, found, err := loadIdentity(store, service)
		if err != nil {
			return helperResponse{}, err
		}
		if !found {
			return helperResponse{}, errors.New("requester identity was not found")
		}
		privateKey, err := decodePrivateKey(identity)
		if err != nil {
			return helperResponse{}, err
		}
		defer zero(privateKey)
		signature := ed25519.Sign(privateKey, message)
		defer zero(signature)
		return helperResponse{
			OK: true, Signature: base64.RawURLEncoding.EncodeToString(signature),
		}, nil
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

func loadIdentity(store credentialStore, service string) (storedIdentity, bool, error) {
	encoded, found, err := store.Load(keychainAccount, service)
	if err != nil {
		return storedIdentity{}, false, errors.New("requester identity Keychain read failed")
	}
	if !found {
		return storedIdentity{}, false, nil
	}
	defer zero(encoded)
	var identity storedIdentity
	if err := json.Unmarshal(encoded, &identity); err != nil {
		return storedIdentity{}, false, errors.New("requester identity in Keychain is invalid")
	}
	if _, err := decodePrivateKey(identity); err != nil {
		return storedIdentity{}, false, err
	}
	return identity, true, nil
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
	parsed, err := url.Parse(origin)
	if err != nil || len(message) > maxCanonicalMessageSize ||
		!strings.HasPrefix(string(message), "onenod-request-v1\n"+parsed.Host+"\n") {
		return errors.New("helper signs only canonical OneNod requests for its Origin")
	}
	lines := strings.Split(string(message), "\n")
	if len(lines) != 8 {
		return errors.New("canonical OneNod request has an invalid field count")
	}
	for _, line := range lines {
		if line == "" || strings.ContainsAny(line, "\r\x00") {
			return errors.New("canonical OneNod request contains an invalid field")
		}
	}
	return nil
}

func boolPointer(value bool) *bool { return &value }

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
