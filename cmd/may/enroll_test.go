package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRequesterRegistrationProofUsesSignedEmptyGetAndFailsClosedOnMismatch(t *testing.T) {
	credential, err := credentialFromSeed("Test Mac")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := publicKeyFingerprint(credential)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://onenod.example-account.workers.dev"
	verifySignedGet := func(request *http.Request) {
		t.Helper()
		if request.Method != http.MethodGet || request.URL.Path != "/v1/requester-self" ||
			request.Body != nil || request.Header.Get(headerDeviceID) != credential.DeviceID {
			t.Fatal("requester registration proof was not the closed body-less GET")
		}
		timestamp, err := strconv.ParseInt(request.Header.Get(headerRequestTimestamp), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := canonicalSignatureString(signatureInput{
			Audience: origin[len("https://"):], Body: []byte("{}"),
			DeviceID: credential.DeviceID, Method: http.MethodGet,
			Nonce: request.Header.Get(headerRequestNonce), Path: request.URL.Path,
			Timestamp: timestamp,
		})
		if err != nil {
			t.Fatal(err)
		}
		signature, err := base64.RawURLEncoding.Strict().DecodeString(
			request.Header.Get(headerRequestSignature),
		)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := base64.RawURLEncoding.Strict().DecodeString(credential.PublicKey)
		if err != nil || !ed25519.Verify(publicKey, []byte(canonical), signature) {
			t.Fatal("requester registration proof signature did not cover the empty GET")
		}
	}

	registered, err := requesterIsRegistered(origin, credential, &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			verifySignedGet(request)
			return jsonHTTPResponse(http.StatusOK, `{
				"device_id":"`+credential.DeviceID+`",
				"public_key_fingerprint":"`+fingerprint+`",
				"registered":true
			}`), nil
		}),
	})
	if err != nil || !registered {
		t.Fatalf("matching requester registration proof failed: registered=%v err=%v", registered, err)
	}

	registered, err = requesterIsRegistered(origin, credential, &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			verifySignedGet(request)
			return jsonHTTPResponse(http.StatusOK, `{
				"device_id":"ffffffff-ffff-4fff-8fff-ffffffffffff",
				"public_key_fingerprint":"`+fingerprint+`",
				"registered":true
			}`), nil
		}),
	})
	if err == nil || registered {
		t.Fatal("mismatched requester registration proof was accepted or freshened")
	}
}

func TestEnrollDoesNotAdoptPreseededUnregisteredRequester(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://onenod.example-account.workers.dev"
	const preseededSlot = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	if err := activateRequesterSlot(origin, preseededSlot); err != nil {
		t.Fatal(err)
	}
	preseeded, err := credentialFromSeed("Test Mac")
	if err != nil {
		t.Fatal(err)
	}
	backend := &serviceKeychainBackend{items: make(map[string][]byte)}
	service, err := requesterKeychainService(origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := (keychainStore{
		backend: backend,
		origin:  origin,
		service: service,
		slot:    preseededSlot,
	}).Save(preseeded); err != nil {
		t.Fatal(err)
	}
	preseededService := service + ".slot." + preseededSlot
	preseededBytes := append([]byte(nil), backend.items[preseededService]...)

	var enrolledDeviceID string
	var enrolledFingerprint string
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		switch request.URL.Path {
		case "/v1/requester-self":
			if request.Header.Get(headerDeviceID) != preseeded.DeviceID {
				t.Fatal("registration proof did not use the locally selected identity")
			}
			return gatewayErrorHTTPResponse(
				http.StatusNotFound,
				"requester_not_found",
			), nil
		case "/v1/requester-enrollments":
			var body enrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.DeviceID == preseeded.DeviceID || body.PublicKey == preseeded.PublicKey {
				t.Fatal("unregistered preseeded requester was submitted for enrollment")
			}
			enrolledDeviceID = body.DeviceID
			candidate := &requesterCredential{
				DeviceID: body.DeviceID, DisplayName: body.DisplayName,
				PublicKey: body.PublicKey, PrivateKey: "test-only", Version: 1,
			}
			enrolledFingerprint, err = publicKeyFingerprint(candidate)
			if err != nil {
				t.Fatal(err)
			}
			return jsonHTTPResponse(http.StatusAccepted, `{
				"enrollment_id":"fresh-enrollment",
				"expires_at":"2099-01-01T00:00:00Z",
				"public_key_fingerprint":"`+enrolledFingerprint+`",
				"status":"pending"
			}`), nil
		case "/v1/requester-enrollments/fresh-enrollment":
			return jsonHTTPResponse(http.StatusOK, `{
				"device_id":"`+enrolledDeviceID+`",
				"public_key_fingerprint":"`+enrolledFingerprint+`",
				"status":"approved"
			}`), nil
		default:
			t.Fatalf("unexpected enrollment path %s", request.URL.Path)
			return nil, nil
		}
	})
	var stdout bytes.Buffer
	err = runCLI([]string{
		"--origin", origin,
		"--poll-interval", "1ms",
		"--timeout", "1s",
		"enroll", "--name", "Test Mac",
	}, dependencies{
		httpClient: &http.Client{Transport: transport},
		keychain:   keychainStore{backend: backend},
		stdin:      strings.NewReader("y\n"),
		stderr:     io.Discard,
		stdout:     &stdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if requestCount != 3 || enrolledDeviceID == "" ||
		strings.Contains(stdout.String(), preseeded.DeviceID) {
		t.Fatalf("preseeded enrollment isolation failed: requests=%d output=%q", requestCount, stdout.String())
	}
	activeSlot, err := activeRequesterSlot(origin)
	if err != nil {
		t.Fatal(err)
	}
	if activeSlot == preseededSlot || !requesterSlotPattern.MatchString(activeSlot) {
		t.Fatalf("fresh approved requester was not activated: %q", activeSlot)
	}
	if !bytes.Equal(backend.items[preseededService], preseededBytes) {
		t.Fatal("preseeded Keychain item was modified")
	}
}

func TestFreshRequesterCeremonyDefaultsNoBeforeKeychainWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://onenod.example-account.workers.dev"
	backend := &recordingKeychainBackend{
		loadErr: errors.New("unselected legacy requester must not be read"),
	}
	var output strings.Builder
	err := runCLI([]string{
		"--origin", origin, "enroll", "--name", "Test Mac",
	}, dependencies{
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			t.Fatalf("fresh requester contacted the Gateway before its human ceremony: %s", request.URL)
			return nil, nil
		})},
		keychain: keychainStore{backend: backend},
		stdin:    strings.NewReader("\n"),
		stderr:   io.Discard,
		stdout:   &output,
	})
	if err == nil || !strings.Contains(err.Error(), "requester Keychain ceremony was not confirmed") {
		t.Fatalf("fresh requester default-no gate returned %v", err)
	}
	if backend.account != "" || len(backend.saved) != 0 {
		t.Fatal("fresh requester accessed Keychain before confirmation")
	}
	if !strings.Contains(output.String(), "REQUESTER KEYCHAIN SECURITY CEREMONY") ||
		!strings.Contains(output.String(), origin) ||
		!strings.Contains(output.String(), "same macOS user") {
		t.Fatalf("fresh requester ceremony summary is incomplete: %s", output.String())
	}
	if _, statErr := os.Stat(filepath.Join(home, userAgentDirectoryName, "requester.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("fresh requester activated local state before confirmation")
	}
}

func TestExplicitNewRequesterIdentityAlsoRequiresCeremony(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://onenod.example-account.workers.dev"
	backend := &serviceKeychainBackend{items: make(map[string][]byte)}
	var output strings.Builder
	err := runCLI([]string{
		"--origin", origin, "enroll", "--new-identity", "--name", "Replacement Mac",
	}, dependencies{
		keychain: keychainStore{backend: backend},
		stdin:    strings.NewReader("n\n"),
		stderr:   io.Discard,
		stdout:   &output,
	})
	if err == nil || !strings.Contains(err.Error(), "requester Keychain ceremony was not confirmed") ||
		!strings.Contains(output.String(), "Replacement Mac") {
		t.Fatalf("explicit new identity escaped the requester ceremony: err=%v output=%s", err, output.String())
	}
	if len(backend.items) != 0 {
		t.Fatal("explicit new identity wrote a Keychain item before confirmation")
	}
}

func TestEnrollReusesServerProvenRegisteredRequester(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const origin = "https://onenod.example-account.workers.dev"
	const registeredSlot = "11111111-2222-4333-8444-555555555555"
	if err := activateRequesterSlot(origin, registeredSlot); err != nil {
		t.Fatal(err)
	}
	registered, err := credentialFromSeed("Test Mac")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := publicKeyFingerprint(registered)
	if err != nil {
		t.Fatal(err)
	}
	backend := &serviceKeychainBackend{items: make(map[string][]byte)}
	service, err := requesterKeychainService(origin)
	if err != nil {
		t.Fatal(err)
	}
	if err := (keychainStore{
		backend: backend, origin: origin, service: service, slot: registeredSlot,
	}).Save(registered); err != nil {
		t.Fatal(err)
	}
	initialItemCount := len(backend.items)
	requestCount := 0
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestCount++
		switch request.URL.Path {
		case "/v1/requester-self":
			return jsonHTTPResponse(http.StatusOK, `{
				"device_id":"`+registered.DeviceID+`",
				"public_key_fingerprint":"`+fingerprint+`",
				"registered":true
			}`), nil
		case "/v1/requester-enrollments":
			var body enrollmentRequest
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.DeviceID != registered.DeviceID || body.PublicKey != registered.PublicKey {
				t.Fatal("server-proven registered requester was replaced")
			}
			return jsonHTTPResponse(http.StatusOK, `{
				"already_enrolled":true,
				"device_id":"`+registered.DeviceID+`",
				"display_name":"Test Mac",
				"public_key_fingerprint":"`+fingerprint+`",
				"status":"approved"
			}`), nil
		default:
			t.Fatalf("unexpected enrollment path %s", request.URL.Path)
			return nil, nil
		}
	})
	var stdout bytes.Buffer
	if err := runCLI([]string{
		"--origin", origin, "enroll", "--name", "Test Mac",
	}, dependencies{
		httpClient: &http.Client{Transport: transport},
		keychain:   keychainStore{backend: backend},
		stderr:     io.Discard,
		stdout:     &stdout,
	}); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 || len(backend.items) != initialItemCount ||
		!strings.Contains(stdout.String(), registered.DeviceID) {
		t.Fatalf("registered requester was not reused: requests=%d output=%q", requestCount, stdout.String())
	}
	activeSlot, err := activeRequesterSlot(origin)
	if err != nil || activeSlot != registeredSlot {
		t.Fatalf("registered requester slot changed: slot=%q err=%v", activeSlot, err)
	}
}
