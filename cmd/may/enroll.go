package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func runEnroll(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	name := flags.String("name", "", "human-readable requester device name")
	newIdentity := flags.Bool("new-identity", false, "enroll a fresh identity while retaining the prior Keychain item")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may [global flags] enroll [--name \"MacBook\"] [--new-identity]")
	}
	selectedSlot := deps.keychain.slot
	freshIdentity := *newIdentity
	var credential *requesterCredential
	identityCreated := false
	if !freshIdentity {
		existing, found, err := deps.keychain.LoadIfPresent()
		if err != nil {
			return err
		}
		if found {
			registered, err := requesterIsRegistered(config.origin, existing, deps.httpClient)
			if err != nil {
				return err
			}
			if registered {
				credential = existing
			} else {
				freshIdentity = true
				fmt.Fprintln(deps.stderr, "The selected local requester is not registered by this Gateway; creating a fresh isolated identity without modifying it.")
			}
		} else {
			freshIdentity = true
		}
	}
	if freshIdentity {
		var err error
		selectedSlot, err = newUUIDv4()
		if err != nil {
			return err
		}
		deps.keychain.slot = selectedSlot
		if *newIdentity {
			fmt.Fprintln(deps.stderr, "Creating a fresh requester identity; the prior Keychain item will be retained and never overwritten.")
		}
	}

	requestedName := strings.TrimSpace(*name)
	displayName := requestedName
	if displayName == "" {
		displayName = defaultRequesterDisplayName()
		fmt.Fprintf(deps.stderr, "Using requester device name %q.\n", displayName)
	}
	if credential == nil && freshIdentity {
		if err := confirmFreshRequesterCeremony(
			deps.stdin, deps.stdout, config.origin, displayName,
		); err != nil {
			return err
		}
	}
	var err error
	if credential != nil {
		if credential.DisplayName != displayName {
			return fmt.Errorf(
				"Keychain already contains requester %q; refusing to overwrite it",
				credential.DisplayName,
			)
		}
	} else if freshIdentity && deps.keychain.backend == nil && deps.keychain.origin != "" {
		credential, err = bootstrapRequesterTransport(config.origin, selectedSlot, displayName)
		if err == nil {
			credential.helperOrigin = config.origin
			credential.helperSlot = selectedSlot
			err = credential.validatePublic()
			identityCreated = err == nil
		}
	} else {
		credential, identityCreated, err = deps.keychain.Ensure(displayName)
	}
	if err != nil {
		return err
	}
	if !identityCreated {
		fmt.Fprintln(deps.stderr, "Reusing the existing requester credential from Keychain.")
	}
	fingerprint, err := publicKeyFingerprint(credential)
	if err != nil {
		return err
	}
	fmt.Fprintf(
		deps.stderr,
		"Requester device %s\nPublic-key fingerprint %s\n",
		credential.DeviceID,
		fingerprint,
	)
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return err
	}
	request := enrollmentRequest{
		DeviceID:    credential.DeviceID,
		DisplayName: credential.DisplayName,
		PublicKey:   credential.PublicKey,
	}
	var created enrollmentCreateResponse
	createContext, cancelCreate := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	if err := client.doJSON(
		createContext,
		http.MethodPost,
		"/v1/requester-enrollments",
		request,
		&created,
	); err != nil {
		cancelCreate()
		return err
	}
	cancelCreate()
	if created.AlreadyEnrolled {
		if normalizeStatus(created.Status) != "approved" || created.EnrollmentID != "" ||
			created.ExpiresAt != "" || created.DeviceID != credential.DeviceID ||
			created.DisplayName != credential.DisplayName ||
			created.PublicKeyFingerprint != fingerprint {
			return errors.New("gateway returned an invalid already-enrolled requester response")
		}
		if freshIdentity {
			if err := activateRequesterSlot(config.origin, selectedSlot); err != nil {
				return errors.New("existing requester is active but activating its non-secret local slot failed")
			}
		}
		return writeSafeJSON(deps.stdout, map[string]any{
			"already_enrolled":       true,
			"device_id":              credential.DeviceID,
			"public_key_fingerprint": fingerprint,
			"status":                 "approved",
		})
	}
	enrollmentID := created.EnrollmentID
	if enrollmentID == "" {
		return errors.New("gateway enrollment response did not include an enrollment ID")
	}
	if normalizeStatus(created.Status) != "pending" || created.ExpiresAt == "" {
		return errors.New("gateway returned an invalid enrollment response")
	}
	if created.PublicKeyFingerprint != fingerprint {
		return errors.New("gateway enrollment fingerprint did not match the local requester key")
	}
	fmt.Fprintf(
		deps.stderr,
		"Enrollment %s submitted; compare the device ID and fingerprint in the PWA, then approve.\n",
		enrollmentID,
	)

	pollContext, cancelPoll, err := approvalWaitContext(
		created.ExpiresAt,
		config.timeout,
	)
	if err != nil {
		return err
	}
	status, err := pollStatus(pollContext, config.pollInterval, func() (string, error) {
		var current enrollmentStatusResponse
		path := "/v1/requester-enrollments/" + url.PathEscape(enrollmentID)
		if err := client.doJSON(
			pollContext,
			http.MethodGet,
			path,
			nil,
			&current,
		); err != nil {
			return "", err
		}
		if current.DeviceID != credential.DeviceID ||
			current.PublicKeyFingerprint != fingerprint {
			return "", errors.New("gateway enrollment identity changed while waiting")
		}
		return current.Status, nil
	})
	cancelPoll()
	if err != nil {
		return err
	}
	if freshIdentity && isAuthorizedStatus(status) {
		if err := activateRequesterSlot(config.origin, selectedSlot); err != nil {
			return errors.New("new requester was approved but activating its non-secret local slot failed")
		}
	}
	return writeSafeJSON(deps.stdout, map[string]string{
		"device_id":              credential.DeviceID,
		"enrollment_id":          enrollmentID,
		"public_key_fingerprint": fingerprint,
		"status":                 status,
	})
}

func requesterIsRegistered(
	origin string,
	credential *requesterCredential,
	httpClient *http.Client,
) (bool, error) {
	client, err := newAPIClient(origin, credential, httpClient)
	if err != nil {
		return false, err
	}
	var response requesterSelfResponse
	requestContext, cancel := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	defer cancel()
	if err := client.doJSON(
		requestContext,
		http.MethodGet,
		"/v1/requester-self",
		nil,
		&response,
	); err != nil {
		if isGatewayErrorCode(err, "requester_not_found") {
			return false, nil
		}
		return false, fmt.Errorf("verify existing requester registration failed: %w", err)
	}
	fingerprint, err := publicKeyFingerprint(credential)
	if err != nil {
		return false, err
	}
	if !response.Registered || response.DeviceID != credential.DeviceID ||
		response.PublicKeyFingerprint != fingerprint {
		return false, errors.New("gateway returned an invalid requester registration proof")
	}
	return true, nil
}

func defaultRequesterDisplayName() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "This Mac"
	}
	hostname = strings.TrimSpace(strings.TrimSuffix(hostname, ".local"))
	if hostname == "" {
		return "This Mac"
	}
	runes := []rune(hostname)
	if len(runes) > 80 {
		return string(runes[:80])
	}
	return hostname
}
