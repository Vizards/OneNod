package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const gatewayRequestTimeout = 5 * time.Minute
const approvalObservationGrace = 5 * time.Second

type dependencies struct {
	httpClient    *http.Client
	keychain      keychainStore
	platformProbe func() (hostPlatform, error)
	releases      releaseSource
	stderr        io.Writer
	stdin         io.Reader
	stdout        io.Writer
}

type cliConfig struct {
	origin       string
	pollInterval time.Duration
	timeout      time.Duration
}

func main() {
	deps := dependencies{
		httpClient: &http.Client{Timeout: gatewayRequestTimeout},
		keychain:   keychainStore{},
		stderr:     os.Stderr,
		stdin:      os.Stdin,
		stdout:     os.Stdout,
	}
	var err error
	switch filepath.Base(os.Args[0]) {
	case gitSignAdapterBinaryName:
		err = runGitSignAdapter(os.Args[1:], deps)
	default:
		err = runCLI(os.Args[1:], deps)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "may: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string, deps dependencies) error {
	global := flag.NewFlagSet("may", flag.ContinueOnError)
	global.SetOutput(deps.stderr)
	config := cliConfig{}
	defaultConfiguredOrigin := os.Getenv(userAgentOriginKey)
	global.StringVar(
		&config.origin,
		"origin",
		defaultConfiguredOrigin,
		"gateway origin (global flag; place before the command)",
	)
	global.DurationVar(
		&config.pollInterval,
		"poll-interval",
		2*time.Second,
		"approval status polling interval",
	)
	global.DurationVar(
		&config.timeout,
		"timeout",
		10*time.Minute,
		"maximum human approval wait after a request is created",
	)
	global.Usage = func() {
		fmt.Fprintln(deps.stderr, usageText)
	}
	if err := global.Parse(args); err != nil {
		return err
	}
	if config.pollInterval <= 0 || config.timeout <= 0 {
		return errors.New("poll-interval and timeout must be positive")
	}
	remaining := global.Args()
	if len(remaining) == 0 {
		global.Usage()
		return errors.New("a command is required")
	}
	if requesterCommand(remaining[0]) {
		if config.origin == "" {
			installedOrigin, err := installedUserOrigin()
			if err != nil {
				return err
			}
			config.origin = installedOrigin
		}
		if config.origin == "" {
			return errors.New(
				"Gateway origin is not configured; run may install --origin URL or pass --origin before the command",
			)
		}
		keychainService, err := requesterKeychainService(config.origin)
		if err != nil {
			return err
		}
		deps.keychain.service = keychainService
		deps.keychain.origin = config.origin
		activeSlot, err := activeRequesterSlot(config.origin)
		if err != nil {
			return err
		}
		deps.keychain.slot = activeSlot
	}

	switch remaining[0] {
	case "preflight":
		return runPreflight(remaining[1:], config, deps)
	case "enroll":
		return runEnroll(remaining[1:], config, deps)
	case "catalog":
		return runCatalog(remaining[1:], config, deps)
	case "read":
		return runRead(remaining[1:], config, deps)
	case "secret":
		return runSecret(remaining[1:], config, deps)
	case "item":
		return runItem(remaining[1:], config, deps)
	case "ssh":
		return runSSH(remaining[1:], config, deps)
	case "agent":
		return runAgent(remaining[1:], config, deps)
	case "install":
		return runBinaryInstall(remaining[1:], deps)
	case "version":
		return runVersion(remaining[1:], deps)
	case "update":
		return runUpdate(remaining[1:], deps)
	case "configure":
		return runConfigure(remaining[1:], deps)
	case "dev":
		return runDev(remaining[1:], deps)
	case "operator":
		return runOperator(remaining[1:], deps)
	case "help", "-h", "--help":
		global.Usage()
		return nil
	default:
		global.Usage()
		return fmt.Errorf("unknown command %q", remaining[0])
	}
}

func requesterCommand(command string) bool {
	switch command {
	case "preflight", "enroll", "catalog", "read", "secret", "item", "ssh", "agent":
		return true
	default:
		return false
	}
}

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
	if *newIdentity {
		var err error
		selectedSlot, err = newUUIDv4()
		if err != nil {
			return err
		}
		deps.keychain.slot = selectedSlot
		fmt.Fprintln(deps.stderr, "Creating a fresh requester identity; the prior Keychain item will be retained and never overwritten.")
	}

	requestedName := strings.TrimSpace(*name)
	displayName := requestedName
	if displayName == "" {
		displayName = defaultRequesterDisplayName()
		fmt.Fprintf(deps.stderr, "Using requester device name %q.\n", displayName)
	}
	credential, identityCreated, err := deps.keychain.Ensure(displayName)
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
		if *newIdentity {
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
	if *newIdentity && normalizeStatus(status) == "consumed" {
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

func runCatalog(args []string, config cliConfig, deps dependencies) error {
	if len(args) < 2 || args[0] != "search" {
		return errors.New("usage: may [global flags] catalog search <query>")
	}
	query := strings.TrimSpace(strings.Join(args[1:], " "))
	if query == "" {
		return errors.New("catalog query is required")
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	defer cancel()
	response, err := searchCatalog(ctx, client, query)
	if err != nil {
		return err
	}
	return writeIndentedValue(deps.stdout, response)
}

func runSecret(args []string, config cliConfig, deps dependencies) error {
	if len(args) == 0 || args[0] != "read" {
		return errors.New(secretReadUsage)
	}
	flags := flag.NewFlagSet("secret read", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	itemID := flags.String("item", "", "1Password item ID")
	fieldID := flags.String("field", "", "1Password field ID")
	expectedVersion := flags.Int64("expected-version", -1, "expected 1Password item version")
	raw := flags.Bool("raw", false, "write the secret value to stdout")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *itemID == "" || *fieldID == "" {
		return errors.New(secretReadUsage)
	}
	if *expectedVersion < -1 {
		return errors.New("expected-version must be non-negative")
	}
	value, err := readApprovedSecret(
		config,
		deps,
		*itemID,
		*fieldID,
		*expectedVersion,
	)
	if err != nil {
		return err
	}
	return emitConsumedSecret(deps.stdout, deps.stderr, value, *raw)
}

type enrollmentRequest struct {
	DeviceID    string `json:"device_id"`
	DisplayName string `json:"display_name"`
	PublicKey   string `json:"public_key"`
}

type enrollmentCreateResponse struct {
	AlreadyEnrolled      bool   `json:"already_enrolled"`
	DeviceID             string `json:"device_id"`
	DisplayName          string `json:"display_name"`
	EnrollmentID         string `json:"enrollment_id"`
	ExpiresAt            string `json:"expires_at"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Status               string `json:"status"`
}

type enrollmentStatusResponse struct {
	CreatedAt            string `json:"created_at"`
	DeviceID             string `json:"device_id"`
	DisplayName          string `json:"display_name"`
	ExpiresAt            string `json:"expires_at"`
	ID                   string `json:"id"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
	Status               string `json:"status"`
}

type catalogSearchRequest struct {
	Query string `json:"query"`
}

type catalogFieldResult struct {
	FieldID   string `json:"field_id"`
	FieldType string `json:"field_type"`
	Label     string `json:"label"`
}

type catalogItemResult struct {
	Category  string               `json:"category"`
	Fields    []catalogFieldResult `json:"fields"`
	ItemID    string               `json:"item_id"`
	SSH       *catalogSSHMetadata  `json:"ssh,omitempty"`
	Title     string               `json:"title"`
	UpdatedAt string               `json:"updated_at"`
	Version   int64                `json:"version"`
}

type catalogSSHMetadata struct {
	Algorithm     string `json:"algorithm"`
	Fingerprint   string `json:"fingerprint"`
	PublicKey     string `json:"public_key"`
	PublicKeyBlob string `json:"public_key_blob"`
}

type catalogSearchResponse struct {
	Items []catalogItemResult `json:"items"`
}

type clientObservation struct {
	Application string `json:"application"`
	Source      string `json:"source"`
}

type createRequest struct {
	Action          string            `json:"action"`
	Client          clientObservation `json:"client"`
	ExpectedVersion int64             `json:"expected_version"`
	FieldID         string            `json:"field_id"`
	IdempotencyKey  string            `json:"idempotency_key"`
	ItemID          string            `json:"item_id"`
}

type requestStatusResponse struct {
	Error     string `json:"error,omitempty"`
	ExpiresAt string `json:"expires_at"`
	PollToken string `json:"poll_token,omitempty"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
}

type consumeRequest struct{}

type secretConsumeResponse struct {
	OK        bool    `json:"ok"`
	RequestID string  `json:"request_id"`
	Status    string  `json:"status"`
	Value     *string `json:"value,omitempty"`
}

func (response secretConsumeResponse) secretValue() (string, bool) {
	if response.Value != nil {
		return *response.Value, true
	}
	return "", false
}

func runRead(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("read", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	noNewline := flags.Bool("no-newline", false, "do not append a newline")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: may [global flags] read [--no-newline] op://Agent/<item>/<field>")
	}
	itemID, fieldID, version, err := resolveSecretReference(config, deps, flags.Arg(0))
	if err != nil {
		return err
	}
	value, err := readApprovedSecret(config, deps, itemID, fieldID, version)
	if err != nil {
		return err
	}
	if *noNewline {
		_, err = io.WriteString(deps.stdout, value)
		return err
	}
	_, err = fmt.Fprintln(deps.stdout, value)
	return err
}

func resolveSecretReference(
	config cliConfig,
	deps dependencies,
	reference string,
) (string, string, int64, error) {
	parsed, err := url.Parse(reference)
	if err != nil || parsed.Scheme != "op" || parsed.Host != "Agent" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", 0, errors.New("secret reference must be op://Agent/<item>/<field>")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	if len(segments) != 2 {
		return "", "", 0, errors.New("secret reference must contain exactly one item and one field")
	}
	itemReference, err := url.PathUnescape(segments[0])
	if err != nil || strings.TrimSpace(itemReference) == "" {
		return "", "", 0, errors.New("secret reference contains an invalid item")
	}
	fieldReference, err := url.PathUnescape(segments[1])
	if err != nil || strings.TrimSpace(fieldReference) == "" {
		return "", "", 0, errors.New("secret reference contains an invalid field")
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return "", "", 0, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return "", "", 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	defer cancel()
	response, err := searchCatalog(ctx, client, itemReference)
	if err != nil {
		return "", "", 0, err
	}
	var matches []catalogItemResult
	for _, item := range response.Items {
		if item.ItemID == itemReference {
			matches = []catalogItemResult{item}
			break
		}
		if item.Title == itemReference {
			matches = append(matches, item)
		}
	}
	if len(matches) != 1 {
		return "", "", 0, fmt.Errorf("secret reference item %q resolved to %d exact matches", itemReference, len(matches))
	}
	item := matches[0]
	var fieldMatches []catalogFieldResult
	for _, field := range item.Fields {
		if field.FieldID == fieldReference {
			fieldMatches = []catalogFieldResult{field}
			break
		}
		if field.Label == fieldReference {
			fieldMatches = append(fieldMatches, field)
		}
	}
	if len(fieldMatches) != 1 {
		return "", "", 0, fmt.Errorf("secret reference field %q resolved to %d exact matches", fieldReference, len(fieldMatches))
	}
	if item.Version <= 0 {
		return "", "", 0, errors.New("catalog returned an invalid item version")
	}
	return item.ItemID, fieldMatches[0].FieldID, item.Version, nil
}

func readApprovedSecret(
	config cliConfig,
	deps dependencies,
	itemID string,
	fieldID string,
	expectedVersion int64,
) (string, error) {
	if err := validateIdentifier(itemID, "item"); err != nil {
		return "", err
	}
	if err := validateIdentifier(fieldID, "field"); err != nil {
		return "", err
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return "", err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return "", err
	}
	resolvedVersion := expectedVersion
	if resolvedVersion < 0 {
		ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
		resolvedVersion, err = resolveExpectedVersion(ctx, client, itemID)
		cancel()
		if err != nil {
			return "", err
		}
		fmt.Fprintf(deps.stderr, "Resolved item version %d from the requester-authenticated catalog.\n", resolvedVersion)
	}
	if resolvedVersion <= 0 {
		return "", errors.New("expected-version must be a positive integer")
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return "", err
	}
	request := createRequest{
		Action:          "secret.read",
		Client:          detectLocalClientFromPID(os.Getppid()),
		ExpectedVersion: resolvedVersion,
		FieldID:         fieldID,
		IdempotencyKey:  idempotencyKey,
		ItemID:          itemID,
	}
	var created requestStatusResponse
	createContext, cancelCreate := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	err = client.doJSON(createContext, http.MethodPost, "/v1/requests", request, &created)
	cancelCreate()
	if err != nil {
		return "", err
	}
	if created.RequestID == "" || created.ExpiresAt == "" || created.PollToken == "" {
		return "", errors.New("gateway returned an invalid request creation response")
	}
	status := normalizeStatus(created.Status)
	if status == "pending" {
		fmt.Fprintf(deps.stderr, "Request %s submitted; waiting for human approval.\n", created.RequestID)
		pollContext, cancelPoll, contextError := approvalWaitContext(created.ExpiresAt, config.timeout)
		if contextError != nil {
			return "", contextError
		}
		status, err = pollStatus(pollContext, config.pollInterval, func() (string, error) {
			var current requestStatusResponse
			path := "/v1/requests/" + url.PathEscape(created.RequestID) + "/status"
			if err := client.doPollingJSON(pollContext, path, created.PollToken, &current); err != nil {
				return "", err
			}
			if current.RequestID != "" && current.RequestID != created.RequestID {
				return "", errors.New("gateway status response changed the request ID")
			}
			return current.Status, nil
		})
		cancelPoll()
		if err != nil {
			return "", err
		}
	}
	if !isAuthorizedStatus(status) {
		return "", fmt.Errorf("request reached unexpected status %q", status)
	}
	var consumed secretConsumeResponse
	consumeContext, cancelConsume := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	err = client.doJSON(
		consumeContext,
		http.MethodPost,
		"/v1/requests/"+url.PathEscape(created.RequestID)+"/consume",
		consumeRequest{},
		&consumed,
	)
	cancelConsume()
	if err != nil {
		return "", err
	}
	if !consumed.OK || consumed.RequestID != created.RequestID ||
		normalizeStatus(consumed.Status) != "consumed" {
		return "", errors.New("gateway returned an invalid consume response")
	}
	value, ok := consumed.secretValue()
	if !ok {
		return "", errors.New("consume response did not include a secret value")
	}
	return value, nil
}

func emitConsumedSecret(
	stdout io.Writer,
	stderr io.Writer,
	value string,
	raw bool,
) error {
	if raw {
		_, err := io.WriteString(stdout, value)
		return err
	}
	fmt.Fprintln(
		stderr,
		"Secret was consumed successfully; value suppressed because --raw was not specified.",
	)
	return nil
}

func approvalWaitContext(
	expiresAt string,
	maximumWait time.Duration,
) (context.Context, context.CancelFunc, error) {
	return approvalWaitContextFrom(context.Background(), expiresAt, maximumWait)
}

func approvalWaitContextFrom(
	parent context.Context,
	expiresAt string,
	maximumWait time.Duration,
) (context.Context, context.CancelFunc, error) {
	expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return nil, nil, errors.New("gateway returned an invalid expiry timestamp")
	}
	now := time.Now()
	deadline := now.Add(maximumWait)
	expiryWithGrace := expiry.Add(approvalObservationGrace)
	if expiryWithGrace.Before(deadline) {
		deadline = expiryWithGrace
	}
	if !deadline.After(now) {
		return nil, nil, errors.New("approval request has already expired")
	}
	contextValue, cancel := context.WithDeadline(parent, deadline)
	return contextValue, cancel, nil
}

func pollStatus(
	ctx context.Context,
	interval time.Duration,
	fetch func() (string, error),
) (string, error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status, err := fetch()
		if err != nil {
			return "", err
		}
		normalized := normalizeStatus(status)
		switch normalized {
		case "approved", "authorized", "active", "registered":
			return normalized, nil
		case "pending", "waiting_approval", "authenticating", "submitting":
			// Continue polling.
		case "denied", "rejected", "expired", "failed", "error", "unknown":
			return "", fmt.Errorf("request ended with status %q", normalized)
		default:
			return "", fmt.Errorf("gateway returned unknown status %q", status)
		}

		select {
		case <-ctx.Done():
			return "", errors.New("timed out waiting for approval")
		case <-ticker.C:
		}
	}
}

func normalizeStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func isAuthorizedStatus(value string) bool {
	normalized := normalizeStatus(value)
	return normalized == "approved" || normalized == "authorized"
}

func searchCatalog(
	ctx context.Context,
	client *apiClient,
	query string,
) (catalogSearchResponse, error) {
	var response catalogSearchResponse
	if err := client.doJSON(
		ctx,
		http.MethodPost,
		"/v1/catalog/search",
		catalogSearchRequest{Query: query},
		&response,
	); err != nil {
		return catalogSearchResponse{}, err
	}
	if response.Items == nil {
		return catalogSearchResponse{}, errors.New("gateway catalog response did not include items")
	}
	return response, nil
}

func resolveExpectedVersion(
	ctx context.Context,
	client *apiClient,
	itemID string,
) (int64, error) {
	response, err := searchCatalog(ctx, client, itemID)
	if err != nil {
		return 0, fmt.Errorf("resolve expected version: %w", err)
	}
	var version int64
	matches := 0
	for _, item := range response.Items {
		if item.ItemID != itemID {
			continue
		}
		if item.Version <= 0 {
			return 0, errors.New("catalog returned a non-positive item version")
		}
		version = item.Version
		matches++
	}
	if matches == 0 {
		return 0, errors.New(
			"catalog did not return the requested item; pass --expected-version explicitly",
		)
	}
	if matches > 1 {
		return 0, errors.New("catalog returned duplicate entries for the requested item")
	}
	return version, nil
}

func writeSafeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func writeIndentedValue(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

const usageText = `may — requester for the OneNod approval gateway

Usage:
  may install --origin https://<worker>.<account>.workers.dev [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may version [--json]
  may update check [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]] [--json]
  may update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may configure ssh <status|apply|restore>
  may configure git-signing status
  may configure git-signing apply --signing-key <key-or-path>
  may configure git-signing restore
  may [--origin URL] preflight
  may [--origin URL] enroll [--name "MacBook"] [--new-identity]
  may [--origin URL] catalog search <query>
  may [--origin URL] read [--no-newline] op://Agent/<item>/<field>
  may [--origin URL] secret read --item <id> --field <id> [--expected-version n] [--raw]
  may [--origin URL] item create --spec <file|->
  may [--origin URL] item patch --item <id> --spec <file|-> [--expected-version n]
  may [--origin URL] item archive --item <id> [--expected-version n]
  may [--origin URL] ssh public-key export --item <id> --output <path.pub>
  may [--origin URL] agent <serve|status|refresh>
  may dev verify-release --directory <dist/release> [--artifact <basename>]...
  may operator init [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]
  may operator update [--channel stable|beta|alpha | --version X.Y.Z[-alpha.N|-beta.N]]

The install and update commands consume manifest- and provenance-verified artifacts from the
selected immutable GitHub Release channel in Vizards/OneNod; stable is the default. They never inspect a
source checkout or update external tools such as Wrangler or 1Password CLI.
For requester commands, the default origin is read from ONENOD_ORIGIN or the
strict per-user ~/.onenod/env, in that order.
Global flags must appear before the command.`

const secretReadUsage = "usage: may [global flags] secret read --item <id> --field <id> [--expected-version n] [--raw]"
