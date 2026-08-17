package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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
	response, err := searchCatalogWithLocalFallback(ctx, client, itemReference, deps)
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
		resolvedVersion, err = resolveExpectedVersionWithLocalFallback(
			ctx,
			client,
			itemID,
			deps,
		)
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
	localClient := callingApplicationContext(config, deps)
	defer localClient.Evidence.close()
	request := createRequest{
		Action:          "secret.read",
		Client:          localClient.Observation,
		ExpectedVersion: resolvedVersion,
		FieldID:         fieldID,
		IdempotencyKey:  idempotencyKey,
		ItemID:          itemID,
	}
	if localClient.ScopeKind == "application" && localClient.ScopeID != "" {
		request.AuthorizationScope = &applicationAuthorizationScope{
			ScopeID: localClient.ScopeID, ScopeKind: localClient.ScopeKind,
		}
	}
	var created requestStatusResponse
	createContext, cancelCreate := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	err = client.doApplicationJSON(
		createContext,
		http.MethodPost,
		"/v1/requests",
		request,
		&created,
		localClient,
	)
	cancelCreate()
	if err != nil {
		fallbackContext, cancelFallback := context.WithTimeout(
			context.Background(),
			localFallbackOperationLimit,
		)
		defer cancelFallback()
		return readSecretWithLocalFallback(
			fallbackContext,
			err,
			deps,
			itemID,
			fieldID,
			resolvedVersion,
		)
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
	err = client.doCapabilityJSON(
		consumeContext,
		http.MethodPost,
		"/v1/requests/"+url.PathEscape(created.RequestID)+"/consume",
		consumeRequest{},
		&consumed,
		created.PollToken,
	)
	cancelConsume()
	if err != nil {
		fallbackContext, cancelFallback := context.WithTimeout(
			context.Background(),
			localFallbackOperationLimit,
		)
		defer cancelFallback()
		return readSecretWithLocalFallback(
			fallbackContext,
			err,
			deps,
			itemID,
			fieldID,
			resolvedVersion,
		)
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

func useApprovedCredential(
	config cliConfig,
	deps dependencies,
	itemID string,
	fieldIDs []string,
	expectedVersion int64,
) (map[string]string, error) {
	if err := validateIdentifier(itemID, "item"); err != nil {
		return nil, err
	}
	if expectedVersion <= 0 {
		return nil, errors.New("credential item version must be a positive integer")
	}
	if len(fieldIDs) == 0 || len(fieldIDs) > 16 {
		return nil, errors.New("credential field set must contain between 1 and 16 fields")
	}
	for index, fieldID := range fieldIDs {
		if err := validateIdentifier(fieldID, "field"); err != nil {
			return nil, err
		}
		if index > 0 && fieldIDs[index-1] >= fieldID {
			return nil, errors.New("credential field IDs must be sorted and unique")
		}
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return nil, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return nil, err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return nil, err
	}
	localClient := callingApplicationContext(config, deps)
	defer localClient.Evidence.close()
	request := credentialUseRequest{
		Action:          "credential.use",
		Client:          localClient.Observation,
		ExpectedVersion: expectedVersion,
		FieldIDs:        fieldIDs,
		IdempotencyKey:  idempotencyKey,
		ItemID:          itemID,
	}
	if localClient.ScopeKind == "application" && localClient.ScopeID != "" {
		request.AuthorizationScope = &applicationAuthorizationScope{
			ScopeID: localClient.ScopeID, ScopeKind: localClient.ScopeKind,
		}
	}
	var created requestStatusResponse
	createContext, cancelCreate := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	err = client.doApplicationJSON(
		createContext,
		http.MethodPost,
		"/v1/requests",
		request,
		&created,
		localClient,
	)
	cancelCreate()
	if err != nil {
		fallbackContext, cancelFallback := context.WithTimeout(
			context.Background(),
			localFallbackOperationLimit,
		)
		defer cancelFallback()
		return readCredentialWithLocalFallback(
			fallbackContext,
			err,
			deps,
			itemID,
			fieldIDs,
			expectedVersion,
		)
	}
	if created.RequestID == "" || created.ExpiresAt == "" || created.PollToken == "" {
		return nil, errors.New("gateway returned an invalid request creation response")
	}
	status := normalizeStatus(created.Status)
	if status == "pending" {
		fmt.Fprintf(deps.stderr, "Request %s submitted; waiting for human approval.\n", created.RequestID)
		pollContext, cancelPoll, contextError := approvalWaitContext(
			created.ExpiresAt,
			config.timeout,
		)
		if contextError != nil {
			return nil, contextError
		}
		status, err = pollStatus(pollContext, config.pollInterval, func() (string, error) {
			var current requestStatusResponse
			path := "/v1/requests/" + url.PathEscape(created.RequestID) + "/status"
			if err := client.doPollingJSON(
				pollContext,
				path,
				created.PollToken,
				&current,
			); err != nil {
				return "", err
			}
			if current.RequestID != "" && current.RequestID != created.RequestID {
				return "", errors.New("gateway status response changed the request ID")
			}
			return current.Status, nil
		})
		cancelPoll()
		if err != nil {
			return nil, err
		}
	}
	if !isAuthorizedStatus(status) {
		return nil, fmt.Errorf("request reached unexpected status %q", status)
	}
	var consumed secretConsumeResponse
	consumeContext, cancelConsume := context.WithTimeout(
		context.Background(),
		gatewayRequestTimeout,
	)
	err = client.doCapabilityJSON(
		consumeContext,
		http.MethodPost,
		"/v1/requests/"+url.PathEscape(created.RequestID)+"/consume",
		consumeRequest{},
		&consumed,
		created.PollToken,
	)
	cancelConsume()
	if err != nil {
		fallbackContext, cancelFallback := context.WithTimeout(
			context.Background(),
			localFallbackOperationLimit,
		)
		defer cancelFallback()
		return readCredentialWithLocalFallback(
			fallbackContext,
			err,
			deps,
			itemID,
			fieldIDs,
			expectedVersion,
		)
	}
	if !consumed.OK || consumed.RequestID != created.RequestID ||
		normalizeStatus(consumed.Status) != "consumed" ||
		consumed.ItemID != itemID || consumed.Version != expectedVersion ||
		len(consumed.Values) != len(fieldIDs) {
		return nil, errors.New("gateway returned an invalid credential consume response")
	}
	for index, field := range consumed.Values {
		if field.FieldID != fieldIDs[index] {
			return nil, errors.New("credential consume response changed the requested field set")
		}
	}
	values := make(map[string]string, len(fieldIDs))
	for index, field := range consumed.Values {
		values[field.FieldID] = field.Value
		consumed.Values[index].Value = ""
	}
	return values, nil
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
