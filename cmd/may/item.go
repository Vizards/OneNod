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
	"sort"
	"strings"
	"time"
)

const (
	itemCreateUsage  = "usage: may [global flags] item create --spec <file|->"
	itemPatchUsage   = "usage: may [global flags] item patch --item <id> --spec <file|-> [--expected-version n]"
	itemArchiveUsage = "usage: may [global flags] item archive --item <id> [--expected-version n]"
	maximumSpecBytes = 64 * 1024
	internalFieldID  = "com.github.vizards.onenod"
)

type itemCreateSpec struct {
	Category string                `json:"category"`
	Fields   []itemCreateFieldSpec `json:"fields"`
	Title    string                `json:"title"`
}

type itemCreateFieldSpec struct {
	FieldID   string  `json:"field_id"`
	FieldType string  `json:"field_type"`
	Label     string  `json:"label"`
	Value     *string `json:"value"`
}

type itemPatchSpec struct {
	Operations []itemPatchOperation `json:"operations"`
}

type itemPatchOperation struct {
	FieldID   string  `json:"field_id"`
	FieldType *string `json:"field_type,omitempty"`
	Label     *string `json:"label,omitempty"`
	Op        string  `json:"op"`
	Value     *string `json:"value,omitempty"`
}

type itemCreateFieldRequest struct {
	FieldID   string `json:"field_id"`
	FieldType string `json:"field_type"`
	Label     string `json:"label"`
	Value     string `json:"value"`
}

type itemCreateRequest struct {
	Action         string                   `json:"action"`
	Category       string                   `json:"category"`
	Fields         []itemCreateFieldRequest `json:"fields"`
	IdempotencyKey string                   `json:"idempotency_key"`
	Client         clientObservation        `json:"client"`
	Title          string                   `json:"title"`
}

type itemPatchRequest struct {
	Action          string               `json:"action"`
	ExpectedVersion int64                `json:"expected_version"`
	IdempotencyKey  string               `json:"idempotency_key"`
	Client          clientObservation    `json:"client"`
	ItemID          string               `json:"item_id"`
	Operations      []itemPatchOperation `json:"operations"`
}

type itemArchiveRequest struct {
	Action          string            `json:"action"`
	ExpectedVersion int64             `json:"expected_version"`
	IdempotencyKey  string            `json:"idempotency_key"`
	Client          clientObservation `json:"client"`
	ItemID          string            `json:"item_id"`
}

type itemMutationResponse struct {
	ItemID    string `json:"item_id"`
	OK        bool   `json:"ok"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Version   *int64 `json:"version,omitempty"`
}

type itemMutationStatusResponse struct {
	Error     string `json:"error,omitempty"`
	ExpiresAt string `json:"expires_at"`
	ItemID    string `json:"item_id,omitempty"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Version   *int64 `json:"version,omitempty"`
}

func runItem(args []string, config cliConfig, deps dependencies) error {
	if len(args) == 0 {
		return errors.New("usage: may [global flags] item <create|patch|archive> ...")
	}
	switch args[0] {
	case "create":
		return runItemCreate(args[1:], config, deps)
	case "patch":
		return runItemPatch(args[1:], config, deps)
	case "archive":
		return runItemArchive(args[1:], config, deps)
	default:
		return fmt.Errorf("unknown item command %q", args[0])
	}
}

func runItemCreate(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("item create", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	specPath := flags.String("spec", "", "JSON spec path, or - for stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *specPath == "" {
		return errors.New(itemCreateUsage)
	}
	var spec itemCreateSpec
	if err := readStrictSpec(*specPath, deps.stdin, &spec); err != nil {
		return err
	}
	fields, err := validateCreateSpec(spec)
	if err != nil {
		return err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return err
	}
	localClient := callingApplicationContext(config, deps)
	defer localClient.Evidence.close()
	request := itemCreateRequest{
		Action:         "item.create",
		Category:       spec.Category,
		Fields:         fields,
		IdempotencyKey: idempotencyKey,
		Client:         localClient.Observation,
		Title:          spec.Title,
	}
	return submitAndConsumeItemMutation(request, localClient, config, deps)
}

func runItemPatch(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("item patch", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	itemID := flags.String("item", "", "1Password item ID")
	specPath := flags.String("spec", "", "JSON spec path, or - for stdin")
	expectedVersion := flags.Int64("expected-version", -1, "expected 1Password item version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *itemID == "" || *specPath == "" {
		return errors.New(itemPatchUsage)
	}
	if err := validateIdentifier(*itemID, "item"); err != nil {
		return err
	}
	var spec itemPatchSpec
	if err := readStrictSpec(*specPath, deps.stdin, &spec); err != nil {
		return err
	}
	if err := validatePatchSpec(&spec); err != nil {
		return err
	}
	version, err := mutationExpectedVersion(config, deps, *itemID, *expectedVersion)
	if err != nil {
		return err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return err
	}
	localClient := callingApplicationContext(config, deps)
	defer localClient.Evidence.close()
	request := itemPatchRequest{
		Action:          "item.patch",
		ExpectedVersion: version,
		IdempotencyKey:  idempotencyKey,
		Client:          localClient.Observation,
		ItemID:          *itemID,
		Operations:      spec.Operations,
	}
	return submitAndConsumeItemMutation(request, localClient, config, deps)
}

func runItemArchive(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("item archive", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	itemID := flags.String("item", "", "1Password item ID")
	expectedVersion := flags.Int64("expected-version", -1, "expected 1Password item version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *itemID == "" {
		return errors.New(itemArchiveUsage)
	}
	if err := validateIdentifier(*itemID, "item"); err != nil {
		return err
	}
	version, err := mutationExpectedVersion(config, deps, *itemID, *expectedVersion)
	if err != nil {
		return err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return err
	}
	localClient := callingApplicationContext(config, deps)
	defer localClient.Evidence.close()
	request := itemArchiveRequest{
		Action:          "item.archive",
		ExpectedVersion: version,
		IdempotencyKey:  idempotencyKey,
		Client:          localClient.Observation,
		ItemID:          *itemID,
	}
	return submitAndConsumeItemMutation(request, localClient, config, deps)
}

func readStrictSpec(path string, stdin io.Reader, result any) error {
	var input io.Reader
	var closeInput func() error
	if path == "-" {
		if stdin == nil {
			stdin = os.Stdin
		}
		input = stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open item spec: %w", err)
		}
		input = file
		closeInput = file.Close
	}
	if closeInput != nil {
		defer closeInput()
	}
	data, err := io.ReadAll(io.LimitReader(input, maximumSpecBytes+1))
	if err != nil {
		return errors.New("read item spec failed")
	}
	if len(data) > maximumSpecBytes {
		return errors.New("item spec exceeded 64 KiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return errors.New("item spec is not valid closed-schema JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("item spec must contain exactly one JSON object")
	}
	return nil
}

func validateCreateSpec(spec itemCreateSpec) ([]itemCreateFieldRequest, error) {
	if !isWritableCategory(spec.Category) {
		return nil, errors.New("item spec category is not writable")
	}
	if err := validateText(spec.Title, 256, "title"); err != nil {
		return nil, err
	}
	if len(spec.Fields) == 0 || len(spec.Fields) > 32 {
		return nil, errors.New("item spec must contain 1 to 32 fields")
	}
	fields := make([]itemCreateFieldRequest, 0, len(spec.Fields))
	for _, field := range spec.Fields {
		if err := validateUserFieldID(field.FieldID); err != nil {
			return nil, err
		}
		if !isWritableCreateFieldType(field.FieldType) {
			return nil, fmt.Errorf("field %q has an unsupported field_type", field.FieldID)
		}
		if err := validateText(field.Label, 128, "field label"); err != nil {
			return nil, err
		}
		if field.Value == nil || len(*field.Value) > 16*1024 {
			return nil, fmt.Errorf("field %q has a missing or oversized value", field.FieldID)
		}
		fields = append(fields, itemCreateFieldRequest{
			FieldID: field.FieldID, FieldType: field.FieldType, Label: field.Label, Value: *field.Value,
		})
	}
	sort.Slice(fields, func(left, right int) bool { return fields[left].FieldID < fields[right].FieldID })
	if err := rejectDuplicateCreateFields(fields); err != nil {
		return nil, err
	}
	if err := validateCreateShape(spec.Category, fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func validatePatchSpec(spec *itemPatchSpec) error {
	if len(spec.Operations) == 0 || len(spec.Operations) > 32 {
		return errors.New("item patch spec must contain 1 to 32 operations")
	}
	for _, operation := range spec.Operations {
		if err := validateUserFieldID(operation.FieldID); err != nil {
			return err
		}
		switch operation.Op {
		case "add":
			if operation.FieldType == nil || !isWritableFieldType(*operation.FieldType) ||
				operation.Label == nil || operation.Value == nil {
				return fmt.Errorf("add operation for %q is incomplete", operation.FieldID)
			}
			if err := validateText(*operation.Label, 128, "field label"); err != nil {
				return err
			}
		case "replace":
			if operation.FieldType != nil || operation.Label != nil || operation.Value == nil {
				return fmt.Errorf("replace operation for %q has invalid fields", operation.FieldID)
			}
		case "remove":
			if operation.FieldType != nil || operation.Label != nil || operation.Value != nil {
				return fmt.Errorf("remove operation for %q has invalid fields", operation.FieldID)
			}
		default:
			return fmt.Errorf("field %q has an unsupported patch operation", operation.FieldID)
		}
		if operation.Value != nil && len(*operation.Value) > 16*1024 {
			return fmt.Errorf("field %q has an oversized value", operation.FieldID)
		}
	}
	sort.Slice(spec.Operations, func(left, right int) bool {
		return spec.Operations[left].FieldID < spec.Operations[right].FieldID
	})
	for index := 1; index < len(spec.Operations); index++ {
		if spec.Operations[index-1].FieldID == spec.Operations[index].FieldID {
			return fmt.Errorf("field %q appears more than once", spec.Operations[index].FieldID)
		}
	}
	return nil
}

func rejectDuplicateCreateFields(fields []itemCreateFieldRequest) error {
	for index := 1; index < len(fields); index++ {
		if fields[index-1].FieldID == fields[index].FieldID {
			return fmt.Errorf("field %q appears more than once", fields[index].FieldID)
		}
	}
	return nil
}

func mutationExpectedVersion(
	config cliConfig,
	deps dependencies,
	itemID string,
	expected int64,
) (int64, error) {
	if expected < -1 || expected == 0 {
		return 0, errors.New("expected-version must be a positive integer when provided")
	}
	if expected > 0 {
		return expected, nil
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return 0, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	defer cancel()
	version, err := resolveExpectedVersion(ctx, client, itemID)
	if err != nil {
		return 0, err
	}
	fmt.Fprintf(
		deps.stderr,
		"Resolved item version %d from the requester-authenticated catalog.\n",
		version,
	)
	return version, nil
}

func submitAndConsumeItemMutation(
	request any,
	localClient localClientContext,
	config cliConfig,
	deps dependencies,
) error {
	credential, err := deps.keychain.Load()
	if err != nil {
		return err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return err
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
		return err
	}
	if created.RequestID == "" || created.ExpiresAt == "" || created.PollToken == "" {
		return errors.New("gateway returned an invalid item request response")
	}
	status := normalizeStatus(created.Status)
	if status == "pending" {
		fmt.Fprintf(deps.stderr, "Request %s submitted; waiting for human approval.\n", created.RequestID)
		pollContext, cancelPoll, contextError := approvalWaitContext(created.ExpiresAt, config.timeout)
		if contextError != nil {
			return contextError
		}
		status, err = pollStatus(pollContext, config.pollInterval, func() (string, error) {
			var current itemMutationStatusResponse
			path := "/v1/requests/" + url.PathEscape(created.RequestID) + "/status"
			if err := client.doPollingJSON(pollContext, path, created.PollToken, &current); err != nil {
				return "", err
			}
			if current.RequestID != created.RequestID {
				return "", errors.New("gateway status response changed the request ID")
			}
			return current.Status, nil
		})
		cancelPoll()
		if err != nil {
			return err
		}
	}
	if !isAuthorizedStatus(status) {
		return fmt.Errorf("request reached unexpected status %q", status)
	}

	consumePath := "/v1/requests/" + url.PathEscape(created.RequestID) + "/consume"
	var consumed itemMutationResponse
	consumeContext, cancelConsume := context.WithTimeout(context.Background(), gatewayRequestTimeout)
	err = client.doCapabilityJSON(
		consumeContext,
		http.MethodPost,
		consumePath,
		consumeRequest{},
		&consumed,
		created.PollToken,
	)
	cancelConsume()
	if err != nil {
		return fmt.Errorf("consume item request %s: %w", created.RequestID, err)
	}
	if !consumed.OK || consumed.RequestID != created.RequestID {
		return errors.New("gateway returned an invalid item consume response")
	}
	if normalizeStatus(consumed.Status) == "unknown" {
		fmt.Fprintf(
			deps.stderr,
			"Request %s has an unknown write outcome; waiting for read-only reconciliation.\n",
			created.RequestID,
		)
		consumed, err = waitForItemReconciliation(
			client,
			created.RequestID,
			created.PollToken,
			config,
		)
		if err != nil {
			return err
		}
	}
	if normalizeStatus(consumed.Status) != "consumed" || consumed.ItemID == "" {
		return errors.New("gateway returned an invalid completed item response")
	}
	return writeSafeJSON(deps.stdout, consumed)
}

func waitForItemReconciliation(
	client *apiClient,
	requestID string,
	pollToken string,
	config cliConfig,
) (itemMutationResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()
	ticker := time.NewTicker(config.pollInterval)
	defer ticker.Stop()
	for {
		var current itemMutationStatusResponse
		path := "/v1/requests/" + url.PathEscape(requestID) + "/status"
		if err := client.doPollingJSON(ctx, path, pollToken, &current); err != nil {
			return itemMutationResponse{}, err
		}
		if current.RequestID != requestID {
			return itemMutationResponse{}, errors.New("gateway status response changed the request ID")
		}
		switch normalizeStatus(current.Status) {
		case "consumed":
			if current.ItemID == "" {
				return itemMutationResponse{}, errors.New("completed item status omitted the item ID")
			}
			return itemMutationResponse{
				ItemID: current.ItemID, OK: true, RequestID: requestID, Status: "consumed", Version: current.Version,
			}, nil
		case "executing", "submitting", "unknown":
			// Reconciliation is alarm-driven; polling is persistence read-only.
		case "error", "expired", "denied", "rejected":
			return itemMutationResponse{}, fmt.Errorf("item request ended with status %q", current.Status)
		default:
			return itemMutationResponse{}, fmt.Errorf("gateway returned unexpected item status %q", current.Status)
		}
		select {
		case <-ctx.Done():
			return itemMutationResponse{}, errors.New("timed out waiting for item write reconciliation")
		case <-ticker.C:
		}
	}
}

func isWritableCategory(value string) bool {
	switch value {
	case "ApiCredentials", "Login", "Password", "SecureNote", "SshKey":
		return true
	default:
		return false
	}
}

func isWritableCreateFieldType(value string) bool {
	return value == "SshKey" || isWritableFieldType(value)
}

func validateCreateShape(category string, fields []itemCreateFieldRequest) error {
	if category == "SshKey" {
		if len(fields) != 1 || fields[0].FieldID != "private_key" ||
			fields[0].FieldType != "SshKey" || fields[0].Label != "private key" {
			return errors.New("SSH Key item must contain exactly one private_key SshKey field")
		}
		return nil
	}
	for _, field := range fields {
		if field.FieldType == "SshKey" {
			return errors.New("SshKey fields require the SSH Key item category")
		}
	}
	return nil
}

func isWritableFieldType(value string) bool {
	switch value {
	case "Concealed", "Email", "Text", "Url":
		return true
	default:
		return false
	}
}

func validateUserFieldID(value string) error {
	if err := validateIdentifier(value, "field_id"); err != nil {
		return err
	}
	if strings.HasPrefix(value, internalFieldID) {
		return errors.New("field_id uses the gateway-reserved namespace")
	}
	return nil
}

func validateIdentifier(value string, name string) error {
	if value == "" || len(value) > 256 || containsControl(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateText(value string, maximum int, name string) error {
	if value == "" || len(value) > maximum || containsControl(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
