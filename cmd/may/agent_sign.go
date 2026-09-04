package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/crypto/ssh"
)

func (agent approvalAgent) signForConnection(
	state *sshAgentConnectionState,
	keyBlob []byte,
	data []byte,
	flags uint32,
) (resultSignature *ssh.Signature, returnErr error) {
	if len(keyBlob) == 0 {
		return nil, errors.New("invalid key blob")
	}
	if len(data) == 0 || len(data) > 64*1024 {
		return nil, errors.New("invalid signing payload")
	}
	var err error
	if len(state.identities) == 0 {
		state.identities, err = agent.currentIdentities()
		if err != nil {
			return nil, err
		}
	}
	identity := findIdentity(state.identities, keyBlob)
	if identity == nil {
		return nil, errors.New("requested SSH identity is not configured")
	}
	algorithm, err := signatureAlgorithm(identity.catalog.Metadata.Algorithm, flags)
	if err != nil {
		return nil, err
	}
	operation := sshOperationForPayload(data, keyBlob, state.binding)
	var observation beholderObservation
	hadBeholderBinding := state.beholderBinding != ""
	if hadBeholderBinding {
		// The binding is one-use even when Core is unavailable. During E1 the
		// disposition is observation-only: every signature still follows the
		// existing Gateway/human-approval path below.
		binding := state.beholderBinding
		state.beholderBinding = ""
		_, observation, _ = observeBeholderAgentOperationWithEvidence(
			agent.deps,
			binding,
			sshBeholderOperationTarget(operation, *identity, data, agent.config),
		)
		binding = ""
	}
	if hadBeholderBinding && observation.EvidenceID == "" && agent.deps.stderr != nil {
		fmt.Fprintln(agent.deps.stderr, "Beholder SSH outcome correlation is unavailable for this operation.")
	}
	outcome := newBeholderOutcomeTracker(agent.deps, observation, false)
	defer func() { outcome.finish(returnErr, returnErr == nil) }()
	result, err := requestSshSignature(
		agent.context,
		agent.config,
		agent.deps,
		*identity,
		state.client,
		agent.sessionKey,
		operation,
		algorithm,
		data,
		outcome,
	)
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(result.SignatureBlob)
	if err != nil || len(signature) == 0 || len(signature) > 16*1024 {
		return nil, errors.New("gateway returned an invalid SSH signature")
	}
	publicKey, err := ssh.ParsePublicKey(identity.keyBlob)
	if err != nil {
		return nil, errors.New("configured SSH public key is invalid")
	}
	if err := publicKey.Verify(data, &ssh.Signature{Format: result.Algorithm, Blob: signature}); err != nil {
		return nil, errors.New("gateway returned an SSH signature that did not verify")
	}
	return &ssh.Signature{Format: result.Algorithm, Blob: signature}, nil
}

func findIdentity(identities []servedSSHIdentity, keyBlob []byte) *servedSSHIdentity {
	for index := range identities {
		if bytes.Equal(identities[index].keyBlob, keyBlob) {
			return &identities[index]
		}
	}
	return nil
}

func requestSshSignature(
	ctx context.Context,
	config cliConfig,
	deps dependencies,
	identity servedSSHIdentity,
	localClient localClientContext,
	sessionKey ed25519.PrivateKey,
	operation sshOperation,
	algorithm string,
	data []byte,
	outcome *beholderOutcomeTracker,
) (sshSignConsumeResponse, error) {
	credential, err := deps.keychain.Load()
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	idempotencyKey, err := newUUIDv7(time.Now())
	if err != nil {
		return sshSignConsumeResponse{}, err
	}
	request := sshSignRequest{
		Action:              "ssh.sign",
		Algorithm:           algorithm,
		Client:              localClient.Observation,
		Data:                base64.RawURLEncoding.EncodeToString(data),
		ExpectedFingerprint: identity.catalog.Metadata.Fingerprint,
		ExpectedVersion:     identity.catalog.Version,
		IdempotencyKey:      idempotencyKey,
		ItemID:              identity.catalog.ItemID,
		Operation:           operation,
	}
	if err := attachSshAuthorizationSession(&request, localClient, sessionKey); err != nil {
		return sshSignConsumeResponse{}, err
	}
	var created requestStatusResponse
	createContext, cancelCreate := context.WithTimeout(ctx, gatewayRequestTimeout)
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
		if isGatewayErrorCode(err, "onepassword_rate_limited") {
			outcome.failAt("gateway-create")
			outcome.useLocalFallback()
			fmt.Fprintln(deps.stderr, "The remote 1Password Service Account quota is exhausted; requesting approval from the local 1Password SSH Agent on this Mac.")
			fallbackContext, cancelFallback := context.WithTimeout(
				ctx,
				localFallbackOperationLimit,
			)
			defer cancelFallback()
			result, localErr := signWithConfiguredLocalSSHAgent(
				fallbackContext,
				deps,
				identity,
				algorithm,
				data,
			)
			if localErr != nil {
				return sshSignConsumeResponse{}, localFallbackUnavailable(err, localErr)
			}
			return result, nil
		}
		outcome.failAt("gateway-create")
		return sshSignConsumeResponse{}, fmt.Errorf("create SSH approval request failed: %w", err)
	}
	if created.RequestID == "" || created.ExpiresAt == "" || created.PollToken == "" {
		outcome.failAt("gateway-create-response")
		return sshSignConsumeResponse{}, errors.New("gateway returned an invalid SSH approval response")
	}
	status := normalizeStatus(created.Status)
	outcome.setRequest(created.RequestID, status)
	if status == "pending" {
		fmt.Fprintf(deps.stderr, "SSH sign request %s submitted; waiting for human approval.\n", created.RequestID)
		pollContext, cancelPoll, contextError := approvalWaitContextFrom(ctx, created.ExpiresAt, config.timeout)
		if contextError != nil {
			outcome.failAt("approval-wait-setup")
			return sshSignConsumeResponse{}, fmt.Errorf(
				"prepare SSH request %s approval wait failed: %w",
				created.RequestID,
				contextError,
			)
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
			outcome.observeStatus(current.Status)
			return current.Status, nil
		})
		cancelPoll()
		if err != nil {
			outcome.failAt("approval-wait")
			return sshSignConsumeResponse{}, fmt.Errorf(
				"poll SSH request %s status failed: %w",
				created.RequestID,
				err,
			)
		}
	}
	if !isAuthorizedStatus(status) {
		outcome.observeStatus(status)
		outcome.failAt("authorization-status")
		return sshSignConsumeResponse{}, fmt.Errorf(
			"SSH request %s reached unexpected status %q",
			created.RequestID,
			status,
		)
	}
	var consumed sshSignConsumeResponse
	consumeContext, cancelConsume := context.WithTimeout(ctx, gatewayRequestTimeout)
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
		if isGatewayErrorCode(err, "onepassword_rate_limited") {
			outcome.failAt("gateway-consume")
			outcome.useLocalFallback()
			fmt.Fprintln(deps.stderr, "The remote 1Password Service Account quota is exhausted; requesting approval from the local 1Password SSH Agent on this Mac.")
			fallbackContext, cancelFallback := context.WithTimeout(
				ctx,
				localFallbackOperationLimit,
			)
			defer cancelFallback()
			result, localErr := signWithConfiguredLocalSSHAgent(
				fallbackContext,
				deps,
				identity,
				algorithm,
				data,
			)
			if localErr != nil {
				return sshSignConsumeResponse{}, localFallbackUnavailable(err, localErr)
			}
			return result, nil
		}
		outcome.failAt("gateway-consume")
		return sshSignConsumeResponse{}, fmt.Errorf(
			"consume SSH request %s failed: %w",
			created.RequestID,
			err,
		)
	}
	if !consumed.OK || consumed.RequestID != created.RequestID ||
		normalizeStatus(consumed.Status) != "consumed" ||
		consumed.ItemID != identity.catalog.ItemID ||
		consumed.Version != identity.catalog.Version ||
		consumed.Fingerprint != identity.catalog.Metadata.Fingerprint ||
		consumed.Algorithm != algorithm ||
		consumed.PublicKeyBlob != identity.catalog.Metadata.PublicKeyBlob {
		outcome.failAt("gateway-consume-response")
		return sshSignConsumeResponse{}, fmt.Errorf(
			"gateway returned a mismatched SSH signature response for request %s",
			created.RequestID,
		)
	}
	outcome.observeStatus(consumed.Status)
	return consumed, nil
}
