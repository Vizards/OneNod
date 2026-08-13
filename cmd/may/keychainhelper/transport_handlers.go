package main

import (
	"bytes"
	"errors"
	"strings"
)

func handleTransportBootstrap(
	request helperRequest,
	store credentialStore,
	service string,
) (helperResponse, error) {
	if err := transportOperationHasNoApplicationFieldsExceptDisplayName(request); err != nil {
		return helperResponse{}, err
	}
	if err := digestFieldPresentOnlyFor(request, "may", "adapter"); err != nil {
		return helperResponse{}, err
	}
	if request.TransactionID != "" {
		return helperResponse{}, errors.New("transport-bootstrap does not accept transaction proof fields")
	}
	if err := validateDisplayName(request.DisplayName); err != nil {
		return helperResponse{}, err
	}
	may, err := inspectTransportCandidate(
		3,
		request.CandidateMaySHA256,
		request.CandidateMayArchitecture,
		request.CandidateMayCDHash,
		request.CandidateMayDRSHA256,
		transportCodeKindMay,
	)
	if err != nil {
		return helperResponse{}, err
	}
	adapter, err := inspectTransportCandidate(
		4,
		request.CandidateAdapterSHA256,
		request.CandidateAdapterArchitecture,
		request.CandidateAdapterCDHash,
		request.CandidateAdapterDRSHA256,
		transportCodeKindSSHSign,
	)
	if err != nil {
		closeTransportCandidates(may)
		return helperResponse{}, err
	}
	defer closeTransportCandidates(may, adapter)
	dynamicMay, err := directParentIdentityResolver(transportCodeKindMay)
	if err != nil || sameDynamicAndStaticMay(dynamicMay, may.Identity) != nil {
		return helperResponse{}, errors.New("transport bootstrap direct parent does not match candidate may")
	}
	helper, err := currentHelperIdentityResolver()
	if err != nil {
		return helperResponse{}, errors.New("transport bootstrap helper exact identity is unavailable")
	}
	current, err := exactCurrentTransportSet(may.Identity, adapter.Identity)
	if err != nil {
		return helperResponse{}, err
	}

	identity, err := newIdentity(request.DisplayName)
	if err != nil {
		return helperResponse{}, errors.New("requester identity generation failed")
	}
	identity.Transport = &storedTransportTrust{
		Version:          transportStateVersion,
		BootstrapPending: true,
		CurrentHelper:    helper,
		Current:          current,
	}
	provisional, provisionalMetadata, err := encodeCredentialRecord(identity)
	if err != nil {
		return helperResponse{}, errors.New("requester identity encoding failed")
	}
	defer zero(provisional)
	defer zero(provisionalMetadata)
	if err := store.Create(
		keychainAccount,
		service,
		provisional,
		provisionalMetadata,
		keychainAccessPromptRequired,
	); errors.Is(err, errIdentityExists) {
		return helperResponse{}, errors.New("requester bootstrap slot already exists and cannot be adopted")
	} else if err != nil {
		return helperResponse{}, errors.New("requester bootstrap Keychain write failed")
	}
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	if err != nil || !found || !bytes.Equal(encodedMetadata, provisionalMetadata) {
		zero(encodedMetadata)
		return helperResponse{}, errors.New("requester bootstrap metadata authentication failed")
	}
	defer zero(encodedMetadata)
	if !sameTransportCodeIdentity(metadata.Transport.CurrentHelper, helper) ||
		!sameTransportSet(metadata.Transport.Current, current) ||
		!metadata.Transport.BootstrapPending {
		return helperResponse{}, errors.New("requester bootstrap metadata changed after creation")
	}
	loaded, encoded, err := loadIdentityForMetadata(
		store,
		service,
		metadata,
	)
	if err != nil || !bytes.Equal(encoded, provisional) {
		zero(encoded)
		return helperResponse{}, errors.New("requester bootstrap requires explicit Keychain approval")
	}
	defer zero(encoded)
	if loaded.Transport == nil || !loaded.Transport.BootstrapPending ||
		!sameTransportCodeIdentity(loaded.Transport.CurrentHelper, helper) ||
		!sameTransportSet(loaded.Transport.Current, current) {
		return helperResponse{}, errors.New("requester bootstrap proposal changed after creation")
	}
	loaded.Transport = &storedTransportTrust{
		Version:               transportStateVersion,
		ACLConvergencePending: true,
		CurrentHelper:         helper,
		Current:               current,
	}
	if err := replaceIdentityRecordAndConvergeACL(
		store,
		service,
		encodedMetadata,
		loaded,
	); err != nil {
		return helperResponse{}, errors.New("requester bootstrap could not constrain Keychain access to this helper")
	}
	return helperResponse{OK: true, Identity: &loaded.publicIdentity}, nil
}

func handleTransportStage(
	request helperRequest,
	store credentialStore,
	service string,
) (helperResponse, error) {
	if err := transportOperationHasNoApplicationFields(request); err != nil {
		return helperResponse{}, err
	}
	if err := digestFieldPresentOnlyFor(request, "may", "adapter", "helper"); err != nil {
		return helperResponse{}, err
	}
	if err := validateTransactionID(request.TransactionID); err != nil {
		return helperResponse{}, err
	}
	if _, err := currentHelperIdentityResolver(); err != nil {
		return helperResponse{}, errors.New("transport-stage caller is not a valid helper build")
	}
	if _, err := directParentIdentityResolver(transportCodeKindMay); err != nil {
		return helperResponse{}, errors.New("transport-stage caller is not a valid may build")
	}
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encodedMetadata)
	if !found {
		return helperResponse{}, errors.New("requester identity was not found")
	}
	if err := authenticateCurrentTransport(&metadata.Transport); err != nil {
		return helperResponse{}, err
	}
	if metadata.Transport.Staged != nil {
		return helperResponse{}, errors.New("a transport update is already staged")
	}
	identity, encoded, err := loadIdentityForMetadata(
		store,
		service,
		metadata,
	)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encoded)

	may, err := inspectTransportCandidate(
		3,
		request.CandidateMaySHA256,
		request.CandidateMayArchitecture,
		request.CandidateMayCDHash,
		request.CandidateMayDRSHA256,
		transportCodeKindMay,
	)
	if err != nil {
		return helperResponse{}, err
	}
	adapter, err := inspectTransportCandidate(
		4,
		request.CandidateAdapterSHA256,
		request.CandidateAdapterArchitecture,
		request.CandidateAdapterCDHash,
		request.CandidateAdapterDRSHA256,
		transportCodeKindSSHSign,
	)
	if err != nil {
		closeTransportCandidates(may)
		return helperResponse{}, err
	}
	helper, err := inspectTransportCandidate(
		5,
		request.CandidateHelperSHA256,
		request.CandidateHelperArchitecture,
		request.CandidateHelperCDHash,
		request.CandidateHelperDRSHA256,
		transportCodeKindHelper,
	)
	if err != nil {
		closeTransportCandidates(may, adapter)
		return helperResponse{}, err
	}
	defer closeTransportCandidates(may, adapter, helper)
	transports, err := exactCurrentTransportSet(may.Identity, adapter.Identity)
	if err != nil {
		return helperResponse{}, err
	}
	capability, capabilityHash, err := newCommitCapability()
	if err != nil {
		return helperResponse{}, errors.New("transport commit capability generation failed")
	}
	defer zero(capability)
	identity.Transport.Staged = &storedTransportTransaction{
		TransactionID:       request.TransactionID,
		CommitCapabilitySHA: capabilityHash,
		Helper:              helper.Identity,
		Transports:          transports,
	}
	if err := replaceIdentityRecord(
		store,
		service,
		encodedMetadata,
		identity,
		keychainAccessPreserve,
	); err != nil {
		return helperResponse{}, errors.New("staged transport state could not be persisted")
	}
	if err := writeCommitCapability(capability); err != nil {
		return helperResponse{}, err
	}
	return helperResponse{OK: true}, nil
}

func handleTransportFinalize(
	request helperRequest,
	store credentialStore,
	service string,
	helperBootstrap bool,
) (helperResponse, error) {
	if err := transportOperationHasNoApplicationFields(request); err != nil {
		return helperResponse{}, err
	}
	if err := digestFieldPresentOnlyFor(request); err != nil {
		return helperResponse{}, err
	}
	if err := validateTransactionID(request.TransactionID); err != nil {
		return helperResponse{}, err
	}
	parent, parentErr := directParentIdentityResolver(transportCodeKindMay)
	if parentErr != nil {
		return helperResponse{}, errors.New("transport commit direct parent is not an exact OneNod may build")
	}
	helper, helperErr := currentHelperIdentityResolver()
	if helperErr != nil {
		return helperResponse{}, errors.New("transport commit caller is not an exact helper build")
	}
	capability, err := readCommitCapability()
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(capability)
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encodedMetadata)
	if !found {
		return helperResponse{}, errors.New("requester transport trust was not found")
	}
	trust := &metadata.Transport
	if trust.Staged == nil {
		if trust.LastFinalizedTransactionID == request.TransactionID &&
			trust.LastFinalizedTransactionState == "committed" &&
			currentAuthorizedSet(trust).authorizes(parent) {
			if !sameTransportCodeIdentity(helper, trust.CurrentHelper) {
				return helperResponse{}, errors.New("idempotent transport commit requires the committed exact helper")
			}
			if trust.ACLConvergencePending {
				if err := repairACLConvergence(store, service, metadata, encodedMetadata); err != nil {
					return helperResponse{}, errors.New("committed Keychain ACL repair failed")
				}
			}
			return helperResponse{OK: true}, nil
		}
		return helperResponse{}, errors.New("no matching staged transport update exists")
	}
	staged := trust.Staged
	if staged.TransactionID != request.TransactionID ||
		!verifyRawCommitCapability(capability, staged.CommitCapabilitySHA) {
		return helperResponse{}, errors.New("transport commit proof is invalid")
	}
	if !currentAuthorizedSet(trust).stages(parent) {
		return helperResponse{}, errors.New("transport commit caller is not the staged exact may build")
	}
	helperChanged := !sameTransportCodeIdentity(
		trust.CurrentHelper,
		staged.Helper,
	)
	if helperBootstrap {
		if !helperChanged || !sameTransportCodeIdentity(helper, staged.Helper) {
			return helperResponse{}, errors.New("transport-bootstrap-helper requires the staged exact helper build")
		}
	} else if helperChanged || !sameTransportCodeIdentity(helper, trust.CurrentHelper) {
		return helperResponse{}, errors.New("transport-commit requires an unchanged current helper build")
	}
	// Only after all public metadata, exact code, and anonymous capability checks
	// succeed may a changed helper request kSecValueData and potentially present
	// the one-time Keychain approval dialog.
	identity, encoded, err := loadIdentityForMetadata(
		store,
		service,
		metadata,
	)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encoded)
	staged = identity.Transport.Staged
	identity.Transport.CurrentHelper = staged.Helper
	identity.Transport.Current = cloneTransportIdentities(staged.Transports)
	identity.Transport.Staged = nil
	identity.Transport.LastFinalizedTransactionID = request.TransactionID
	identity.Transport.LastFinalizedTransactionState = "committed"
	var persistErr error
	if helperChanged {
		identity.Transport.ACLConvergencePending = true
		persistErr = replaceIdentityRecordAndConvergeACL(
			store, service, encodedMetadata, identity,
		)
	} else {
		persistErr = replaceIdentityRecord(
			store, service, encodedMetadata, identity, keychainAccessPreserve,
		)
	}
	if persistErr != nil {
		return helperResponse{}, errors.New("transport commit or Keychain ACL convergence failed")
	}
	return helperResponse{OK: true}, nil
}

func handleTransportAbort(
	request helperRequest,
	store credentialStore,
	service string,
) (helperResponse, error) {
	if err := transportOperationHasNoApplicationFields(request); err != nil {
		return helperResponse{}, err
	}
	if err := digestFieldPresentOnlyFor(request); err != nil {
		return helperResponse{}, err
	}
	if err := validateTransactionID(request.TransactionID); err != nil {
		return helperResponse{}, err
	}
	if _, err := currentHelperIdentityResolver(); err != nil {
		return helperResponse{}, errors.New("transport-abort caller is not a valid helper build")
	}
	if _, err := directParentIdentityResolver(transportCodeKindMay); err != nil {
		return helperResponse{}, errors.New("transport-abort caller is not a valid may build")
	}
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encodedMetadata)
	if !found {
		return helperResponse{}, errors.New("requester transport trust was not found")
	}
	trust := &metadata.Transport
	if trust.Staged == nil {
		if trust.LastFinalizedTransactionID == request.TransactionID &&
			trust.LastFinalizedTransactionState == "aborted" &&
			authenticateCurrentTransport(trust) == nil {
			return helperResponse{OK: true}, nil
		}
		return helperResponse{}, errors.New("no matching staged transport update exists")
	}
	if trust.Staged.TransactionID != request.TransactionID {
		return helperResponse{}, errors.New("transport-abort transaction does not match staged state")
	}
	if err := authenticateCurrentTransport(trust); err != nil {
		return helperResponse{}, errors.New("transport-abort requires the restored current helper and may builds")
	}
	identity, encoded, err := loadIdentityForMetadata(
		store,
		service,
		metadata,
	)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encoded)
	identity.Transport.Staged = nil
	identity.Transport.LastFinalizedTransactionID = request.TransactionID
	identity.Transport.LastFinalizedTransactionState = "aborted"
	if err := replaceIdentityRecord(
		store,
		service,
		encodedMetadata,
		identity,
		keychainAccessPreserve,
	); err != nil {
		return helperResponse{}, errors.New("transport abort or Keychain ACL convergence failed")
	}
	return helperResponse{OK: true}, nil
}

func handleTransportStatus(
	request helperRequest,
	store credentialStore,
	service string,
) (helperResponse, error) {
	if err := transportOperationHasNoApplicationFields(request); err != nil {
		return helperResponse{}, err
	}
	if err := digestFieldPresentOnlyFor(request); err != nil {
		return helperResponse{}, err
	}
	if request.TransactionID != "" {
		return helperResponse{}, errors.New("transport-status does not accept transaction proof fields")
	}
	if _, err := currentHelperIdentityResolver(); err != nil {
		return helperResponse{}, errors.New("transport-status caller is not a valid helper build")
	}
	if _, err := directParentIdentityResolver(transportCodeKindMay); err != nil {
		return helperResponse{}, errors.New("transport-status caller is not a valid may build")
	}
	metadata, encodedMetadata, found, err := inspectCredentialMetadata(store, service)
	if err != nil {
		return helperResponse{}, err
	}
	defer zero(encodedMetadata)
	if !found {
		return helperResponse{OK: true, Role: "none"}, nil
	}
	if metadata.Transport.BootstrapPending {
		return helperResponse{}, errors.New("requester transport bootstrap is incomplete")
	}
	role, err := transportCallerRole(&metadata.Transport)
	if err != nil {
		return helperResponse{}, err
	}
	if role == "current" && metadata.Transport.ACLConvergencePending {
		// A changed-helper finalize may have persisted the new current exact
		// state before SecKeychainItemSetAccess completed or before its response
		// reached may. Authenticated status is the capability-free repair boundary.
		if err := repairACLConvergence(store, service, metadata, encodedMetadata); err != nil {
			return helperResponse{}, errors.New("finalized Keychain ACL repair failed")
		}
	}
	response := helperResponse{OK: true, Role: role}
	if metadata.Transport.Staged != nil {
		response.TransactionID = metadata.Transport.Staged.TransactionID
		response.TransactionState = "staged"
	} else if metadata.Transport.LastFinalizedTransactionID != "" {
		response.TransactionID = metadata.Transport.LastFinalizedTransactionID
		response.TransactionState = metadata.Transport.LastFinalizedTransactionState
	}
	return response, nil
}

func validateDisplayName(displayName string) error {
	if strings.TrimSpace(displayName) == "" || len(displayName) > 128 ||
		strings.ContainsAny(displayName, "\x00\r\n") {
		return errors.New("display_name is invalid")
	}
	return nil
}

func transportOperationHasNoApplicationFieldsExceptDisplayName(request helperRequest) error {
	if request.ApplicationEvidence != "" || request.CanonicalBody != "" || request.Message != "" {
		return errors.New("transport-bootstrap does not accept application or signing fields")
	}
	return nil
}

func replaceIdentityRecord(
	store credentialStore,
	service string,
	expectedMetadata []byte,
	identity storedIdentity,
	access keychainAccessPolicy,
) error {
	encoded, metadata, err := encodeCredentialRecord(identity)
	if err != nil {
		return errors.New("requester identity encoding failed")
	}
	defer zero(encoded)
	defer zero(metadata)
	if err := store.Replace(
		keychainAccount,
		service,
		expectedMetadata,
		encoded,
		metadata,
		access,
	); err != nil {
		if errors.Is(err, errIdentityChanged) {
			return errIdentityChanged
		}
		return safeTransportError(err)
	}
	return nil
}

// replaceIdentityRecordAndConvergeACL makes the content transition durable
// before changing the legacy Keychain ACL. ACLConvergencePending is signed into
// both the public envelope and private data, so a crash after that first call is
// repaired only by the newly-current exact helper and may through status.
func replaceIdentityRecordAndConvergeACL(
	store credentialStore,
	service string,
	expectedMetadata []byte,
	identity storedIdentity,
) error {
	if identity.Transport == nil || !identity.Transport.ACLConvergencePending {
		return errors.New("Keychain ACL convergence marker is missing")
	}
	pendingData, pendingMetadata, err := encodeCredentialRecord(identity)
	if err != nil {
		return errors.New("requester identity encoding failed")
	}
	defer zero(pendingData)
	defer zero(pendingMetadata)
	if err := store.Replace(
		keychainAccount, service, expectedMetadata,
		pendingData, pendingMetadata, keychainAccessSelfOnly,
	); err != nil {
		return safeTransportError(err)
	}
	identity.Transport.ACLConvergencePending = false
	if err := replaceIdentityRecord(
		store, service, pendingMetadata, identity, keychainAccessPreserve,
	); err != nil {
		return err
	}
	return nil
}

func repairACLConvergence(
	store credentialStore,
	service string,
	metadata credentialMetadata,
	encodedMetadata []byte,
) error {
	if !metadata.Transport.ACLConvergencePending || metadata.Transport.Staged != nil ||
		metadata.Transport.BootstrapPending {
		return errors.New("Keychain ACL convergence state is invalid")
	}
	identity, encoded, err := loadIdentityForMetadata(store, service, metadata)
	if err != nil {
		return err
	}
	defer zero(encoded)
	if identity.Transport == nil || !identity.Transport.ACLConvergencePending {
		return errors.New("Keychain ACL convergence state changed")
	}
	if err := store.Constrain(
		keychainAccount, service, encodedMetadata, keychainAccessSelfOnly,
	); err != nil {
		return err
	}
	identity.Transport.ACLConvergencePending = false
	return replaceIdentityRecord(
		store, service, encodedMetadata, identity, keychainAccessPreserve,
	)
}
