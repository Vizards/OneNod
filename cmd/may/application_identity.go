package main

import (
	"errors"
	"os"
)

const (
	applicationAssuranceUnverified = "unverified"
	applicationAssuranceVerified   = "verified-code-signature"
	applicationEvidenceParent      = "parent"
	applicationEvidenceSSHPeer     = "ssh-peer"
	macOSPrincipalScheme           = "macos-designated-requirement-v1"
)

type applicationIdentity struct {
	Assurance         string `json:"assurance"`
	Platform          string `json:"platform"`
	PrincipalScheme   string `json:"principal_scheme,omitempty"`
	PrincipalID       string `json:"principal_id,omitempty"`
	SignerName        string `json:"signer_name,omitempty"`
	SigningIdentifier string `json:"signing_identifier,omitempty"`
	TeamIdentifier    string `json:"team_identifier,omitempty"`
}

type applicationEvidence struct {
	Kind     string
	PeerFile *os.File
}

func (evidence applicationEvidence) close() {
	if evidence.PeerFile != nil {
		_ = evidence.PeerFile.Close()
	}
}

type applicationResolver func(
	origin string,
	slot string,
	evidence applicationEvidence,
) (localClientContext, error)

func resolveObservedApplication(
	resolver applicationResolver,
	origin string,
	slot string,
	evidence applicationEvidence,
) localClientContext {
	if resolver == nil {
		evidence.close()
		return unknownLocalClientContext()
	}
	context, err := resolver(origin, slot, evidence)
	if err != nil {
		evidence.close()
		return unknownLocalClientContext()
	}
	context.Evidence = evidence
	return context
}

func resolveApplicationWithHelper(
	origin string,
	slot string,
	evidence applicationEvidence,
) (localClientContext, error) {
	observation, err := observeApplicationWithHelper(origin, slot, evidence)
	if err != nil {
		return localClientContext{}, err
	}
	context := localClientContext{Observation: observation}
	if observation.Identity.Assurance == applicationAssuranceVerified {
		if observation.Identity.PrincipalScheme != macOSPrincipalScheme ||
			observation.Identity.PrincipalID == "" {
			return localClientContext{}, errors.New("Keychain helper returned an invalid verified application identity")
		}
		context.ScopeID = observation.Identity.PrincipalID
		context.ScopeKind = "application"
	}
	return context, nil
}

func callingApplicationContext(
	config cliConfig,
	deps dependencies,
) localClientContext {
	return resolveObservedApplication(
		deps.applicationResolver,
		config.origin,
		deps.keychain.slot,
		applicationEvidence{Kind: applicationEvidenceParent},
	)
}

func unknownApplicationIdentity() applicationIdentity {
	return applicationIdentity{
		Assurance: applicationAssuranceUnverified,
		Platform:  runtimeApplicationPlatform(),
	}
}
