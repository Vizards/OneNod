//go:build !darwin || !cgo

package main

import "os"

func resolveApplicationIdentity(evidence string) (applicationIdentity, error) {
	return resolveApplicationIdentityWithAuthorizedTransports(evidence, authorizedTransportSet{})
}

func resolveApplicationIdentityWithAuthorizedTransports(
	evidence string,
	_ authorizedTransportSet,
) (applicationIdentity, error) {
	if err := validateApplicationEvidence(evidence); err != nil {
		return applicationIdentity{}, err
	}
	return applicationIdentity{}, errApplicationIdentityUnavailable
}

func currentHelperTransportCodeIdentity() (transportCodeIdentity, error) {
	return transportCodeIdentity{}, errApplicationIdentityUnavailable
}

func directParentTransportCodeIdentity(
	_ transportCodeKind,
) (transportCodeIdentity, error) {
	return transportCodeIdentity{}, errApplicationIdentityUnavailable
}

func transportCodeIdentityAtFile(
	_ *os.File,
	_ transportCodeKind,
) (transportCodeIdentity, error) {
	return transportCodeIdentity{}, errApplicationIdentityUnavailable
}
