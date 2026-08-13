//go:build darwin

package main

import "testing"

func TestVerifiedHelperObservationBecomesApplicationScope(t *testing.T) {
	t.Parallel()
	context := resolveObservedApplication(
		func(_ string, _ string, evidence applicationEvidence) (localClientContext, error) {
			if evidence.Kind != applicationEvidenceParent {
				t.Fatalf("evidence kind = %q", evidence.Kind)
			}
			return localClientContext{
				Observation: clientObservation{
					Application: "Signed Editor",
					Identity: applicationIdentity{
						Assurance:         applicationAssuranceVerified,
						Platform:          "macos",
						PrincipalScheme:   macOSPrincipalScheme,
						PrincipalID:       "verified-principal",
						SigningIdentifier: "com.example.editor",
						TeamIdentifier:    "EXAMPLETEAM",
					},
					Source: "process-ancestry",
				},
				ScopeID:   "verified-principal",
				ScopeKind: "application",
			}, nil
		},
		"https://onenod.example.workers.dev",
		"active",
		applicationEvidence{Kind: applicationEvidenceParent},
	)
	if context.ScopeID != "verified-principal" || context.ScopeKind != "application" {
		t.Fatalf("verified application context = %+v", context)
	}
	if context.Observation.Identity.SigningIdentifier != "com.example.editor" {
		t.Fatalf("verified observation = %+v", context.Observation)
	}
}

func TestUnavailableResolverCannotProduceRememberedScope(t *testing.T) {
	t.Parallel()
	context := resolveObservedApplication(
		nil,
		"https://onenod.example.workers.dev",
		"active",
		applicationEvidence{Kind: applicationEvidenceParent},
	)
	if context.ScopeID != "" || context.ScopeKind != "" {
		t.Fatalf("unavailable resolver produced scope %+v", context)
	}
	if context.Observation.Identity.Assurance != applicationAssuranceUnverified {
		t.Fatalf("unavailable identity = %+v", context.Observation.Identity)
	}
}
