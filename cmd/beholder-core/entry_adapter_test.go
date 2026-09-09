package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDirectMayAdapterBindsExactRequestWithoutRetainingValues(t *testing.T) {
	secretSentinel := "E1_SECRET_VALUE_MUST_NOT_CROSS_THE_ADAPTER"
	payload := []byte(`{"action":"secret.read","item_id":"item-alpha","field_id":"password","value":"` + secretSentinel + `"}`)
	request, err := directMayOperationTarget(
		"secret.read",
		"item-alpha",
		[]string{"password"},
		7,
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secretSentinel) || strings.Contains(string(encoded), `"value"`) {
		t.Fatalf("direct may adapter retained a request value: %s", encoded)
	}
	store := testDecisionBindingStore(t)
	capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: request})
	if issue.ErrorCode != "" {
		t.Fatal(issue)
	}
	if result := store.consume(capability, request); !result.Matched {
		t.Fatalf("exact direct may request did not consume: %+v", result)
	}
}

func TestDirectMayAdapterRejectsChangedFieldVersionOrPayload(t *testing.T) {
	approvedPayload := []byte(`{"action":"credential.use","item_id":"item-alpha","field_ids":["password","username"],"expected_version":7}`)
	approved, err := directMayOperationTarget(
		"credential.use",
		"item-alpha",
		[]string{"password", "username"},
		7,
		approvedPayload,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		fields  []string
		version int64
		payload []byte
	}{
		{name: "field", fields: []string{"password"}, version: 7, payload: approvedPayload},
		{name: "version", fields: []string{"password", "username"}, version: 8, payload: approvedPayload},
		{name: "payload", fields: []string{"password", "username"}, version: 7, payload: append(append([]byte(nil), approvedPayload...), ' ')},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, targetErr := directMayOperationTarget("credential.use", "item-alpha", test.fields, test.version, test.payload)
			if targetErr != nil {
				t.Fatal(targetErr)
			}
			store := testDecisionBindingStore(t)
			capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: approved})
			if issue.ErrorCode != "" {
				t.Fatal(issue)
			}
			if result := store.consume(capability, actual); result.Matched || result.ErrorCode != "operation-target-mismatch" {
				t.Fatalf("changed direct may request was accepted: %+v", result)
			}
		})
	}
}

func TestSSHAndGitAdaptersShareOneContractButCannotCrossConsume(t *testing.T) {
	ssh, err := sshAgentOperationTarget(
		"ssh.authentication",
		"item-key-alpha",
		"SHA256:key-alpha",
		"deploy",
		"SHA256:host-alpha",
		[]byte("exact SSH userauth payload"),
	)
	if err != nil {
		t.Fatal(err)
	}
	git, err := sshAgentOperationTarget(
		"git.ssh-signature",
		"item-key-alpha",
		"SHA256:key-alpha",
		"",
		"",
		[]byte("exact SSHSIG git payload"),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := testDecisionBindingStore(t)
	capability, issue := store.issue(gatekeeperDecisionFixture{Disposition: "allow", Request: ssh})
	if issue.ErrorCode != "" {
		t.Fatal(issue)
	}
	if result := store.consume(capability, git); result.Matched || result.ErrorCode != "operation-target-mismatch" {
		t.Fatalf("SSH authorization crossed into Git signing: %+v", result)
	}
}

func TestDirectMayAdapterRequiresCanonicalFieldOrder(t *testing.T) {
	if _, err := directMayOperationTarget(
		"credential.use",
		"item-alpha",
		[]string{"username", "password"},
		7,
		[]byte(`{"action":"credential.use"}`),
	); err == nil {
		t.Fatal("non-canonical direct may field order was accepted")
	}
}
