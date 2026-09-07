package beholdercontext

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
)

func TestDeriveToolInputFeaturesKeepsOnlyCoarseSignals(t *testing.T) {
	t.Parallel()
	secret := "TOKEN=E1_FEATURE_SENTINEL_DO_NOT_STORE"
	path := "/Users/example/.onenod/bin/may"
	host := "example.invalid"
	features := deriveToolInputFeatures(secret + " " + path + " preflight | ssh -G " + host)
	if !features.Observed || !features.HasPipe {
		t.Fatalf("missing coarse signals: %+v", features)
	}
	for _, expected := range []string{"credential", "network", "onenod", "ssh"} {
		if !slices.Contains(features.Families, expected) {
			t.Fatalf("missing family %q: %+v", expected, features)
		}
	}
	encoded, err := json.Marshal(features)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, path, host, "E1_FEATURE_SENTINEL_DO_NOT_STORE"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("derived features retained raw token %q", forbidden)
		}
	}
	if features.RawCommandStored || features.RawTokensStored {
		t.Fatalf("raw storage flags must stay false: %+v", features)
	}
}

func TestDeriveToolInputFeaturesRecognizesMacPeerInsideExecSource(t *testing.T) {
	features := deriveToolInputFeatures("await tools.exec_command({cmd: `mac-peer macbook true`});")
	for _, expected := range []string{"ssh", "network"} {
		if !slices.Contains(features.Families, expected) {
			t.Fatalf("freeform exec source is missing family %q: %+v", expected, features)
		}
	}
}
