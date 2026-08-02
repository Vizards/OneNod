package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestKeychainHelperResponseAcceptsHelloContract(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(
		`{"ok":true,"protocol":1,"source_commit":"0123456789abcdef0123456789abcdef01234567","version":"1.0.0"}`,
	))
	decoder.DisallowUnknownFields()
	var response keychainHelperResponse
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("decode helper hello response: %v", err)
	}
	if !response.OK || response.Protocol != 1 || response.Version != "1.0.0" ||
		response.Source != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("unexpected helper hello response: %+v", response)
	}
}
