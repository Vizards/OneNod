package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maximumBeholderWorkerMessage = 16 * 1024 * 1024

// The local context service uses the installed requester's existing signing
// authority. The input and output stay on pipes and never contain its key.
func runInternalBeholderWorkerStep(config cliConfig, deps dependencies, expectedDeviceID string) error {
	if !safeBeholderToken(expectedDeviceID, 8, 128) || config.origin == "" {
		return errors.New("invalid Beholder Worker requester identity")
	}
	decoder := json.NewDecoder(io.LimitReader(deps.stdin, maximumBeholderWorkerMessage+1))
	decoder.DisallowUnknownFields()
	var input struct {
		EvidenceID string          `json:"evidence_id"`
		Variant    string          `json:"variant"`
		Action     string          `json:"action"`
		Body       json.RawMessage `json:"body"`
	}
	if decoder.Decode(&input) != nil || ensureDecoderEOF(decoder) != nil ||
		!safeBeholderToken(input.EvidenceID, 8, 96) ||
		(input.Variant != "primary" && input.Variant != "comparison") ||
		(input.Action != "start" && input.Action != "step") ||
		len(input.Body) == 0 || len(input.Body) > maximumBeholderWorkerMessage || !json.Valid(input.Body) {
		return errors.New("invalid Beholder Worker message")
	}
	credential, err := deps.keychain.Load()
	if err != nil {
		return err
	}
	if credential.DeviceID != expectedDeviceID {
		return errors.New("Beholder Worker requester identity mismatch")
	}
	client, err := newAPIClient(config.origin, credential, deps.httpClient)
	if err != nil {
		return err
	}
	path := "/v1/beholder/decisions/" + input.EvidenceID + "/" + input.Variant + "/" + input.Action
	ctx, cancel := context.WithTimeout(context.Background(), 190*time.Second)
	defer cancel()
	var response json.RawMessage
	if err := client.doBeholderWorkerJSON(ctx, path, input.Body, &response); err != nil {
		return err
	}
	return json.NewEncoder(deps.stdout).Encode(response)
}

// Only a small digest envelope is signed and authenticated before the
// Gateway accepts the larger context body. The digest covers its exact bytes.
func (client *apiClient) doBeholderWorkerJSON(ctx context.Context, path string, body []byte, result any) error {
	digest := sha256.Sum256(body)
	digestHex := hex.EncodeToString(digest[:])
	canonical, err := canonicalJSON(map[string]any{
		"content_bytes": len(body), "content_sha256": digestHex,
	})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.origin.String()+path, bytes.NewReader(body))
	if err != nil {
		return errors.New("create Worker request failed")
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("accept", "application/json")
	request.Header.Set("x-onenod-beholder-content-sha256", digestHex)
	request.Header.Set("x-onenod-beholder-content-bytes", strconv.Itoa(len(body)))
	if err := client.sign(request, path, canonical, nil); err != nil {
		return err
	}
	return client.executeJSON(request, result)
}
