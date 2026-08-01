package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	jsoncanonicalizer "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const requesterProtocol = "onenod-request-v1"

type signatureInput struct {
	Audience  string
	Body      []byte
	DeviceID  string
	Method    string
	Nonce     string
	Path      string
	Timestamp int64
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}

	if err := validateCanonicalJSONNumbers(decoded); err != nil {
		return nil, err
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil {
		return nil, fmt.Errorf("canonicalize request body: %w", err)
	}
	return canonical, nil
}

func validateCanonicalJSONNumbers(value any) error {
	switch typed := value.(type) {
	case nil, bool, string:
		return nil
	case json.Number:
		return validateCanonicalInteger(typed.String())
	case []any:
		for _, item := range typed {
			if err := validateCanonicalJSONNumbers(item); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range typed {
			if err := validateCanonicalJSONNumbers(item); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported canonical JSON value %T", value)
	}
}

func validateCanonicalInteger(value string) error {
	if strings.ContainsAny(value, ".eE") {
		return errors.New("request bodies may only contain integer JSON numbers")
	}
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return nil
	}
	if _, err := strconv.ParseUint(value, 10, 64); err == nil {
		return nil
	}
	return fmt.Errorf("invalid integer JSON number %q", value)
}

func canonicalSignatureString(input signatureInput) (string, error) {
	if input.Audience == "" || strings.ContainsAny(input.Audience, "\r\n") {
		return "", errors.New("invalid signature audience")
	}
	method := strings.ToUpper(input.Method)
	if method == "" || strings.ContainsAny(method, "\r\n") {
		return "", errors.New("invalid signature method")
	}
	if !strings.HasPrefix(input.Path, "/") ||
		strings.ContainsAny(input.Path, "?#\r\n") {
		return "", errors.New("signature path must be an absolute path without query or fragment")
	}
	for name, value := range map[string]string{
		"device ID": input.DeviceID,
		"nonce":     input.Nonce,
	} {
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return "", fmt.Errorf("invalid %s", name)
		}
	}
	if input.Timestamp < 0 {
		return "", errors.New("signature timestamp must be non-negative")
	}

	bodyHash := sha256.Sum256(input.Body)
	lines := []string{
		requesterProtocol,
		input.Audience,
		method,
		input.Path,
		base64.RawURLEncoding.EncodeToString(bodyHash[:]),
		input.DeviceID,
		strconv.FormatInt(input.Timestamp, 10),
		input.Nonce,
	}
	return strings.Join(lines, "\n"), nil
}
