package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	headerDeviceID               = "x-onenod-device-id"
	headerRequestNonce           = "x-onenod-request-nonce"
	headerRequestSignature       = "x-onenod-request-signature"
	headerRequestTimestamp       = "x-onenod-request-timestamp"
	headerApplicationAttestation = "x-onenod-application-attestation"
	headerGatewayErrorCode       = "x-onenod-error-code"
	maxResponseBytes             = 1 << 20
)

var workersDevHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.workers\.dev$`)
var safeGatewayErrorCodes = map[string]int{
	"onepassword_rate_limited": http.StatusTooManyRequests,
	"requester_not_found":      http.StatusNotFound,
}

type gatewayHTTPError struct {
	Code   string
	Status int
}

func (value *gatewayHTTPError) Error() string {
	return fmt.Sprintf("gateway returned %s (HTTP %d)", value.Code, value.Status)
}

func isGatewayErrorCode(err error, code string) bool {
	var gatewayError *gatewayHTTPError
	expectedStatus, supported := safeGatewayErrorCodes[code]
	return supported && errors.As(err, &gatewayError) &&
		gatewayError.Code == code && gatewayError.Status == expectedStatus
}

type apiClient struct {
	credential *requesterCredential
	httpClient *http.Client
	now        func() time.Time
	origin     *url.URL
	random     io.Reader
}

func newAPIClient(
	origin string,
	credential *requesterCredential,
	httpClient *http.Client,
) (*apiClient, error) {
	parsed, err := parseGatewayOrigin(origin)
	if err != nil {
		return nil, err
	}
	if credential == nil {
		return nil, errors.New("requester credential is required")
	}
	if err := credential.validatePublic(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: gatewayRequestTimeout}
	}
	safeHTTPClient := *httpClient
	if safeHTTPClient.CheckRedirect == nil {
		safeHTTPClient.CheckRedirect = func(
			_ *http.Request,
			_ []*http.Request,
		) error {
			return errors.New("gateway redirects are not allowed")
		}
	}
	return &apiClient{
		credential: credential,
		httpClient: &safeHTTPClient,
		now:        time.Now,
		origin:     parsed,
		random:     rand.Reader,
	}, nil
}

func parseGatewayOrigin(origin string) (*url.URL, error) {
	parsed, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("parse origin: %w", err)
	}
	workersDev := strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".workers.dev")
	if workersDev {
		if parsed.Scheme != "https" || parsed.Host != parsed.Hostname() ||
			parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || !workersDevHostPattern.MatchString(parsed.Host) ||
			parsed.String() != origin {
			return nil, errors.New("workers.dev origin must be normalized lowercase HTTPS with no port, path, query, fragment, or userinfo")
		}
		return parsed, nil
	}
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	if parsed.Scheme == "" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("origin must contain only scheme and host")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("origin must use HTTPS except for localhost")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (client *apiClient) doJSON(
	ctx context.Context,
	method string,
	path string,
	body any,
	result any,
) error {
	return client.doJSONInternal(ctx, method, path, body, result, nil, "")
}

func (client *apiClient) doApplicationJSON(
	ctx context.Context,
	method string,
	path string,
	body any,
	result any,
	application localClientContext,
) error {
	return client.doJSONInternal(
		ctx, method, path, body, result, &application.Evidence, "",
	)
}

func (client *apiClient) doCapabilityJSON(
	ctx context.Context,
	method string,
	path string,
	body any,
	result any,
	pollToken string,
) error {
	if !validPollingCapability(pollToken) {
		return errors.New("gateway returned an invalid polling capability")
	}
	return client.doJSONInternal(
		ctx, method, path, body, result, nil, pollToken,
	)
}

func (client *apiClient) doJSONInternal(
	ctx context.Context,
	method string,
	path string,
	body any,
	result any,
	applicationEvidence *applicationEvidence,
	bearerToken string,
) error {
	var canonicalBody []byte
	var requestBody io.Reader
	if body == nil {
		// Signed body-less requests use the canonical empty object as their
		// digest input. No GET request body is sent over HTTP.
		canonicalBody = []byte("{}")
	} else {
		var err error
		canonicalBody, err = canonicalJSON(body)
		if err != nil {
			return err
		}
		requestBody = bytes.NewReader(canonicalBody)
	}

	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("request path must be absolute and contain no query or fragment")
	}
	requestURL := client.origin.String() + path
	request, err := http.NewRequestWithContext(
		ctx,
		strings.ToUpper(method),
		requestURL,
		requestBody,
	)
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}
	if body != nil {
		request.Header.Set("content-type", "application/json")
	}
	request.Header.Set("accept", "application/json")
	if bearerToken != "" {
		request.Header.Set("authorization", "Bearer "+bearerToken)
	}
	if err := client.sign(request, path, canonicalBody, applicationEvidence); err != nil {
		return err
	}
	return client.executeJSON(request, result)
}

func (client *apiClient) doPollingJSON(
	ctx context.Context,
	path string,
	pollToken string,
	result any,
) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("request path must be absolute and contain no query or fragment")
	}
	if !validPollingCapability(pollToken) {
		return errors.New("gateway returned an invalid polling capability")
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		client.origin.String()+path,
		nil,
	)
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}
	request.Header.Set("accept", "application/json")
	request.Header.Set("authorization", "Bearer "+pollToken)
	return client.executeJSON(request, result)
}

func validPollingCapability(pollToken string) bool {
	if len(pollToken) != 43 {
		return false
	}
	for _, value := range pollToken {
		if !(value >= 'A' && value <= 'Z') &&
			!(value >= 'a' && value <= 'z') &&
			!(value >= '0' && value <= '9') && value != '_' && value != '-' {
			return false
		}
	}
	return true
}

func (client *apiClient) executeJSON(request *http.Request, result any) error {
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("gateway request failed: %w", err)
	}
	defer response.Body.Close()

	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return errors.New("read gateway response failed")
	}
	if len(responseBody) > maxResponseBytes {
		return errors.New("gateway response exceeded size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Gateway error bodies may contain request metadata or secret-shaped
		// upstream diagnostics. Do not attach them to CLI errors.
		code := response.Header.Get(headerGatewayErrorCode)
		if isSafeGatewayErrorCode(code, response.StatusCode) {
			return &gatewayHTTPError{Code: code, Status: response.StatusCode}
		}
		return fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(response.Header.Get("content-type")); mediaType != "" &&
		!strings.HasPrefix(mediaType, "application/json") {
		return errors.New("gateway returned a non-JSON response")
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return errors.New("gateway returned invalid JSON")
	}
	return nil
}

func isSafeGatewayErrorCode(code string, status int) bool {
	expected, ok := safeGatewayErrorCodes[code]
	return ok && expected == status
}

func (client *apiClient) sign(
	request *http.Request,
	path string,
	canonicalBody []byte,
	applicationEvidence *applicationEvidence,
) error {
	nonceBytes := make([]byte, 16)
	if _, err := io.ReadFull(client.random, nonceBytes); err != nil {
		return fmt.Errorf("generate request nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := client.now().Unix()
	canonical, err := canonicalSignatureString(signatureInput{
		Audience:  client.origin.Host,
		Body:      canonicalBody,
		DeviceID:  client.credential.DeviceID,
		Method:    request.Method,
		Nonce:     nonce,
		Path:      path,
		Timestamp: timestamp,
	})
	if err != nil {
		return err
	}
	signature, applicationAttestation, err :=
		client.credential.signCanonicalWithApplication(
			[]byte(canonical), canonicalBody, applicationEvidence,
		)
	if err != nil {
		return err
	}
	request.Header.Set(headerDeviceID, client.credential.DeviceID)
	request.Header.Set(headerRequestTimestamp, strconv.FormatInt(timestamp, 10))
	request.Header.Set(headerRequestNonce, nonce)
	request.Header.Set(
		headerRequestSignature,
		base64.RawURLEncoding.EncodeToString(signature),
	)
	if len(applicationAttestation) > 0 {
		request.Header.Set(
			headerApplicationAttestation,
			base64.RawURLEncoding.EncodeToString(applicationAttestation),
		)
	}
	return nil
}

func newUUIDv4() (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return formatUUID(bytes), nil
}

func newUUIDv7(now time.Time) (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, bytes[6:]); err != nil {
		return "", fmt.Errorf("generate UUID: %w", err)
	}
	milliseconds := uint64(now.UnixMilli())
	var timestamp [8]byte
	binary.BigEndian.PutUint64(timestamp[:], milliseconds)
	copy(bytes[:6], timestamp[2:])
	bytes[6] = (bytes[6] & 0x0f) | 0x70
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	return formatUUID(bytes), nil
}

func formatUUID(value []byte) string {
	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		value[0:4],
		value[4:6],
		value[6:8],
		value[8:10],
		value[10:16],
	)
}
