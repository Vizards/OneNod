package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func fetchCloudflareAccounts(
	base http.RoundTripper,
	oauthToken []byte,
) ([]activeWranglerAccount, error) {
	if len(oauthToken) == 0 {
		return nil, errors.New("Wrangler OAuth token is empty")
	}
	client := secureCloudflareAPIClient(base)
	seen := map[string]struct{}{}
	var accounts []activeWranglerAccount
	for page := 1; page <= maxCloudflareAccountPages; page++ {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		address := fmt.Sprintf(
			"https://api.cloudflare.com/client/v4/accounts?page=%d&per_page=%d",
			page, cloudflareAccountPageSize,
		)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			cancel()
			return nil, errors.New("build Cloudflare accounts request failed")
		}
		request.Header.Set("Authorization", "Bearer "+string(oauthToken))
		response, err := client.Do(request)
		if err != nil {
			cancel()
			return nil, errors.New("list Cloudflare accounts for Wrangler profile failed")
		}
		encoded, readErr := io.ReadAll(io.LimitReader(
			response.Body, maxCloudflareAccountResponse+1,
		))
		closeErr := response.Body.Close()
		cancel()
		if readErr != nil || closeErr != nil || len(encoded) > maxCloudflareAccountResponse {
			zeroBytes(encoded)
			return nil, errors.New("read Cloudflare accounts response failed")
		}
		var envelope struct {
			Success bool `json:"success"`
			Result  []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"result"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(encoded, &envelope) != nil || !envelope.Success {
			zeroBytes(encoded)
			return nil, errors.New("Wrangler OAuth cannot list Cloudflare accounts")
		}
		zeroBytes(encoded)
		for _, account := range envelope.Result {
			if !cloudflareAccountIDPattern.MatchString(account.ID) ||
				strings.TrimSpace(account.Name) == "" {
				return nil, errors.New("Cloudflare returned an invalid account")
			}
			if _, duplicate := seen[account.ID]; duplicate {
				return nil, errors.New("Cloudflare returned a duplicate account")
			}
			seen[account.ID] = struct{}{}
			accounts = append(accounts, activeWranglerAccount{
				ID: account.ID, Name: account.Name,
			})
		}
		if len(envelope.Result) < cloudflareAccountPageSize {
			return accounts, nil
		}
	}
	return nil, errors.New("Cloudflare account discovery exceeded its page limit")
}

func fetchCloudflareAccountSubdomain(base http.RoundTripper, accountID string, oauthToken []byte) (string, error) {
	client := secureCloudflareAPIClient(base)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/accounts/"+accountID+"/workers/subdomain", nil)
	if err != nil {
		return "", errors.New("build Cloudflare subdomain request failed")
	}
	request.Header.Set("Authorization", "Bearer "+string(oauthToken))
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("read Cloudflare workers.dev account subdomain failed")
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", errors.New("read Cloudflare subdomain response failed")
	}
	defer zeroBytes(encoded)
	var envelope struct {
		Success bool `json:"success"`
		Result  struct {
			Subdomain string `json:"subdomain"`
		} `json:"result"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal(encoded, &envelope) != nil ||
		!envelope.Success || !dnsLabelPattern.MatchString(envelope.Result.Subdomain) {
		return "", errors.New("the selected account has no readable workers.dev subdomain; configure it in Cloudflare Dashboard before starting")
	}
	return envelope.Result.Subdomain, nil
}

func secureCloudflareAPIClient(base http.RoundTripper) *http.Client {
	if base == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		base = transport
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: exactHostTransport{base: base, host: "api.cloudflare.com"},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("Cloudflare API redirects are forbidden")
		},
	}
}

func assertNoCloudflareCredentialEnvironment() error {
	for _, name := range []string{
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY", "CLOUDFLARE_EMAIL",
		"CF_API_TOKEN", "CF_API_KEY", "CF_EMAIL",
	} {
		if os.Getenv(name) != "" {
			return fmt.Errorf("unset %s before an operator Cloudflare action; OneNod manages only named Wrangler OAuth profiles", name)
		}
	}
	return nil
}

func readRemoteInitializationState(client *http.Client, origin string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return readRemoteInitializationStateContext(ctx, client, origin)
}

func readRemoteInitializationStateContext(
	ctx context.Context,
	client *http.Client,
	origin string,
) (bool, error) {
	client = safePublicHTTPClient(client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/v1/human/state", nil)
	if err != nil {
		return false, errors.New("build bootstrap verification request failed")
	}
	response, err := client.Do(request)
	if err != nil {
		return false, errors.New("verify remote bootstrap state failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return false, errors.New("Gateway bootstrap state check returned a non-200 status")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return false, errors.New("read Gateway bootstrap state failed")
	}
	defer zeroBytes(encoded)
	var state struct {
		Initialized bool `json:"initialized"`
	}
	if json.Unmarshal(encoded, &state) != nil {
		return false, errors.New("Gateway bootstrap state is invalid")
	}
	return state.Initialized, nil
}

func waitForGatewayReadiness(
	ctx context.Context,
	client *http.Client,
	origin string,
	expectedVersion string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 || !validProductVersion(expectedVersion) {
		return errors.New("invalid public Gateway readiness wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		var health struct {
			Environment string `json:"environment"`
			OK          bool   `json:"ok"`
			Service     string `json:"service"`
			Version     string `json:"version"`
		}
		if err := readOperatorGatewayJSON(probeContext, client, origin, "/api/health", &health); err != nil {
			return false, err
		}
		if !health.OK || health.Environment != "prod" || health.Service != "onenod-gateway" {
			return false, errors.New("public Gateway health returned an unexpected service identity")
		}
		if health.Version != expectedVersion {
			return false, fmt.Errorf(
				"public Gateway reports release %s instead of %s",
				health.Version, expectedVersion,
			)
		}
		return true, nil
	})
}

func waitForRemoteRuntimeVersion(
	ctx context.Context,
	client *http.Client,
	origin string,
	expectedVersion string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 || !validProductVersion(expectedVersion) {
		return errors.New("invalid public runtime version wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		var response remoteRuntimeVersionResponse
		if err := readOperatorGatewayJSON(probeContext, client, origin, "/api/version", &response); err != nil {
			return false, err
		}
		remote, complete := parseRemoteRuntimeVersion(response)
		if !complete {
			return false, errors.New("public runtime version declaration is internally inconsistent")
		}
		if remote.GatewayVersion != expectedVersion || remote.ExecutorVersion != expectedVersion ||
			remote.PwaVersion != expectedVersion {
			return false, fmt.Errorf(
				"public runtime reports Gateway %s, Executor %s, and PWA %s instead of %s",
				remote.GatewayVersion, remote.ExecutorVersion, remote.PwaVersion, expectedVersion,
			)
		}
		return true, nil
	})
}

func waitForRemoteInitialization(
	ctx context.Context,
	client *http.Client,
	origin string,
	timeout time.Duration,
	pollInterval time.Duration,
) error {
	if timeout <= 0 || pollInterval <= 0 {
		return errors.New("invalid owner initialization wait")
	}
	return waitForOperatorCondition(ctx, timeout, pollInterval, func(probeContext context.Context) (bool, error) {
		initialized, err := readRemoteInitializationStateContext(probeContext, client, origin)
		if err != nil {
			return false, err
		}
		if !initialized {
			return false, errors.New("owner identity is not initialized yet")
		}
		return true, nil
	})
}

func waitForOperatorCondition(
	ctx context.Context,
	timeout time.Duration,
	pollInterval time.Duration,
	probe func(context.Context) (bool, error),
) error {
	waitContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for {
		probeContext, cancelProbe := context.WithTimeout(waitContext, requesterPreflightTimeout)
		ready, err := probe(probeContext)
		cancelProbe()
		if ready && err == nil {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-waitContext.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			if lastErr != nil {
				return fmt.Errorf("wait ended: %w", lastErr)
			}
			return errors.New("wait ended before the condition became ready")
		case <-timer.C:
		}
	}
}

func readOperatorGatewayJSON(
	ctx context.Context,
	client *http.Client,
	origin string,
	path string,
	result any,
) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("invalid Gateway readiness path")
	}
	client = safePublicHTTPClient(client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+path, nil)
	if err != nil {
		return errors.New("build Gateway readiness request failed")
	}
	request.Header.Set("accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Gateway readiness request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Gateway readiness returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(response.Header.Get("content-type")); mediaType != "" && !strings.HasPrefix(mediaType, "application/json") {
		return errors.New("Gateway readiness returned a non-JSON response")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(encoded) == 0 || len(encoded) > 64*1024 {
		return errors.New("read Gateway readiness response failed")
	}
	defer zeroBytes(encoded)
	if json.Unmarshal(encoded, result) != nil {
		return errors.New("Gateway readiness response is invalid")
	}
	return nil
}
