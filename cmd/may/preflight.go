package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const requesterPreflightTimeout = 15 * time.Second

type requesterPreflightReport struct {
	Assurance string `json:"assurance"`
	Channel   string `json:"channel"`
	Executor  struct {
		Declared bool   `json:"declared"`
		Runtime  string `json:"runtime"`
		Version  string `json:"version"`
	} `json:"executor"`
	Gateway struct {
		Environment string `json:"environment"`
		Version     string `json:"version"`
	} `json:"gateway"`
	GatewayCrypto string `json:"gateway_crypto"`
	HumanIdentity string `json:"human_identity"`
	LocalFallback struct {
		AgentConfig string `json:"agent_config"`
		Configured  bool   `json:"configured"`
		DesktopApp  string `json:"desktop_app"`
		SSHAgent    string `json:"ssh_agent"`
	} `json:"local_fallback"`
	Origin    string `json:"origin"`
	Requester struct {
		DeviceID             string `json:"device_id,omitempty"`
		DisplayName          string `json:"display_name,omitempty"`
		LocalCredential      string `json:"local_credential"`
		PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`
	} `json:"requester"`
}

func runPreflight(args []string, config cliConfig, deps dependencies) error {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(deps.stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: may [global flags] preflight")
	}
	parsedOrigin, err := parseGatewayOrigin(config.origin)
	if err != nil {
		return err
	}
	origin := parsedOrigin.String()

	client := safePublicHTTPClient(deps.httpClient)
	var gateway struct {
		Environment string `json:"environment"`
		OK          bool   `json:"ok"`
		Service     string `json:"service"`
		Version     string `json:"version"`
	}
	if err := readPublicGatewayJSON(client, origin, "/api/health", &gateway); err != nil {
		return fmt.Errorf("Gateway health preflight failed: %w", err)
	}
	if !gateway.OK || gateway.Environment != "prod" ||
		gateway.Service != "onenod-gateway" ||
		!validHealthVersion(gateway.Version) {
		return errors.New("Gateway health preflight returned an unexpected production identity")
	}

	var version struct {
		OK             bool   `json:"ok"`
		ReleaseChannel string `json:"release_channel"`
		ReleaseVersion string `json:"release_version"`
		Service        string `json:"service"`
		SourceCommit   string `json:"source_commit"`
		Components     struct {
			Executor struct {
				Declared bool   `json:"declared"`
				Channel  string `json:"channel"`
				Version  string `json:"version"`
			} `json:"executor"`
			Gateway struct {
				AcceptedClientProtocol protocolRange `json:"accepted_client_protocol"`
				Channel                string        `json:"channel"`
				Version                string        `json:"version"`
			} `json:"gateway"`
			PWA struct {
				Channel string `json:"channel"`
				Version string `json:"version"`
			} `json:"pwa"`
		} `json:"components"`
	}
	if err := readPublicGatewayJSON(client, origin, "/api/version", &version); err != nil {
		return fmt.Errorf("Gateway static version preflight failed: %w", err)
	}
	expectedChannel := releaseChannelForVersion(version.ReleaseVersion)
	if !version.OK || version.Service != "onenod-gateway" ||
		!validProductVersion(version.ReleaseVersion) || !commitPattern.MatchString(version.SourceCommit) ||
		!validReleaseChannel(expectedChannel) || releaseChannel(version.ReleaseChannel) != expectedChannel ||
		releaseChannel(version.Components.Gateway.Channel) != expectedChannel ||
		releaseChannel(version.Components.Executor.Channel) != expectedChannel ||
		releaseChannel(version.Components.PWA.Channel) != expectedChannel ||
		version.Components.Gateway.Version != version.ReleaseVersion ||
		version.Components.Executor.Version != version.ReleaseVersion ||
		version.Components.PWA.Version != version.ReleaseVersion ||
		!version.Components.Executor.Declared ||
		!protocolContains(version.Components.Gateway.AcceptedClientProtocol, mayClientProtocol) {
		return errors.New("Gateway static version preflight returned an incompatible release declaration")
	}

	report := requesterPreflightReport{
		Assurance:     "anonymous_runtime_self_report; deep readiness is proven by enrollment or an approved operation",
		Channel:       version.ReleaseChannel,
		GatewayCrypto: "not_checked_anonymously",
		HumanIdentity: "not_checked_anonymously",
		Origin:        origin,
	}
	report.Gateway.Environment = gateway.Environment
	report.Gateway.Version = gateway.Version
	report.Executor.Declared = version.Components.Executor.Declared
	report.Executor.Runtime = "declared_cloudflare_worker"
	report.Executor.Version = version.Components.Executor.Version
	report.LocalFallback.DesktopApp = localDesktopAppStatus()
	report.LocalFallback.AgentConfig = "not detected"
	if configPath, configPathErr := onePasswordSSHAgentConfigPath(); configPathErr == nil {
		if _, found, readErr := readOptionalRegularFile(configPath, 1<<20); readErr == nil && found {
			report.LocalFallback.AgentConfig = "present"
		}
	}
	report.LocalFallback.SSHAgent = "not detected"
	if socketPath, socketErr := onePasswordSSHAgentSocketPath(); socketErr == nil {
		if _, statErr := os.Lstat(socketPath); statErr == nil {
			report.LocalFallback.SSHAgent = "present"
		}
	}
	_, report.LocalFallback.Configured, err = readLocalFallbackConfig()
	if err != nil {
		return err
	}
	report.Requester.LocalCredential = "absent"
	if deps.keychain.selected {
		credential, found, err := deps.keychain.LoadIfPresent()
		if err != nil {
			return err
		}
		if found {
			fingerprint, err := publicKeyFingerprint(credential)
			if err != nil {
				return errors.New("requester credential preflight failed")
			}
			report.Requester.LocalCredential = "present"
			report.Requester.DeviceID = credential.DeviceID
			report.Requester.DisplayName = credential.DisplayName
			report.Requester.PublicKeyFingerprint = fingerprint
		}
	}
	return writeIndentedValue(deps.stdout, report)
}

func safePublicHTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = &http.Client{Timeout: requesterPreflightTimeout}
	}
	safe := *client
	if safe.Timeout == 0 || safe.Timeout > requesterPreflightTimeout {
		safe.Timeout = requesterPreflightTimeout
	}
	safe.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("Gateway redirects are not allowed")
	}
	return &safe
}

func readPublicGatewayJSON(
	client *http.Client,
	origin string,
	path string,
	result any,
) error {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "?#\r\n") {
		return errors.New("invalid preflight path")
	}
	requestContext, cancel := context.WithTimeout(context.Background(), requesterPreflightTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodGet,
		origin+path,
		nil,
	)
	if err != nil {
		return errors.New("build preflight request failed")
	}
	request.Header.Set("accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("Gateway preflight request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Gateway returned HTTP %d", response.StatusCode)
	}
	if mediaType := strings.ToLower(response.Header.Get("content-type")); !strings.HasPrefix(mediaType, "application/json") {
		return errors.New("Gateway preflight returned a non-JSON response")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(encoded) > 64*1024 {
		return errors.New("read Gateway preflight response failed")
	}
	if err := json.Unmarshal(encoded, result); err != nil {
		return errors.New("Gateway preflight returned invalid JSON")
	}
	return nil
}

func validHealthVersion(version string) bool {
	return version != "" && len(version) <= 64 &&
		!strings.ContainsAny(version, "\x00\r\n\t ")
}
