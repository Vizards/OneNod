//go:build darwin

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

const (
	systemCurlPath           = "/usr/bin/curl"
	maximumCurlMetadataBytes = 256 * 1024
)

type systemCurlTransportError struct {
	Stage    string
	ExitCode int
	Detail   string
}

func (failure *systemCurlTransportError) Error() string {
	if failure == nil {
		return "system curl transport failed"
	}
	message := "system curl transport failed at " + failure.Stage
	if failure.ExitCode >= 0 {
		message += fmt.Sprintf(" (exit %d)", failure.ExitCode)
	}
	if failure.Detail != "" {
		message += ": " + failure.Detail
	}
	return message
}

func useSystemCurlProviderTransport(endpoint string) bool {
	return providercontract.UsesSystemCurl(endpoint)
}

// systemCurlProviderRoundTrip uses Apple's platform-signed curl as the sole
// HTTPS transport for the private-LAN provider origin. macOS NECP denies
// anonymous LaunchAgent binaries before SYN while allowing the platform
// network client. The API key enters curl through an anonymous descriptor; it
// is never placed in argv, the environment, or a filesystem object.
func systemCurlProviderRoundTrip(
	ctx context.Context,
	request *http.Request,
	contentType string,
	apiKey []byte,
	body []byte,
) (*http.Response, error) {
	if ctx == nil || request == nil || request.URL == nil || !providercontract.UsesSystemCurl(request.URL.String()) ||
		contentType != "application/json" || len(apiKey) < 16 || len(apiKey) > maximumCredentialSize ||
		bytes.IndexAny(apiKey, "\r\n\x00") >= 0 || len(body) == 0 || len(body) > maximumLocalWireSize {
		return nil, &systemCurlTransportError{Stage: "validation", ExitCode: -1}
	}
	info, err := os.Lstat(systemCurlPath)
	stat, statOK := infoSyscallStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, &systemCurlTransportError{Stage: "curl-identity", ExitCode: -1}
	}
	if !statOK || stat.Uid != 0 {
		return nil, &systemCurlTransportError{Stage: "curl-owner", ExitCode: -1}
	}
	headerReader, headerWriter, err := os.Pipe()
	if err != nil {
		return nil, &systemCurlTransportError{Stage: "header-pipe", ExitCode: -1}
	}
	defer headerReader.Close()
	defer headerWriter.Close()
	markerBytes := make([]byte, 24)
	if _, err := rand.Read(markerBytes); err != nil {
		clear(markerBytes)
		return nil, &systemCurlTransportError{Stage: "response-marker", ExitCode: -1}
	}
	marker := "__BEHOLDER_CURL_" + hex.EncodeToString(markerBytes) + "__"
	clear(markerBytes)

	stdout := &limitedBuffer{maximum: maximumModelResponseSize + maximumCurlMetadataBytes}
	stderr := &limitedBuffer{maximum: 64 * 1024}
	command := exec.CommandContext(ctx, systemCurlPath,
		"--disable",
		"--silent",
		"--show-error",
		"--no-progress-meter",
		"--proto", "=https",
		"--connect-timeout", "10",
		"--max-time", "600",
		"--request", http.MethodPost,
		"--header", "Content-Type: "+contentType,
		"--header", "@/dev/fd/3",
		"--data-binary", "@-",
		"--write-out", marker+"%{http_code}\n%{header_json}",
		request.URL.String(),
	)
	command.Stdin = bytes.NewReader(body)
	command.Stdout = stdout
	command.Stderr = stderr
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
	command.ExtraFiles = []*os.File{headerReader}
	if err := command.Start(); err != nil {
		stdout.clear()
		stderr.clear()
		return nil, &systemCurlTransportError{Stage: "start", ExitCode: -1}
	}
	_ = headerReader.Close()
	header := append([]byte("Authorization: Bearer "), apiKey...)
	header = append(header, '\n')
	_, headerErr := headerWriter.Write(header)
	clear(header)
	closeErr := headerWriter.Close()
	waitErr := command.Wait()
	if headerErr != nil || closeErr != nil {
		stdout.clear()
		detail := safeCurlDiagnostic(stderr.buffer.Bytes(), apiKey)
		stderr.clear()
		return nil, &systemCurlTransportError{Stage: "header-write", ExitCode: processExitCode(command), Detail: detail}
	}
	if waitErr != nil || stdout.overflow || stderr.overflow {
		detail := safeCurlDiagnostic(stderr.buffer.Bytes(), apiKey)
		stdoutOverflow := stdout.overflow
		stderrOverflow := stderr.overflow
		stdout.clear()
		stderr.clear()
		stage := "execute"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			stage = "deadline"
		} else if stdoutOverflow {
			stage = "response-limit"
		} else if stderrOverflow {
			stage = "diagnostic-limit"
		}
		return nil, &systemCurlTransportError{Stage: stage, ExitCode: processExitCode(command), Detail: detail}
	}
	stderr.clear()
	output := stdout.buffer.Bytes()
	markerIndex := bytes.LastIndex(output, []byte(marker))
	if markerIndex < 0 {
		stdout.clear()
		return nil, &systemCurlTransportError{Stage: "response-metadata", ExitCode: processExitCode(command)}
	}
	metadata := output[markerIndex+len(marker):]
	newline := bytes.IndexByte(metadata, '\n')
	if newline <= 0 {
		stdout.clear()
		return nil, &systemCurlTransportError{Stage: "response-status", ExitCode: processExitCode(command)}
	}
	status, err := strconv.Atoi(string(metadata[:newline]))
	if err != nil || status < 100 || status > 599 {
		stdout.clear()
		return nil, &systemCurlTransportError{Stage: "response-status", ExitCode: processExitCode(command)}
	}
	var curlHeaders map[string][]string
	if json.Unmarshal(metadata[newline+1:], &curlHeaders) != nil {
		stdout.clear()
		return nil, &systemCurlTransportError{Stage: "response-headers", ExitCode: processExitCode(command)}
	}
	responseBody := append([]byte(nil), output[:markerIndex]...)
	stdout.clear()
	headers := make(http.Header, len(curlHeaders))
	for name, values := range curlHeaders {
		for _, value := range values {
			headers.Add(name, value)
		}
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     headers,
		Body:       io.NopCloser(bytes.NewReader(responseBody)),
		Request:    request,
	}, nil
}

func infoSyscallStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func processExitCode(command *exec.Cmd) int {
	if command == nil || command.ProcessState == nil {
		return -1
	}
	return command.ProcessState.ExitCode()
}

func safeCurlDiagnostic(value, apiKey []byte) string {
	if len(value) == 0 {
		return ""
	}
	copyValue := append([]byte(nil), value...)
	if len(apiKey) > 0 {
		copyValue = bytes.ReplaceAll(copyValue, apiKey, []byte("[REDACTED]"))
	}

	text := strings.TrimSpace(string(copyValue))
	clear(copyValue)
	if len(text) > 2048 {
		text = text[:2048]
	}
	return text
}
