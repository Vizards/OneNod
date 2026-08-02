package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	keychainHelperBinaryName = "onenod-keychain-helper"
	keychainHelperProtocol   = 1
	maxHelperResponseBytes   = 64 * 1024
	keychainHelperTimeout    = 15 * time.Second
)

type keychainHelperRequest struct {
	DisplayName string `json:"display_name,omitempty"`
	Message     string `json:"message,omitempty"`
	Operation   string `json:"operation"`
	Origin      string `json:"origin,omitempty"`
	Slot        string `json:"slot,omitempty"`
}

type keychainHelperResponse struct {
	Error    string `json:"error,omitempty"`
	Found    *bool  `json:"found,omitempty"`
	Identity *struct {
		DeviceID    string `json:"device_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
		Version     int    `json:"version"`
	} `json:"identity,omitempty"`
	OK        bool   `json:"ok"`
	Protocol  int    `json:"protocol,omitempty"`
	Signature string `json:"signature,omitempty"`
	Source    string `json:"source_commit,omitempty"`
	Version   string `json:"version,omitempty"`
}

func installedKeychainHelperPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("resolve user home for Keychain helper failed")
	}
	return filepath.Join(home, userAgentDirectoryName, "libexec", keychainHelperBinaryName), nil
}

func callKeychainHelper(request keychainHelperRequest) (keychainHelperResponse, error) {
	path, err := installedKeychainHelperPath()
	if err != nil {
		return keychainHelperResponse{}, err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o100 == 0 || info.Mode().Perm()&0o022 != 0 {
		return keychainHelperResponse{}, errors.New("Keychain helper path must be an owner-executable, non-writable regular file, not a symlink")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return keychainHelperResponse{}, errors.New("Keychain helper must be owned by the current macOS user")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return keychainHelperResponse{}, errors.New("encode Keychain helper request failed")
	}
	defer zeroBytes(encoded)
	ctx, cancel := context.WithTimeout(context.Background(), keychainHelperTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, path)
	// The helper needs no ambient configuration. An empty environment keeps its
	// stable executable identity from being weakened by loader, language-runtime,
	// credential, proxy, or tool-specific variables inherited from the caller.
	command.Env = []string{}
	command.Stdin = bytes.NewReader(encoded)
	command.Stderr = io.Discard
	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		return keychainHelperResponse{}, errors.New("create private Keychain helper response pipe failed")
	}
	if err := command.Start(); err != nil {
		return keychainHelperResponse{}, errors.New("Keychain helper failed to start")
	}
	responseBytes, readErr := io.ReadAll(io.LimitReader(stdoutPipe, maxHelperResponseBytes+1))
	waitErr := command.Wait()
	if ctx.Err() != nil {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper timed out")
	}
	if readErr != nil || waitErr != nil {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper failed")
	}
	if len(responseBytes) == 0 || len(responseBytes) > maxHelperResponseBytes {
		zeroBytes(responseBytes)
		return keychainHelperResponse{}, errors.New("Keychain helper returned an invalid response size")
	}
	defer zeroBytes(responseBytes)
	decoder := json.NewDecoder(bytes.NewReader(responseBytes))
	decoder.DisallowUnknownFields()
	var response keychainHelperResponse
	if err := decoder.Decode(&response); err != nil {
		return keychainHelperResponse{}, errors.New("Keychain helper returned invalid JSON")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return keychainHelperResponse{}, errors.New("Keychain helper returned trailing data")
	}
	if !response.OK {
		if response.Error == "" {
			return keychainHelperResponse{}, errors.New("Keychain helper rejected the operation")
		}
		return keychainHelperResponse{}, fmt.Errorf("Keychain helper: %s", response.Error)
	}
	return response, nil
}

func helperResponseCredential(
	response keychainHelperResponse,
) (*requesterCredential, error) {
	if response.Identity == nil {
		return nil, errors.New("Keychain helper omitted public identity metadata")
	}
	return &requesterCredential{
		DeviceID: response.Identity.DeviceID, DisplayName: response.Identity.DisplayName,
		PublicKey: response.Identity.PublicKey, Version: response.Identity.Version,
	}, nil
}

func ensureRequesterWithHelper(origin, slot, displayName string) (*requesterCredential, bool, error) {
	existing, found, err := loadRequesterFromHelper(origin, slot)
	if err != nil {
		return nil, false, err
	}
	if found {
		if existing.DisplayName != displayName {
			return nil, false, fmt.Errorf(
				"Keychain already contains requester %q; refusing to overwrite it",
				existing.DisplayName,
			)
		}
		return existing, false, nil
	}
	response, err := callKeychainHelper(keychainHelperRequest{
		Operation: "ensure", Origin: origin, Slot: slot, DisplayName: displayName,
	})
	if err != nil {
		return nil, false, err
	}
	credential, err := helperResponseCredential(response)
	return credential, true, err
}

func loadRequesterFromHelper(origin, slot string) (*requesterCredential, bool, error) {
	response, err := callKeychainHelper(keychainHelperRequest{
		Operation: "public", Origin: origin, Slot: slot,
	})
	if err != nil {
		return nil, false, err
	}
	if response.Found == nil || !*response.Found {
		return nil, false, nil
	}
	credential, err := helperResponseCredential(response)
	return credential, true, err
}

func signRequesterWithHelper(origin, slot string, message []byte) ([]byte, error) {
	response, err := callKeychainHelper(keychainHelperRequest{
		Operation: "sign", Origin: origin, Slot: slot,
		Message: base64.RawURLEncoding.EncodeToString(message),
	})
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(response.Signature)
	if err != nil || len(signature) != 64 {
		return nil, errors.New("Keychain helper returned an invalid signature")
	}
	return signature, nil
}

func inspectInstalledKeychainHelper() (keychainHelperResponse, error) {
	response, err := callKeychainHelper(keychainHelperRequest{Operation: "hello"})
	if err != nil {
		return keychainHelperResponse{}, err
	}
	if response.Protocol != keychainHelperProtocol || response.Version == "" {
		return keychainHelperResponse{}, errors.New("installed Keychain helper protocol is unsupported")
	}
	return response, nil
}
