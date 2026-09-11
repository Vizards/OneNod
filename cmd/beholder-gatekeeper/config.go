package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const maximumCredentialSize = 16 * 1024

func loadProductionConfig(path, expectedSHA256 string) (confirmedConfig, string, error) {
	if expectedSHA256 != confirmedConfigSHA256 {
		return confirmedConfig{}, "", errors.New("configuration is not the confirmed deployment")
	}
	config, digest, err := loadConfirmedConfig(path, expectedSHA256)
	if err != nil {
		return config, digest, err
	}
	if config.Revision.ID != "E2-AI0-R16" || !config.Retrieval.Enabled {
		return confirmedConfig{}, "", errors.New("production requires the retrieval deployment revision")
	}
	return config, digest, nil
}

func loadConfirmedConfig(path, expectedSHA256 string) (confirmedConfig, string, error) {
	var config confirmedConfig
	if !filepath.IsAbs(path) || len(expectedSHA256) != sha256.Size*2 {
		return config, "", errors.New("invalid confirmed config identity")
	}
	contents, err := os.ReadFile(path)
	if err != nil || len(contents) == 0 || len(contents) > 1024*1024 {
		clear(contents)
		return config, "", errors.New("read confirmed config failed")
	}
	digest := sha256.Sum256(contents)
	actual := hex.EncodeToString(digest[:])
	if actual != strings.ToLower(expectedSHA256) || json.Unmarshal(contents, &config) != nil {
		clear(contents)
		return confirmedConfig{}, "", errors.New("confirmed config identity mismatch")
	}
	clear(contents)
	if err := validateConfirmedConfig(config); err != nil {
		return confirmedConfig{}, "", err
	}
	return config, actual, nil
}

func currentExecutableSHA256() (string, error) {
	path, err := os.Executable()
	if err != nil || !filepath.IsAbs(path) {
		return "", errors.New("executable path unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, 256*1024*1024+1)); err != nil {
		return "", err
	}
	if info, err := file.Stat(); err != nil || info.Size() <= 0 || info.Size() > 256*1024*1024 {
		return "", errors.New("executable identity invalid")
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func readCredentialWithMay(mayPath, reference string, stderr io.Writer) ([]byte, error) {
	if !filepath.IsAbs(mayPath) || !strings.HasPrefix(reference, "op://Agent/") || stderr == nil {
		return nil, errors.New("invalid credential requester configuration")
	}
	var output limitedBuffer
	output.maximum = maximumCredentialSize
	command := exec.Command(mayPath, "read", "--no-newline", reference)
	command.Stdout = &output
	command.Stderr = stderr
	command.Stdin = nil
	if err := command.Run(); err != nil || output.overflow || output.buffer.Len() < 16 {
		output.clear()
		return nil, errors.New("Gatekeeper credential request failed")
	}
	credential := append([]byte(nil), output.buffer.Bytes()...)
	output.clear()
	if bytes.IndexAny(credential, "\r\n\x00") >= 0 || len(credential) > maximumCredentialSize {
		clear(credential)
		return nil, errors.New("Gatekeeper credential shape invalid")
	}
	return credential, nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (buffer *limitedBuffer) Write(value []byte) (int, error) {
	if buffer.overflow {
		return len(value), nil
	}
	if buffer.buffer.Len()+len(value) > buffer.maximum {
		buffer.overflow = true
		return len(value), nil
	}
	return buffer.buffer.Write(value)
}

func (buffer *limitedBuffer) clear() {
	contents := buffer.buffer.Bytes()
	clear(contents)
	buffer.buffer.Reset()
	buffer.overflow = false
}
