package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const platformProbeTimeout = 5 * time.Second

type hostPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Version      string `json:"version,omitempty"`
}

func currentHostPlatform(deps dependencies) (hostPlatform, error) {
	if deps.platformProbe != nil {
		return deps.platformProbe()
	}
	return probeHostPlatform()
}

func probeHostPlatform() (hostPlatform, error) {
	platform := hostPlatform{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	if runtime.GOOS != "darwin" {
		return platform, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), platformProbeTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/usr/bin/sw_vers", "-productVersion").Output()
	if err != nil || ctx.Err() != nil {
		return platform, errors.New("unsupported_platform: cannot determine the macOS product version")
	}
	platform.Version = strings.TrimSpace(string(output))
	if _, err := parseMacOSVersion(platform.Version); err != nil {
		return platform, fmt.Errorf("unsupported_platform: %w", err)
	}
	return platform, nil
}

func requireSupportedReleaseHost(manifest releaseManifest, deps dependencies) error {
	platform, err := currentHostPlatform(deps)
	if err != nil {
		return err
	}
	return validateReleaseHostPlatform(manifest, platform)
}

func validateReleaseHostPlatform(manifest releaseManifest, platform hostPlatform) error {
	if platform.OS != "darwin" {
		return fmt.Errorf("unsupported_platform: OneNod supports macOS only; detected %s/%s", platform.OS, platform.Architecture)
	}
	supportedArchitecture := false
	for _, architecture := range manifest.Requirements.MacOS.Architectures {
		if platform.Architecture == architecture {
			supportedArchitecture = true
			break
		}
	}
	if !supportedArchitecture {
		return fmt.Errorf("unsupported_platform: architecture %s is not supported by this release", platform.Architecture)
	}
	actual, err := parseMacOSVersion(platform.Version)
	if err != nil {
		return fmt.Errorf("unsupported_platform: %w", err)
	}
	minimum, err := parseMacOSVersion(manifest.Requirements.MacOS.Minimum)
	if err != nil {
		return errors.New("unsupported_platform: verified release declares an invalid minimum macOS version")
	}
	if compareNumericVersion(actual, minimum) < 0 {
		return fmt.Errorf("unsupported_platform: macOS %s is older than required macOS %s", platform.Version, manifest.Requirements.MacOS.Minimum)
	}
	return nil
}

func parseMacOSVersion(value string) ([]int, error) {
	if value != strings.TrimSpace(value) || value == "" {
		return nil, errors.New("macOS product version is missing or malformed")
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, errors.New("macOS product version is missing or malformed")
	}
	parsed := make([]int, len(parts))
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return nil, errors.New("macOS product version is missing or malformed")
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, errors.New("macOS product version is missing or malformed")
		}
		parsed[index] = number
	}
	return parsed, nil
}

func compareNumericVersion(left, right []int) int {
	length := len(left)
	if len(right) > length {
		length = len(right)
	}
	for index := 0; index < length; index++ {
		leftValue, rightValue := 0, 0
		if index < len(left) {
			leftValue = left[index]
		}
		if index < len(right) {
			rightValue = right[index]
		}
		if leftValue < rightValue {
			return -1
		}
		if leftValue > rightValue {
			return 1
		}
	}
	return 0
}
