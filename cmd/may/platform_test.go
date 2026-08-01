package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestReleaseHostPlatformEnforcesMacOS15(t *testing.T) {
	manifest := validManifestFixture("0.0.1", nil)
	tests := []struct {
		name    string
		version string
		wantErr bool
	}{
		{name: "older release", version: "14.7", wantErr: true},
		{name: "minimum release", version: "15.0"},
		{name: "newer patch", version: "15.6.1"},
		{name: "newer major", version: "16.0"},
		{name: "missing minor", version: "15", wantErr: true},
		{name: "suffix", version: "15.0-beta", wantErr: true},
		{name: "empty component", version: "15..1", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateReleaseHostPlatform(manifest, hostPlatform{
				OS: "darwin", Architecture: "arm64", Version: test.version,
			})
			if (err != nil) != test.wantErr {
				t.Fatalf("validate version %q: error=%v wantErr=%v", test.version, err, test.wantErr)
			}
		})
	}
}

func TestReleaseHostPlatformRejectsWrongOSAndArchitecture(t *testing.T) {
	manifest := validManifestFixture("0.0.1", nil)
	for _, platform := range []hostPlatform{
		{OS: "linux", Architecture: "arm64"},
		{OS: "darwin", Architecture: "386", Version: "15.0"},
	} {
		if err := validateReleaseHostPlatform(manifest, platform); err == nil ||
			!strings.Contains(err.Error(), "unsupported_platform") {
			t.Fatalf("unsupported platform %+v was accepted: %v", platform, err)
		}
	}
}

func TestUpdateCheckReportsUnsupportedPlatformWithoutMutation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	manifest := validManifestFixture("0.0.1", []releaseArtifact{{
		Name: "onenod-darwin-arm64.tar.gz", Kind: "may", Size: 1,
		SHA256: "sha256:" + strings.Repeat("a", 64),
	}})
	source := &memoryReleaseSource{}
	source.release = &verifiedRelease{Manifest: manifest, Source: source}
	var output strings.Builder
	err := runUpdateCheck([]string{"--json"}, dependencies{
		releases: source, stderr: io.Discard, stdout: &output,
		platformProbe: func() (hostPlatform, error) {
			return hostPlatform{OS: "darwin", Architecture: "arm64", Version: "14.7"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var report updateCheckReport
	if err := json.Unmarshal([]byte(output.String()), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "unsupported_platform" || len(report.Plan) != 1 || len(report.Warnings) != 1 {
		t.Fatalf("unexpected unsupported-platform report: %+v", report)
	}
}
