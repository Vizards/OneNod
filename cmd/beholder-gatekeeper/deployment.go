package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Machine routing and credential references remain in the exact confirmed JSON.
// Production serve also requires its compiled digest before requesting any key.
func validDeploymentMetadata(config confirmedConfig) bool {
	healthyOrigin := func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
			u.RawQuery == "" && u.Fragment == "" && u.Path == ""
	}
	return config.Provider.Route != "" && healthyOrigin(config.Provider.CallerOrigin) &&
		config.Provider.BaseURL == config.Provider.CallerOrigin+"/v1" &&
		healthyOrigin(config.Provider.UpstreamOrigin) &&
		strings.HasPrefix(config.Authentication.OneNodReference, "op://Agent/") &&
		filepath.IsAbs(config.Observability.EvidenceRoot)
}

func defaultUserPath(parts ...string) string {
	homeDirectory, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(homeDirectory) {
		return ""
	}
	return filepath.Join(append([]string{homeDirectory}, parts...)...)
}
