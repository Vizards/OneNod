//go:build !darwin

package main

import (
	"context"
	"errors"
	"net/http"
)

func useSystemCurlProviderTransport(string) bool { return false }

func systemCurlProviderRoundTrip(
	context.Context,
	*http.Request,
	string,
	[]byte,
	[]byte,
) (*http.Response, error) {
	return nil, errors.New("system curl provider transport is unavailable")
}
