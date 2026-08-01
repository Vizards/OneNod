//go:build !darwin || !cgo

package main

import "errors"

func openSensitiveBootstrapURL([]byte) error {
	return errors.New("Passkey bootstrap requires macOS LaunchServices")
}
