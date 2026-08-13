//go:build !darwin

package main

import "os"

// The helper is usable only with the macOS Keychain. Retain the pipe shape
// check on unsupported build hosts so protocol state-machine tests can run.
func isAnonymousCapabilityPipe(_ *os.File, info os.FileInfo) bool {
	return info.Mode()&os.ModeNamedPipe != 0
}
