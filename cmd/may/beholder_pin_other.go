//go:build !darwin

package main

func beholderCorePinWarning(*localInstallReceipt) string { return "" }
