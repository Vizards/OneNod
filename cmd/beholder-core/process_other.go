//go:build !darwin

package main

import "errors"

func inspectProcess(pid int) (processIdentity, error) {
	return processIdentity{}, errors.New("process inspection unsupported")
}
