//go:build !darwin

package beholdercontext

import "errors"

func inspectHookProcess(pid int) (hookProcessIdentity, error) {
	return hookProcessIdentity{}, errors.New("process inspection unsupported")
}
