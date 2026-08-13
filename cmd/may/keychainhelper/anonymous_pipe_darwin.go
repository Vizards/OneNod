//go:build darwin

package main

import (
	"os"
	"syscall"
)

func isAnonymousCapabilityPipe(_ *os.File, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode()&os.ModeNamedPipe != 0 && stat.Nlink == 0
}
