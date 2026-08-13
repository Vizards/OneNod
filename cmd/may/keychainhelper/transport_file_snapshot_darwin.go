//go:build darwin

package main

import (
	"os"
	"syscall"
)

func sameTransportFileSnapshot(first, second os.FileInfo) bool {
	firstStat, firstOK := first.Sys().(*syscall.Stat_t)
	secondStat, secondOK := second.Sys().(*syscall.Stat_t)
	return firstOK && secondOK && first.Mode().IsRegular() && second.Mode().IsRegular() &&
		firstStat.Dev == secondStat.Dev && firstStat.Ino == secondStat.Ino &&
		firstStat.Nlink == secondStat.Nlink && firstStat.Uid == secondStat.Uid &&
		firstStat.Gid == secondStat.Gid && firstStat.Mode == secondStat.Mode &&
		firstStat.Size == secondStat.Size &&
		firstStat.Mtimespec == secondStat.Mtimespec &&
		firstStat.Ctimespec == secondStat.Ctimespec
}
