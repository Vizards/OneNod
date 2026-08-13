//go:build !darwin

package main

import "os"

func sameTransportFileSnapshot(first, second os.FileInfo) bool {
	return first.Mode().IsRegular() && second.Mode().IsRegular() &&
		os.SameFile(first, second) && first.Size() == second.Size() &&
		first.Mode() == second.Mode() && first.ModTime() == second.ModTime()
}
