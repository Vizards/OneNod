package main

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// SSH/Git adapters keep transport metadata out of command output. An unsafe or
// unavailable log path disables observation only, never the requested operation.
func openClientTransportLog() (*os.File, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("transport log unavailable")
	}
	root, err := unix.Open(filepath.Join(home, userAgentDirectoryName), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("transport log unavailable")
	}
	defer unix.Close(root)
	private := func(fd int, directory bool) bool {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Getuid()) || stat.Mode&0o077 != 0 {
			return false
		}
		if directory {
			return stat.Mode&unix.S_IFMT == unix.S_IFDIR
		}
		return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1
	}
	if !private(root, true) {
		return nil, errors.New("transport log unavailable")
	}
	if err := unix.Mkdirat(root, "logs", 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, errors.New("transport log unavailable")
	}
	directory, err := unix.Openat(root, "logs", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("transport log unavailable")
	}
	defer unix.Close(directory)
	if !private(directory, true) {
		return nil, errors.New("transport log unavailable")
	}
	fd, err := unix.Openat(directory, "beholder-handshake.jsonl", unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, errors.New("transport log unavailable")
	}
	if !private(fd, false) {
		unix.Close(fd)
		return nil, errors.New("transport log unavailable")
	}
	return os.NewFile(uintptr(fd), "beholder-handshake-log"), nil
}
