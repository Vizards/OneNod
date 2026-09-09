package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const maximumTrustedExecutableSize = 256 * 1024 * 1024

type trustedExecutableIdentity struct {
	path             string
	digest           [sha256.Size]byte
	fileInfo         os.FileInfo
	requireRootOwner bool
}

func captureTrustedExecutable(
	path, expectedSHA256 string,
	requireRootOwner bool,
) (trustedExecutableIdentity, error) {
	if !filepath.IsAbs(path) || len(expectedSHA256) != sha256.Size*2 {
		return trustedExecutableIdentity{}, errors.New("invalid trusted executable identity")
	}
	expected, err := hex.DecodeString(expectedSHA256)
	if err != nil {
		return trustedExecutableIdentity{}, errors.New("invalid trusted executable digest")
	}
	file, info, digest, err := inspectTrustedExecutable(path, requireRootOwner)
	if file != nil {
		_ = file.Close()
	}
	if err != nil || !hmac.Equal(digest[:], expected) {
		return trustedExecutableIdentity{}, errors.New("trusted executable digest mismatch")
	}
	return trustedExecutableIdentity{
		path: filepath.Clean(path), digest: digest, fileInfo: info,
		requireRootOwner: requireRootOwner,
	}, nil
}

func (identity trustedExecutableIdentity) matches(observedPath string) bool {
	if identity.path == "" || !filepath.IsAbs(observedPath) || identity.fileInfo == nil {
		return false
	}
	file, info, digest, err := inspectTrustedExecutable(observedPath, identity.requireRootOwner)
	if file != nil {
		_ = file.Close()
	}
	return err == nil && os.SameFile(identity.fileInfo, info) &&
		hmac.Equal(identity.digest[:], digest[:])
}

func inspectTrustedExecutable(
	path string,
	requireRootOwner bool,
) (*os.File, os.FileInfo, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 ||
		pathInfo.Size() <= 0 || pathInfo.Size() > maximumTrustedExecutableSize {
		return nil, nil, zero, errors.New("trusted executable is not a regular file")
	}
	stat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathInfo.Mode().Perm()&0o022 != 0 || (requireRootOwner && stat.Uid != 0) {
		return nil, nil, zero, errors.New("trusted executable ownership is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, zero, err
	}
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		_ = file.Close()
		return nil, nil, zero, errors.New("trusted executable changed while opening")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumTrustedExecutableSize+1)); err != nil {
		_ = file.Close()
		return nil, nil, zero, err
	}
	copy(zero[:], hash.Sum(nil))
	return file, openedInfo, zero, nil
}
