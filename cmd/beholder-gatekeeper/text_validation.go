package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"unicode/utf8"
)

var reasonCodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func safeUTF8Text(value []byte, maximum int) (string, bool) {
	if maximum <= 0 || !utf8.Valid(value) || bytes.IndexByte(value, 0) >= 0 {
		return "", false
	}
	if len(value) <= maximum {
		return string(value), true
	}
	digest := sha256.Sum256(value)
	marker := fmt.Sprintf("\n[context excerpt: original_bytes=%d sha256=%x; middle omitted]\n", len(value), digest)
	if maximum <= len(marker)+8 {
		return "", false
	}
	headSize := (maximum - len(marker)) / 2
	tailSize := maximum - len(marker) - headSize
	head, tail := value[:headSize], value[len(value)-tailSize:]
	for !utf8.Valid(head) {
		head = head[:len(head)-1]
	}
	for !utf8.Valid(tail) {
		tail = tail[1:]
	}
	return string(head) + marker + string(tail), true
}

func safeReasonCode(value string) bool {
	return reasonCodePattern.MatchString(value)
}
