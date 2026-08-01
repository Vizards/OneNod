//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <stdlib.h>
#include <string.h>

static OSStatus onenod_open_url(const char *value, size_t length) {
    CFURLRef url = CFURLCreateWithBytes(
        kCFAllocatorDefault,
        (const UInt8 *)value,
        length,
        kCFStringEncodingUTF8,
        NULL
    );
    if (url == NULL) return paramErr;
    OSStatus status = LSOpenCFURLRef(url, NULL);
    CFRelease(url);
    return status;
}

static void onenod_zero_and_free_url(void *value, size_t length) {
    if (value != NULL) { memset(value, 0, length); free(value); }
}
*/
import "C"

import (
	"errors"
	"fmt"
)

func openSensitiveBootstrapURL(value []byte) error {
	if len(value) == 0 || len(value) > 4096 {
		return errors.New("bootstrap URL is invalid")
	}
	cValue := C.CBytes(value)
	defer C.onenod_zero_and_free_url(cValue, C.size_t(len(value)))
	status := C.onenod_open_url((*C.char)(cValue), C.size_t(len(value)))
	if status != 0 {
		return fmt.Errorf("LaunchServices returned status %d", int32(status))
	}
	return nil
}
