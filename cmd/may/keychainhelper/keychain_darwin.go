//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static CFStringRef helper_cfstring(const char *value, size_t length) {
    return CFStringCreateWithBytes(kCFAllocatorDefault, (const UInt8 *)value,
        length, kCFStringEncodingUTF8, false);
}

static OSStatus helper_keychain_create(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, const void *data, UInt32 dataLength) {
    CFStringRef a = helper_cfstring(account, accountLength);
    CFStringRef s = helper_cfstring(service, serviceLength);
    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, dataLength);
    if (a == NULL || s == NULL || d == NULL) {
        if (a != NULL) CFRelease(a); if (s != NULL) CFRelease(s); if (d != NULL) CFRelease(d);
        return errSecAllocate;
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) {
        CFRelease(a); CFRelease(s); CFRelease(d); return errSecAllocate;
    }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccount, a);
    CFDictionarySetValue(q, kSecAttrService, s);
    CFDictionarySetValue(q, kSecValueData, d);
    OSStatus status = SecItemAdd(q, NULL);
    CFRelease(q); CFRelease(a); CFRelease(s); CFRelease(d);
    return status;
}

static OSStatus helper_keychain_load(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, UInt32 *dataLength, void **data) {
    CFStringRef a = helper_cfstring(account, accountLength);
    CFStringRef s = helper_cfstring(service, serviceLength);
    if (a == NULL || s == NULL) {
        if (a != NULL) CFRelease(a); if (s != NULL) CFRelease(s); return errSecAllocate;
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) { CFRelease(a); CFRelease(s); return errSecAllocate; }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccount, a);
    CFDictionarySetValue(q, kSecAttrService, s);
    CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(q, &result);
    CFRelease(q); CFRelease(a); CFRelease(s);
    if (status != errSecSuccess) { if (result != NULL) CFRelease(result); return status; }
    if (result == NULL || CFGetTypeID(result) != CFDataGetTypeID()) {
        if (result != NULL) CFRelease(result); return errSecDecode;
    }
    CFDataRef value = (CFDataRef)result;
    CFIndex length = CFDataGetLength(value);
    if (length < 0 || (uint64_t)length > UINT32_MAX) { CFRelease(result); return errSecDecode; }
    void *copy = malloc((size_t)length);
    if (length > 0 && copy == NULL) { CFRelease(result); return errSecAllocate; }
    if (length > 0) memcpy(copy, CFDataGetBytePtr(value), (size_t)length);
    CFRelease(result); *dataLength = (UInt32)length; *data = copy; return errSecSuccess;
}

static void helper_zero_and_free(void *data, size_t length) {
    if (data != NULL) { memset(data, 0, length); free(data); }
}
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

const maxKeychainBytes = 1 << 20

type systemCredentialStore struct{}

func (systemCredentialStore) Create(account, service string, data []byte) error {
	if account == "" || service == "" || len(data) == 0 || len(data) > maxKeychainBytes {
		return errors.New("invalid Keychain item")
	}
	cAccount, cService, cData := C.CString(account), C.CString(service), C.CBytes(data)
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cService))
	defer C.helper_zero_and_free(cData, C.size_t(len(data)))
	status := C.helper_keychain_create(cAccount, C.UInt32(len(account)), cService,
		C.UInt32(len(service)), cData, C.UInt32(len(data)))
	if status == C.errSecDuplicateItem {
		return errIdentityExists
	}
	if status != C.errSecSuccess {
		return fmt.Errorf("Keychain write failed with status %d", int32(status))
	}
	return nil
}

func (systemCredentialStore) Load(account, service string) ([]byte, bool, error) {
	if account == "" || service == "" {
		return nil, false, errors.New("invalid Keychain item")
	}
	cAccount, cService := C.CString(account), C.CString(service)
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cService))
	var length C.UInt32
	var data unsafe.Pointer
	status := C.helper_keychain_load(cAccount, C.UInt32(len(account)), cService,
		C.UInt32(len(service)), &length, &data)
	if status == C.errSecItemNotFound {
		return nil, false, nil
	}
	if status != C.errSecSuccess {
		return nil, false, fmt.Errorf("Keychain read failed with status %d", int32(status))
	}
	defer C.helper_zero_and_free(data, C.size_t(length))
	if uint64(length) > maxKeychainBytes {
		return nil, false, errors.New("Keychain item is too large")
	}
	return C.GoBytes(data, C.int(length)), true, nil
}
