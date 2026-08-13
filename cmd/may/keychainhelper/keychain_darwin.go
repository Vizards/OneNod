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

enum {
    helper_access_preserve = 1,
    helper_access_prompt_required = 2,
    helper_access_self_only = 3,
};

static OSStatus helper_create_access(CFStringRef descriptor, int policy,
    SecAccessRef *access) {
    if (access == NULL || descriptor == NULL ||
        (policy != helper_access_prompt_required && policy != helper_access_self_only)) {
        return errSecParam;
    }
    *access = NULL;
    CFMutableArrayRef trusted = CFArrayCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeArrayCallBacks);
    if (trusted == NULL) return errSecAllocate;
    SecTrustedApplicationRef self = NULL;
    OSStatus status = errSecSuccess;
    if (policy == helper_access_self_only) {
        status = SecTrustedApplicationCreateFromPath(NULL, &self);
        if (status == errSecSuccess && self != NULL) {
            CFArrayAppendValue(trusted, self);
        }
    }
    if (status == errSecSuccess) {
        CFStringRef ceremony = CFSTR(
            "OneNod requester identity - approve only during explicit bootstrap or update"
        );
        status = SecAccessCreate(ceremony, trusted, access);
    }
    if (self != NULL) CFRelease(self);
    CFRelease(trusted);
    return status;
}

static OSStatus helper_keychain_create(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, const void *data, UInt32 dataLength,
    const void *metadata, UInt32 metadataLength, int accessPolicy) {
    CFStringRef a = helper_cfstring(account, accountLength);
    CFStringRef s = helper_cfstring(service, serviceLength);
    CFDataRef d = CFDataCreate(kCFAllocatorDefault, data, dataLength);
    CFDataRef m = CFDataCreate(kCFAllocatorDefault, metadata, metadataLength);
    if (a == NULL || s == NULL || d == NULL || m == NULL) {
        if (a != NULL) CFRelease(a); if (s != NULL) CFRelease(s); if (d != NULL) CFRelease(d);
        if (m != NULL) CFRelease(m);
        return errSecAllocate;
    }
    SecAccessRef access = NULL;
    OSStatus status = helper_create_access(s, accessPolicy, &access);
    if (status != errSecSuccess || access == NULL) {
        CFRelease(a); CFRelease(s); CFRelease(d); CFRelease(m);
        if (access != NULL) CFRelease(access);
        return status == errSecSuccess ? errSecAllocate : status;
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) {
        CFRelease(a); CFRelease(s); CFRelease(d); CFRelease(m); CFRelease(access); return errSecAllocate;
    }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccount, a);
    CFDictionarySetValue(q, kSecAttrService, s);
    CFDictionarySetValue(q, kSecValueData, d);
    CFDictionarySetValue(q, kSecAttrGeneric, m);
    CFDictionarySetValue(q, kSecAttrAccess, access);
    status = SecItemAdd(q, NULL);
    CFRelease(q); CFRelease(a); CFRelease(s); CFRelease(d); CFRelease(m); CFRelease(access);
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

static OSStatus helper_keychain_inspect(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, UInt32 *metadataLength, void **metadata) {
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
    CFDictionarySetValue(q, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(q, &result);
    CFRelease(q); CFRelease(a); CFRelease(s);
    if (status != errSecSuccess) { if (result != NULL) CFRelease(result); return status; }
    if (result == NULL || CFGetTypeID(result) != CFDictionaryGetTypeID()) {
        if (result != NULL) CFRelease(result); return errSecDecode;
    }
    CFTypeRef generic = CFDictionaryGetValue((CFDictionaryRef)result, kSecAttrGeneric);
    if (generic == NULL) {
        CFRelease(result); *metadataLength = 0; *metadata = NULL; return errSecSuccess;
    }
    if (CFGetTypeID(generic) != CFDataGetTypeID()) {
        CFRelease(result); return errSecDecode;
    }
    CFIndex length = CFDataGetLength((CFDataRef)generic);
    if (length < 0 || (uint64_t)length > UINT32_MAX) { CFRelease(result); return errSecDecode; }
    void *copy = malloc((size_t)length);
    if (length > 0 && copy == NULL) { CFRelease(result); return errSecAllocate; }
    if (length > 0) memcpy(copy, CFDataGetBytePtr((CFDataRef)generic), (size_t)length);
    CFRelease(result); *metadataLength = (UInt32)length; *metadata = copy; return errSecSuccess;
}

// SecKeychainItemModifyAttributesAndData changes the encrypted value and its
// signed public envelope together. Ordinary exact-transport rotations preserve
// the already-constrained helper ACL. Bootstrap and helper replacement use the
// separate SetAccess step and persist a repair marker before reaching it.
static OSStatus helper_keychain_replace(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, const void *data, UInt32 dataLength,
    const void *metadata, UInt32 metadataLength,
    int accessPolicy, Boolean *contentChanged) {
    if (contentChanged == NULL) return errSecParam;
    *contentChanged = false;
    CFStringRef a = helper_cfstring(account, accountLength);
    CFStringRef s = helper_cfstring(service, serviceLength);
    if (a == NULL || s == NULL) {
        if (a != NULL) CFRelease(a); if (s != NULL) CFRelease(s); return errSecAllocate;
    }
    if (accessPolicy != helper_access_preserve &&
        accessPolicy != helper_access_self_only) {
        CFRelease(a); CFRelease(s); return errSecParam;
    }
    SecAccessRef access = NULL;
    OSStatus status = errSecSuccess;
    if (accessPolicy == helper_access_self_only) {
        status = helper_create_access(s, accessPolicy, &access);
        if (status != errSecSuccess || access == NULL) {
            CFRelease(a); CFRelease(s);
            if (access != NULL) CFRelease(access);
            return status == errSecSuccess ? errSecAllocate : status;
        }
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) {
        CFRelease(a); CFRelease(s);
        if (access != NULL) CFRelease(access);
        return errSecAllocate;
    }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccount, a);
    CFDictionarySetValue(q, kSecAttrService, s);
    CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    status = SecItemCopyMatching(q, &result);
    CFRelease(q); CFRelease(a); CFRelease(s);
    if (status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        if (access != NULL) CFRelease(access);
        return status;
    }
    if (result == NULL || CFGetTypeID(result) != SecKeychainItemGetTypeID()) {
        if (result != NULL) CFRelease(result);
        if (access != NULL) CFRelease(access);
        return errSecDecode;
    }
    SecKeychainItemRef item = (SecKeychainItemRef)result;
    UInt32 tag = kSecGenericItemAttr;
    SecKeychainAttribute attribute = {tag, metadataLength, (void *)metadata};
    SecKeychainAttributeList attributes = {1, &attribute};
    status = SecKeychainItemModifyAttributesAndData(item, &attributes, dataLength, data);
    if (status == errSecSuccess) {
        *contentChanged = true;
        if (accessPolicy == helper_access_self_only) {
            status = SecKeychainItemSetAccess(item, access);
        }
    }
    CFRelease(result);
    if (access != NULL) CFRelease(access);
    return status;
}

static OSStatus helper_keychain_constrain(const char *account, UInt32 accountLength,
    const char *service, UInt32 serviceLength, int accessPolicy) {
    CFStringRef a = helper_cfstring(account, accountLength);
    CFStringRef s = helper_cfstring(service, serviceLength);
    if (a == NULL || s == NULL) {
        if (a != NULL) CFRelease(a); if (s != NULL) CFRelease(s); return errSecAllocate;
    }
    SecAccessRef access = NULL;
    OSStatus status = helper_create_access(s, accessPolicy, &access);
    if (status != errSecSuccess || access == NULL) {
        CFRelease(a); CFRelease(s);
        if (access != NULL) CFRelease(access);
        return status == errSecSuccess ? errSecAllocate : status;
    }
    CFMutableDictionaryRef q = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (q == NULL) {
        CFRelease(a); CFRelease(s); CFRelease(access); return errSecAllocate;
    }
    CFDictionarySetValue(q, kSecClass, kSecClassGenericPassword);
    CFDictionarySetValue(q, kSecAttrAccount, a);
    CFDictionarySetValue(q, kSecAttrService, s);
    CFDictionarySetValue(q, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(q, kSecMatchLimit, kSecMatchLimitOne);
    CFTypeRef result = NULL;
    status = SecItemCopyMatching(q, &result);
    CFRelease(q); CFRelease(a); CFRelease(s);
    if (status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        CFRelease(access);
        return status;
    }
    if (result == NULL || CFGetTypeID(result) != SecKeychainItemGetTypeID()) {
        if (result != NULL) CFRelease(result);
        CFRelease(access);
        return errSecDecode;
    }
    status = SecKeychainItemSetAccess((SecKeychainItemRef)result, access);
    CFRelease(result); CFRelease(access);
    return status;
}

static void helper_zero_and_free(void *data, size_t length) {
    if (data != NULL) { memset(data, 0, length); free(data); }
}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const maxKeychainBytes = 1 << 20

type systemCredentialStore struct{}

func (systemCredentialStore) Create(
	account,
	service string,
	data,
	metadata []byte,
	access keychainAccessPolicy,
) error {
	if account == "" || service == "" || len(data) == 0 || len(data) > maxKeychainBytes ||
		len(metadata) == 0 || len(metadata) > maxKeychainBytes {
		return errors.New("invalid Keychain item")
	}
	if access != keychainAccessPromptRequired && access != keychainAccessSelfOnly {
		return errors.New("invalid Keychain access policy")
	}
	return withKeychainMutationLock(func() error {
		cAccount, cService := C.CString(account), C.CString(service)
		cData, cMetadata := C.CBytes(data), C.CBytes(metadata)
		defer C.free(unsafe.Pointer(cAccount))
		defer C.free(unsafe.Pointer(cService))
		defer C.helper_zero_and_free(cData, C.size_t(len(data)))
		defer C.helper_zero_and_free(cMetadata, C.size_t(len(metadata)))
		status := C.helper_keychain_create(cAccount, C.UInt32(len(account)), cService,
			C.UInt32(len(service)), cData, C.UInt32(len(data)), cMetadata,
			C.UInt32(len(metadata)), C.int(access))
		if status == C.errSecDuplicateItem {
			return errIdentityExists
		}
		if status != C.errSecSuccess {
			return fmt.Errorf("Keychain write failed with status %d", int32(status))
		}
		return nil
	})
}

func (systemCredentialStore) Inspect(account, service string) ([]byte, bool, error) {
	if account == "" || service == "" {
		return nil, false, errors.New("invalid Keychain item")
	}
	cAccount, cService := C.CString(account), C.CString(service)
	defer C.free(unsafe.Pointer(cAccount))
	defer C.free(unsafe.Pointer(cService))
	var length C.UInt32
	var metadata unsafe.Pointer
	status := C.helper_keychain_inspect(
		cAccount,
		C.UInt32(len(account)),
		cService,
		C.UInt32(len(service)),
		&length,
		&metadata,
	)
	if status == C.errSecItemNotFound {
		return nil, false, nil
	}
	if status != C.errSecSuccess {
		return nil, false, fmt.Errorf("Keychain metadata read failed with status %d", int32(status))
	}
	defer C.helper_zero_and_free(metadata, C.size_t(length))
	if uint64(length) > maxKeychainBytes {
		return nil, false, errors.New("Keychain metadata is too large")
	}
	if length == 0 {
		return []byte{}, true, nil
	}
	return C.GoBytes(metadata, C.int(length)), true, nil
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

func (store systemCredentialStore) Replace(
	account,
	service string,
	expectedMetadata,
	data,
	metadata []byte,
	access keychainAccessPolicy,
) error {
	if account == "" || service == "" || len(expectedMetadata) == 0 ||
		len(expectedMetadata) > maxKeychainBytes || len(data) == 0 ||
		len(data) > maxKeychainBytes || len(metadata) == 0 || len(metadata) > maxKeychainBytes {
		return errors.New("invalid Keychain item replacement")
	}
	if access != keychainAccessPreserve && access != keychainAccessSelfOnly {
		return errors.New("invalid Keychain replacement access policy")
	}
	return withKeychainMutationLock(func() error {
		currentMetadata, found, err := store.Inspect(account, service)
		if err != nil {
			return err
		}
		defer zero(currentMetadata)
		if !found || !bytes.Equal(currentMetadata, expectedMetadata) {
			return errIdentityChanged
		}
		// expectedMetadata is the requester-signed compare-and-replace token. It
		// binds the encrypted data digest, so reading kSecValueData again would add
		// another ceremony interaction without strengthening this boundary.
		cAccount, cService := C.CString(account), C.CString(service)
		cData, cMetadata := C.CBytes(data), C.CBytes(metadata)
		defer C.free(unsafe.Pointer(cAccount))
		defer C.free(unsafe.Pointer(cService))
		defer C.helper_zero_and_free(cData, C.size_t(len(data)))
		defer C.helper_zero_and_free(cMetadata, C.size_t(len(metadata)))
		var contentChanged C.Boolean
		status := C.helper_keychain_replace(
			cAccount,
			C.UInt32(len(account)),
			cService,
			C.UInt32(len(service)),
			cData,
			C.UInt32(len(data)),
			cMetadata,
			C.UInt32(len(metadata)),
			C.int(access),
			&contentChanged,
		)
		if status != C.errSecSuccess {
			if contentChanged != 0 && access == keychainAccessSelfOnly {
				return fmt.Errorf(
					"Keychain content was persisted but self-only ACL convergence failed with status %d; retry is required",
					int32(status),
				)
			}
			return fmt.Errorf("Keychain replacement failed with status %d", int32(status))
		}
		return nil
	})
}

func (store systemCredentialStore) Constrain(
	account,
	service string,
	expectedMetadata []byte,
	access keychainAccessPolicy,
) error {
	if account == "" || service == "" || len(expectedMetadata) == 0 ||
		len(expectedMetadata) > maxKeychainBytes || access != keychainAccessSelfOnly {
		return errors.New("invalid Keychain ACL convergence request")
	}
	return withKeychainMutationLock(func() error {
		currentMetadata, found, err := store.Inspect(account, service)
		if err != nil {
			return err
		}
		defer zero(currentMetadata)
		if !found || !bytes.Equal(currentMetadata, expectedMetadata) {
			return errIdentityChanged
		}
		cAccount, cService := C.CString(account), C.CString(service)
		defer C.free(unsafe.Pointer(cAccount))
		defer C.free(unsafe.Pointer(cService))
		status := C.helper_keychain_constrain(
			cAccount,
			C.UInt32(len(account)),
			cService,
			C.UInt32(len(service)),
			C.int(access),
		)
		if status != C.errSecSuccess {
			return fmt.Errorf("Keychain self-only ACL convergence failed with status %d", int32(status))
		}
		return nil
	})
}

func withKeychainMutationLock(operation func() error) error {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return errors.New("Keychain mutation lock home is unavailable")
	}
	directory := filepath.Join(home, ".onenod")
	lockPath := filepath.Join(directory, "keychain-helper.lock")
	fd, err := unix.Open(
		lockPath,
		unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return errors.New("Keychain mutation lock could not be opened")
	}
	defer unix.Close(fd)
	var lockStat unix.Stat_t
	if err := unix.Fstat(fd, &lockStat); err != nil ||
		lockStat.Mode&unix.S_IFMT != unix.S_IFREG || int(lockStat.Uid) != os.Getuid() ||
		lockStat.Nlink != 1 || lockStat.Mode&0o077 != 0 {
		return errors.New("Keychain mutation lock file is unsafe")
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		return errors.New("Keychain mutation lock could not be acquired")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return operation()
}
