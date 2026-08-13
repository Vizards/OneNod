//go:build darwin && cgo

#include "application_identity_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/message.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

void helper_application_process_free(helper_application_process *process) {
    if (process == NULL) return;
    free(process->path);
    free(process->display_name);
    free(process->signing_identifier);
    free(process->team_identifier);
    free(process->signer_name);
    free(process->designated_requirement);
    free(process->code_directory_hash);
    memset(process, 0, sizeof(*process));
}

static int helper_process_snapshot(pid_t pid, struct proc_bsdinfo *snapshot) {
    memset(snapshot, 0, sizeof(*snapshot));
    int size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, snapshot, sizeof(*snapshot));
    if (size != (int)sizeof(*snapshot) || snapshot->pbi_pid != (uint32_t)pid) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

static int helper_snapshot_is_stable(
    const struct proc_bsdinfo *before,
    const struct proc_bsdinfo *after
) {
    return before->pbi_pid == after->pbi_pid &&
        before->pbi_ppid == after->pbi_ppid &&
        before->pbi_uid == after->pbi_uid &&
        before->pbi_start_tvsec == after->pbi_start_tvsec &&
        before->pbi_start_tvusec == after->pbi_start_tvusec;
}

static int helper_user_home_path(
    uid_t expected_euid,
    char *home_path,
    size_t home_path_size,
    int *system_error
) {
    long suggested_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t buffer_size = suggested_size > 0 ? (size_t)suggested_size : 16384;
    if (buffer_size < 1024) buffer_size = 1024;
    if (buffer_size > 1024 * 1024) buffer_size = 1024 * 1024;
    char *buffer = (char *)malloc(buffer_size);
    struct passwd password;
    struct passwd *result = NULL;
    if (buffer == NULL) {
        *system_error = ENOMEM;
        return -1;
    }
    int status = getpwuid_r(expected_euid, &password, buffer, buffer_size, &result);
    if (status != 0 || result == NULL || password.pw_dir == NULL ||
        password.pw_dir[0] != '/') {
        free(buffer);
        *system_error = status != 0 ? status : ENOENT;
        return -1;
    }
    size_t home_length = strlen(password.pw_dir);
    if (home_length == 0 || home_length >= home_path_size) {
        free(buffer);
        *system_error = ENAMETOOLONG;
        return -1;
    }
    memcpy(home_path, password.pw_dir, home_length + 1);
    free(buffer);
    return 0;
}

static int helper_validate_restricted_directory(
    const char *path,
    uid_t expected_euid,
    int *system_error
) {
    struct stat status;
    if (lstat(path, &status) != 0) {
        *system_error = errno;
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != expected_euid ||
        (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        *system_error = EPERM;
        return -1;
    }
    return 0;
}

typedef struct helper_agent_socket_identity {
    dev_t device;
    ino_t inode;
    char path[PROC_PIDPATHINFO_MAXSIZE];
} helper_agent_socket_identity;

static int helper_resolve_agent_socket(
    uid_t expected_euid,
    helper_agent_socket_identity *identity,
    int *system_error
) {
    char home_path[PROC_PIDPATHINFO_MAXSIZE];
    char onenod_path[PROC_PIDPATHINFO_MAXSIZE];
    struct stat socket_status;
    memset(identity, 0, sizeof(*identity));
    memset(home_path, 0, sizeof(home_path));
    memset(onenod_path, 0, sizeof(onenod_path));
    if (helper_user_home_path(expected_euid, home_path, sizeof(home_path), system_error) != 0) {
        return -1;
    }
    int length = snprintf(onenod_path, sizeof(onenod_path), "%s/.onenod", home_path);
    if (length <= 0 || (size_t)length >= sizeof(onenod_path)) {
        *system_error = ENAMETOOLONG;
        return -1;
    }
    if (helper_validate_restricted_directory(home_path, expected_euid, system_error) != 0 ||
        helper_validate_restricted_directory(onenod_path, expected_euid, system_error) != 0) {
        return -1;
    }
    length = snprintf(identity->path, sizeof(identity->path),
        "%s/agent.sock", onenod_path);
    if (length <= 0 || (size_t)length >= sizeof(identity->path) ||
        (size_t)length >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        *system_error = ENAMETOOLONG;
        return -1;
    }
    if (lstat(identity->path, &socket_status) != 0) {
        *system_error = errno;
        return -1;
    }
    if (!S_ISSOCK(socket_status.st_mode) || socket_status.st_uid != expected_euid ||
        (socket_status.st_mode & ACCESSPERMS) != (S_IRUSR | S_IWUSR)) {
        *system_error = EPERM;
        return -1;
    }
    identity->device = socket_status.st_dev;
    identity->inode = socket_status.st_ino;
    return 0;
}

static int helper_same_agent_socket(
    const helper_agent_socket_identity *first,
    const helper_agent_socket_identity *second
) {
    return first->device == second->device && first->inode == second->inode &&
        strcmp(first->path, second->path) == 0;
}

int helper_validate_process_link(
    pid_t child_pid,
    pid_t expected_parent_pid,
    uint64_t start_seconds,
    uint64_t start_microseconds,
    uid_t expected_euid,
    int *system_error
) {
    struct proc_bsdinfo snapshot;
    *system_error = 0;
    if (child_pid <= 1 || expected_parent_pid <= 1 ||
        helper_process_snapshot(child_pid, &snapshot) != 0) {
        *system_error = errno != 0 ? errno : ESRCH;
        return -1;
    }
    if (snapshot.pbi_pid != (uint32_t)child_pid ||
        snapshot.pbi_ppid != (uint32_t)expected_parent_pid ||
        snapshot.pbi_uid != expected_euid ||
        snapshot.pbi_ruid != expected_euid ||
        snapshot.pbi_start_tvsec != start_seconds ||
        snapshot.pbi_start_tvusec != start_microseconds ||
        (snapshot.pbi_flags & (PROC_FLAG_TRACED | PROC_FLAG_INEXIT)) != 0) {
        *system_error = ESTALE;
        return -1;
    }
    return 0;
}

static int helper_sockaddr_matches_path(
    const struct sockaddr_un *address,
    socklen_t address_length,
    const char *expected_path,
    size_t expected_length
) {
    size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    if (address == NULL || expected_path == NULL || expected_length == 0 ||
        expected_path[0] != '/' ||
        expected_length >= sizeof(address->sun_path) ||
        memchr(expected_path, '\0', expected_length) != NULL ||
        expected_path[expected_length] != '\0' ||
        address_length <= path_offset || address_length > sizeof(*address) ||
        address->sun_family != AF_UNIX || address->sun_len != address_length) {
        return 0;
    }
    size_t returned_length = (size_t)address_length - path_offset;
    if (returned_length != expected_length && returned_length != expected_length + 1) {
        return 0;
    }
    if (memcmp(address->sun_path, expected_path, expected_length) != 0) {
        return 0;
    }
    return returned_length == expected_length || address->sun_path[expected_length] == '\0';
}

static int helper_sockaddr_is_unnamed(
    const struct sockaddr_un *address,
    socklen_t address_length
) {
    size_t path_offset = offsetof(struct sockaddr_un, sun_path);
    if (address == NULL || address_length < path_offset ||
        address_length > sizeof(*address) || address->sun_family != AF_UNIX ||
        address->sun_len != address_length) {
        return 0;
    }
    size_t returned_length = (size_t)address_length - path_offset;
    for (size_t index = 0; index < returned_length; index++) {
        if (address->sun_path[index] != '\0') return 0;
    }
    return 1;
}

int helper_peer_audit_token_at_path(
    int descriptor,
    uid_t expected_euid,
    const char *expected_path,
    size_t expected_path_length,
    audit_token_t *token,
    pid_t *peer_pid,
    int *system_error
) {
    struct stat status;
    struct stat socket_path_status;
    struct sockaddr_un local_address;
    struct sockaddr_un peer_address;
    socklen_t local_length = sizeof(local_address);
    socklen_t peer_length = sizeof(peer_address);
    socklen_t token_length = sizeof(*token);
    socklen_t pid_length = sizeof(*peer_pid);
    *system_error = 0;
    memset(token, 0, sizeof(*token));
    *peer_pid = 0;
    memset(&local_address, 0, sizeof(local_address));
    memset(&peer_address, 0, sizeof(peer_address));
    if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
        !S_ISSOCK(status.st_mode) || status.st_uid != expected_euid) {
        *system_error = descriptor < 0 ? EBADF : (errno != 0 ? errno : ENOTSOCK);
        return -1;
    }
    if (expected_path == NULL || expected_path_length == 0 ||
        expected_path_length >= sizeof(local_address.sun_path) ||
        expected_path[0] != '/' ||
        memchr(expected_path, '\0', expected_path_length) != NULL) {
        *system_error = EINVAL;
        return -1;
    }
    if (lstat(expected_path, &socket_path_status) != 0) {
        *system_error = errno;
        return -1;
    }
    if (!S_ISSOCK(socket_path_status.st_mode) ||
        socket_path_status.st_uid != expected_euid ||
        (socket_path_status.st_mode & ACCESSPERMS) != (S_IRUSR | S_IWUSR)) {
        *system_error = EPERM;
        return -1;
    }
    if (getsockname(descriptor, (struct sockaddr *)&local_address, &local_length) != 0) {
        *system_error = errno;
        return -1;
    }
    if (!helper_sockaddr_matches_path(
            &local_address, local_length, expected_path, expected_path_length)) {
        *system_error = ENOTSOCK;
        return -1;
    }
    if (getpeername(descriptor, (struct sockaddr *)&peer_address, &peer_length) != 0) {
        *system_error = errno;
        return -1;
    }
    if (!helper_sockaddr_is_unnamed(&peer_address, peer_length)) {
        *system_error = ENOTSOCK;
        return -1;
    }
    if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERTOKEN, token, &token_length) != 0 ||
        token_length != sizeof(*token)) {
        *system_error = errno != 0 ? errno : EIO;
        return -1;
    }
    if (getsockopt(descriptor, SOL_LOCAL, LOCAL_PEERPID, peer_pid, &pid_length) != 0 ||
        pid_length != sizeof(*peer_pid) || *peer_pid <= 1) {
        *system_error = errno != 0 ? errno : ESRCH;
        return -1;
    }
    if (audit_token_to_pid(*token) != *peer_pid ||
        audit_token_to_euid(*token) != expected_euid) {
        *system_error = EPERM;
        return -1;
    }
    return 0;
}

int helper_peer_audit_token(
    int descriptor,
    uid_t expected_euid,
    audit_token_t *token,
    pid_t *peer_pid,
    int *system_error
) {
    // These pathname/inode checks distinguish the accepted side of the
    // configured agent socket from a client socket or socketpair. They are
    // connection-shape and DoS checks only: same-UID filesystem metadata is
    // never used to authorize the OneNod transport. The caller process must
    // independently pass the exact SecCode policy enforced in Go.
    helper_agent_socket_identity first_socket;
    helper_agent_socket_identity second_socket;
    memset(&first_socket, 0, sizeof(first_socket));
    memset(&second_socket, 0, sizeof(second_socket));
    if (helper_resolve_agent_socket(expected_euid, &first_socket, system_error) != 0) {
        return -1;
    }
    if (helper_peer_audit_token_at_path(
            descriptor, expected_euid,
            first_socket.path, strlen(first_socket.path),
            token, peer_pid, system_error) != 0) {
        return -1;
    }
    if (helper_resolve_agent_socket(expected_euid, &second_socket, system_error) != 0 ||
        !helper_same_agent_socket(&first_socket, &second_socket)) {
        if (*system_error == 0) *system_error = ESTALE;
        return -1;
    }
    return 0;
}

static char *helper_copy_cf_string(CFTypeRef value) {
    if (value == NULL || CFGetTypeID(value) != CFStringGetTypeID()) return NULL;
    CFStringRef string = (CFStringRef)value;
    CFIndex length = CFStringGetLength(string);
    if (length < 0) return NULL;
    CFIndex maximum = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
    if (maximum < 0 || maximum > 16383) return NULL;
    char *copy = (char *)malloc((size_t)maximum + 1);
    if (copy == NULL) return NULL;
    if (!CFStringGetCString(string, copy, maximum + 1, kCFStringEncodingUTF8)) {
        free(copy);
        return NULL;
    }
    return copy;
}

static int helper_copy_cf_number_u32(CFDictionaryRef information, CFStringRef key, uint32_t *value) {
    CFTypeRef raw = CFDictionaryGetValue(information, key);
    int64_t number = 0;
    if (raw == NULL || CFGetTypeID(raw) != CFNumberGetTypeID() ||
        !CFNumberGetValue((CFNumberRef)raw, kCFNumberSInt64Type, &number) ||
        number < 0 || (uint64_t)number > UINT32_MAX) {
        return -1;
    }
    *value = (uint32_t)number;
    return 0;
}

static int helper_copy_cf_data(
    CFTypeRef value,
    size_t minimum_length,
    size_t maximum_length,
    unsigned char **copy,
    size_t *copy_length
) {
    *copy = NULL;
    *copy_length = 0;
    if (value == NULL || CFGetTypeID(value) != CFDataGetTypeID()) return -1;
    CFDataRef data = (CFDataRef)value;
    CFIndex length = CFDataGetLength(data);
    if (length < 0 || (size_t)length < minimum_length ||
        (size_t)length > maximum_length) {
        return -1;
    }
    unsigned char *bytes = (unsigned char *)malloc((size_t)length);
    if (bytes == NULL) return -1;
    memcpy(bytes, CFDataGetBytePtr(data), (size_t)length);
    *copy = bytes;
    *copy_length = (size_t)length;
    return 0;
}

static int helper_is_known_runtime_entitlement(CFStringRef key) {
    return CFStringCompare(key,
            CFSTR("com.apple.security.cs.disable-library-validation"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key,
            CFSTR("com.apple.security.cs.allow-dyld-environment-variables"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key, CFSTR("com.apple.security.cs.allow-jit"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key,
            CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key,
            CFSTR("com.apple.security.cs.disable-executable-page-protection"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key,
            CFSTR("com.apple.security.cs.allow-relative-library-loads"), 0)
            == kCFCompareEqualTo ||
        CFStringCompare(key, CFSTR("com.apple.security.cs.debugger"), 0)
            == kCFCompareEqualTo;
}

static uint32_t helper_dangerous_entitlements(CFDictionaryRef information) {
    CFTypeRef raw_entitlements = CFDictionaryGetValue(information, kSecCodeInfoEntitlements);
    CFTypeRef value = CFDictionaryGetValue(information, kSecCodeInfoEntitlementsDict);
    if (value == NULL) {
        return raw_entitlements == NULL ? 0 : HELPER_ENTITLEMENT_MALFORMED;
    }
    if (CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        return HELPER_ENTITLEMENT_MALFORMED;
    }
    CFDictionaryRef entitlements = (CFDictionaryRef)value;
    uint32_t flags = 0;
    // Presence is rejected even when a malformed or false value is supplied.
    // This keeps the local trust policy independent of entitlement coercion.
    if (CFDictionaryContainsKey(entitlements, CFSTR("com.apple.security.get-task-allow"))) {
        flags |= HELPER_ENTITLEMENT_GET_TASK_ALLOW;
    }
    if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.disable-library-validation"))) {
        flags |= HELPER_ENTITLEMENT_DISABLE_LIBRARY_VALIDATION;
    }
    if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.allow-dyld-environment-variables"))) {
        flags |= HELPER_ENTITLEMENT_ALLOW_DYLD_ENVIRONMENT_VARIABLES;
    }
    if (CFDictionaryContainsKey(entitlements, CFSTR("com.apple.security.cs.allow-jit"))) {
        flags |= HELPER_ENTITLEMENT_ALLOW_JIT;
    }
    if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"))) {
        flags |= HELPER_ENTITLEMENT_ALLOW_UNSIGNED_EXECUTABLE_MEMORY;
    }
    if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.disable-executable-page-protection"))) {
        flags |= HELPER_ENTITLEMENT_DISABLE_EXECUTABLE_PAGE_PROTECTION;
    }
    if (CFDictionaryContainsKey(entitlements,
            CFSTR("com.apple.security.cs.allow-relative-library-loads"))) {
        flags |= HELPER_ENTITLEMENT_ALLOW_RELATIVE_LIBRARY_LOADS;
    }
    if (CFDictionaryContainsKey(entitlements, CFSTR("com.apple.security.cs.debugger"))) {
        flags |= HELPER_ENTITLEMENT_DEBUGGER;
    }
    // Fail closed as Apple adds Hardened Runtime exceptions. Third-party
    // application policy deliberately allows only the two internal JIT/W^X
    // exceptions below; OneNod helper/transport policy rejects those too.
    CFIndex entitlement_count = CFDictionaryGetCount(entitlements);
    if (entitlement_count < 0 || entitlement_count > 1024) {
        return flags | HELPER_ENTITLEMENT_MALFORMED;
    }
    if (entitlement_count > 0) {
        const void **keys = (const void **)calloc((size_t)entitlement_count, sizeof(void *));
        if (keys == NULL) return flags | HELPER_ENTITLEMENT_MALFORMED;
        CFDictionaryGetKeysAndValues(entitlements, keys, NULL);
        for (CFIndex index = 0; index < entitlement_count; index++) {
            CFTypeRef key = (CFTypeRef)keys[index];
            if (key == NULL || CFGetTypeID(key) != CFStringGetTypeID()) {
                flags |= HELPER_ENTITLEMENT_MALFORMED;
                continue;
            }
            CFStringRef string_key = (CFStringRef)key;
            if (CFStringHasPrefix(string_key, CFSTR("com.apple.security.cs.")) &&
                !helper_is_known_runtime_entitlement(string_key)) {
                flags |= HELPER_ENTITLEMENT_UNKNOWN_RUNTIME_EXCEPTION;
            }
        }
        free(keys);
    }
    return flags;
}

static int helper_code_matches_requirement(SecCodeRef code, CFStringRef source) {
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString(source, kSecCSDefaultFlags, &requirement);
    if (status != errSecSuccess || requirement == NULL) {
        if (requirement != NULL) CFRelease(requirement);
        return 0;
    }
    status = SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement);
    CFRelease(requirement);
    return status == errSecSuccess;
}

static int helper_read_process_path(
    pid_t pid,
    const audit_token_t *token,
    char *path,
    size_t path_size
) {
    memset(path, 0, path_size);
    int length = token != NULL
        ? proc_pidpath_audittoken((audit_token_t *)token, path, (uint32_t)path_size)
        : proc_pidpath(pid, path, (uint32_t)path_size);
    if (length <= 0 || (size_t)length >= path_size) return -1;
    path[path_size - 1] = '\0';
    return 0;
}

int helper_inspect_process(
    pid_t pid,
    const audit_token_t *token,
    uid_t expected_euid,
    helper_application_process *process
) {
    struct proc_bsdinfo before;
    struct proc_bsdinfo after;
    char first_process_path[PROC_PIDPATHINFO_MAXSIZE];
    char second_process_path[PROC_PIDPATHINFO_MAXSIZE];
    CFMutableDictionaryRef attributes = NULL;
    CFTypeRef attribute_value = NULL;
    SecCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    SecRequirementRef designated_requirement = NULL;
    CFDataRef designated_requirement_data = NULL;
    OSStatus security_status = errSecSuccess;
    int result = 0;
    int is_adhoc = 0;

    memset(process, 0, sizeof(*process));
    memset(first_process_path, 0, sizeof(first_process_path));
    memset(second_process_path, 0, sizeof(second_process_path));
    process->code_state = HELPER_CODE_UNAVAILABLE;
    process->signature_class = HELPER_SIGNATURE_UNKNOWN;
    if (token != NULL) {
        pid_t token_pid = audit_token_to_pid(*token);
        if (token_pid <= 1 || token_pid != pid || audit_token_to_euid(*token) != expected_euid) {
            process->system_error = EPERM;
            return -1;
        }
    }
    if (pid <= 1 || helper_process_snapshot(pid, &before) != 0) {
        process->system_error = errno;
        return -1;
    }
    process->pid = (int32_t)before.pbi_pid;
    process->parent_pid = (int32_t)before.pbi_ppid;
    process->start_seconds = before.pbi_start_tvsec;
    process->start_microseconds = before.pbi_start_tvusec;
    if (before.pbi_uid != expected_euid ||
        before.pbi_ruid != expected_euid ||
        (before.pbi_flags & (PROC_FLAG_TRACED | PROC_FLAG_INEXIT)) != 0) {
        process->code_state = HELPER_CODE_INVALID;
        process->system_error = EPERM;
        goto finalize;
    }
    if (helper_read_process_path(pid, token,
        first_process_path, sizeof(first_process_path)) != 0) {
        process->system_error = errno != 0 ? errno : ESRCH;
        result = -1;
        goto finalize;
    }
    attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL) {
        process->system_error = ENOMEM;
        result = -1;
        goto finalize;
    }
    if (token != NULL) {
        attribute_value = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)token, sizeof(*token));
        if (attribute_value != NULL) {
            CFDictionarySetValue(attributes, kSecGuestAttributeAudit, attribute_value);
        }
    } else {
        int32_t process_id = (int32_t)pid;
        attribute_value = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &process_id);
        if (attribute_value != NULL) {
            CFDictionarySetValue(attributes, kSecGuestAttributePid, attribute_value);
        }
    }
    if (attribute_value == NULL) {
        process->system_error = ENOMEM;
        result = -1;
        goto finalize;
    }

    security_status = SecCodeCopyGuestWithAttributes(
        NULL, attributes, kSecCSDefaultFlags, &code);
    process->security_status = (int32_t)security_status;
    if (security_status == errSecCSUnsigned || security_status == errSecCSNoSuchCode) {
        process->code_state = HELPER_CODE_UNSIGNED;
        goto finalize;
    }
    if (security_status != errSecSuccess || code == NULL) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }

    security_status = SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL);
    process->security_status = (int32_t)security_status;
    if (security_status == errSecCSUnsigned) {
        process->code_state = HELPER_CODE_UNSIGNED;
        goto finalize;
    }
    if (security_status != errSecSuccess) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }

    security_status = SecCodeCopySigningInformation(
        (SecStaticCodeRef)code,
        kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation,
        &information);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || information == NULL) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }

    uint32_t signature_flags = 0;
    uint32_t dynamic_status = 0;
    if (helper_copy_cf_number_u32(information, kSecCodeInfoFlags, &signature_flags) != 0 ||
        helper_copy_cf_number_u32(information, kSecCodeInfoStatus, &dynamic_status) != 0 ||
        (dynamic_status & kSecCodeStatusValid) == 0 ||
        (dynamic_status & kSecCodeStatusDebugged) != 0) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    process->hardened_runtime =
        (signature_flags & kSecCodeSignatureRuntime) != 0;
    process->linker_signed =
        (signature_flags & kSecCodeSignatureLinkerSigned) != 0;
    process->dangerous_entitlements = helper_dangerous_entitlements(information);
    if (process->hardened_runtime && helper_copy_cf_number_u32(
            information, kSecCodeInfoRuntimeVersion,
            &process->code_runtime_version) != 0) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    if (helper_copy_cf_data(
            CFDictionaryGetValue(information, kSecCodeInfoUnique), 20, 64,
            &process->code_directory_hash,
            &process->code_directory_hash_length) != 0) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }

    if ((signature_flags & kSecCodeSignatureAdhoc) != 0) {
        is_adhoc = 1;
        process->signature_class = HELPER_SIGNATURE_ADHOC;
        process->code_state = HELPER_CODE_ADHOC;
    } else if ((dynamic_status & kSecCodeStatusPlatform) != 0) {
        process->signature_class = HELPER_SIGNATURE_APPLE_PLATFORM;
    } else if (helper_code_matches_requirement(code,
        CFSTR("anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists"))) {
        process->signature_class = HELPER_SIGNATURE_MAC_APP_STORE;
    } else if (helper_code_matches_requirement(code,
        CFSTR("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))) {
        process->signature_class = HELPER_SIGNATURE_DEVELOPER_ID;
    } else {
        process->code_state = HELPER_CODE_UNSUPPORTED_SIGNATURE;
        goto finalize;
    }

    process->signing_identifier = helper_copy_cf_string(
        CFDictionaryGetValue(information, kSecCodeInfoIdentifier));
    process->team_identifier = helper_copy_cf_string(
        CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier));

    CFTypeRef property_list_value = CFDictionaryGetValue(information, kSecCodeInfoPList);
    if (property_list_value != NULL &&
        CFGetTypeID(property_list_value) == CFDictionaryGetTypeID()) {
        CFDictionaryRef property_list = (CFDictionaryRef)property_list_value;
        CFTypeRef package_type = CFDictionaryGetValue(property_list, CFSTR("CFBundlePackageType"));
        if (package_type != NULL && CFGetTypeID(package_type) == CFStringGetTypeID() &&
            CFStringCompare((CFStringRef)package_type, CFSTR("APPL"), 0) == kCFCompareEqualTo) {
            process->app_bundle = 1;
        }
        CFTypeRef display_name = CFDictionaryGetValue(property_list, CFSTR("CFBundleDisplayName"));
        if (display_name == NULL) {
            display_name = CFDictionaryGetValue(property_list, CFSTR("CFBundleName"));
        }
        process->display_name = helper_copy_cf_string(display_name);
    }

    CFTypeRef certificates_value = CFDictionaryGetValue(information, kSecCodeInfoCertificates);
    if (certificates_value != NULL && CFGetTypeID(certificates_value) == CFArrayGetTypeID() &&
        CFArrayGetCount((CFArrayRef)certificates_value) > 0) {
        CFTypeRef certificate_value = CFArrayGetValueAtIndex((CFArrayRef)certificates_value, 0);
        if (certificate_value != NULL &&
            CFGetTypeID(certificate_value) == SecCertificateGetTypeID()) {
            CFStringRef signer = SecCertificateCopySubjectSummary((SecCertificateRef)certificate_value);
            process->signer_name = helper_copy_cf_string(signer);
            if (signer != NULL) CFRelease(signer);
        }
    }

    security_status = SecCodeCopyDesignatedRequirement(
        (SecStaticCodeRef)code, kSecCSDefaultFlags, &designated_requirement);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || designated_requirement == NULL) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    security_status = SecCodeCheckValidity(code, kSecCSDefaultFlags, designated_requirement);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    security_status = SecRequirementCopyData(
        designated_requirement, kSecCSDefaultFlags, &designated_requirement_data);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || designated_requirement_data == NULL) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    CFIndex requirement_length = CFDataGetLength(designated_requirement_data);
    if (requirement_length <= 0 || requirement_length > 65536) {
        process->code_state = HELPER_CODE_INVALID;
        goto finalize;
    }
    process->designated_requirement = (unsigned char *)malloc((size_t)requirement_length);
    if (process->designated_requirement == NULL) {
        process->system_error = ENOMEM;
        result = -1;
        goto finalize;
    }
    memcpy(process->designated_requirement,
        CFDataGetBytePtr(designated_requirement_data), (size_t)requirement_length);
    process->designated_requirement_length = (size_t)requirement_length;
    process->code_state = is_adhoc ? HELPER_CODE_ADHOC : HELPER_CODE_VERIFIED;

finalize:
    if (designated_requirement_data != NULL) CFRelease(designated_requirement_data);
    if (designated_requirement != NULL) CFRelease(designated_requirement);
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code);
    if (attribute_value != NULL) CFRelease(attribute_value);
    if (attributes != NULL) CFRelease(attributes);
    if (helper_read_process_path(pid, token,
            second_process_path, sizeof(second_process_path)) != 0 ||
        first_process_path[0] == '\0' ||
        strcmp(first_process_path, second_process_path) != 0 ||
        helper_process_snapshot(pid, &after) != 0 ||
        !helper_snapshot_is_stable(&before, &after) ||
        (after.pbi_flags & (PROC_FLAG_TRACED | PROC_FLAG_INEXIT)) != 0) {
        helper_application_process_free(process);
        process->system_error = ESTALE;
        return -1;
    }
    process->path = strdup(second_process_path);
    if (process->path == NULL) {
        helper_application_process_free(process);
        process->system_error = ENOMEM;
        return -1;
    }
    if (result != 0) {
        int system_error = process->system_error;
        helper_application_process_free(process);
        process->system_error = system_error;
    }
    return result;
}

static int helper_stat_is_stable(const struct stat *first, const struct stat *second) {
    return first->st_dev == second->st_dev &&
        first->st_ino == second->st_ino &&
        first->st_mode == second->st_mode &&
        first->st_uid == second->st_uid &&
        first->st_gid == second->st_gid &&
        first->st_size == second->st_size &&
        first->st_mtimespec.tv_sec == second->st_mtimespec.tv_sec &&
        first->st_mtimespec.tv_nsec == second->st_mtimespec.tv_nsec &&
        first->st_ctimespec.tv_sec == second->st_ctimespec.tv_sec &&
        first->st_ctimespec.tv_nsec == second->st_ctimespec.tv_nsec;
}

int helper_inspect_static_transport_fd(
    int descriptor,
    helper_application_process *process
) {
    struct stat descriptor_before;
    struct stat descriptor_after;
    struct stat path_before;
    struct stat path_after;
    char first_path[PATH_MAX];
    char second_path[PATH_MAX];
    CFURLRef path_url = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    SecRequirementRef designated_requirement = NULL;
    CFDataRef designated_requirement_data = NULL;
    OSStatus security_status = errSecSuccess;
    int descriptor_flags = -1;
    int result = -1;

    memset(process, 0, sizeof(*process));
    memset(&descriptor_before, 0, sizeof(descriptor_before));
    memset(&descriptor_after, 0, sizeof(descriptor_after));
    memset(&path_before, 0, sizeof(path_before));
    memset(&path_after, 0, sizeof(path_after));
    memset(first_path, 0, sizeof(first_path));
    memset(second_path, 0, sizeof(second_path));
    process->code_state = HELPER_CODE_UNAVAILABLE;
    process->signature_class = HELPER_SIGNATURE_UNKNOWN;

    descriptor_flags = fcntl(descriptor, F_GETFL);
    if (descriptor < 0 || descriptor_flags < 0 ||
        (descriptor_flags & O_ACCMODE) != O_RDONLY ||
        fstat(descriptor, &descriptor_before) != 0 ||
        !S_ISREG(descriptor_before.st_mode) || descriptor_before.st_size <= 0 ||
        fcntl(descriptor, F_GETPATH, first_path) != 0 || first_path[0] != '/' ||
        stat(first_path, &path_before) != 0 ||
        !helper_stat_is_stable(&descriptor_before, &path_before)) {
        process->system_error = errno != 0 ? errno : EPERM;
        goto finalize;
    }

    path_url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)first_path, strlen(first_path), false);
    if (path_url == NULL) {
        process->system_error = ENOMEM;
        goto finalize;
    }
    security_status = SecStaticCodeCreateWithPath(
        path_url, kSecCSDefaultFlags, &code);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || code == NULL) goto finalize;

    security_status = SecStaticCodeCheckValidity(
        code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, NULL);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess) goto finalize;

    security_status = SecCodeCopySigningInformation(
        code, kSecCSSigningInformation | kSecCSRequirementInformation,
        &information);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || information == NULL) goto finalize;

    uint32_t signature_flags = 0;
    if (helper_copy_cf_number_u32(information, kSecCodeInfoFlags, &signature_flags) != 0 ||
        (signature_flags & kSecCodeSignatureAdhoc) == 0 ||
        (signature_flags & kSecCodeSignatureLinkerSigned) != 0 ||
        (signature_flags & kSecCodeSignatureRuntime) == 0) {
        process->code_state = HELPER_CODE_INVALID;
        process->system_error = EPERM;
        goto finalize;
    }
    process->hardened_runtime = 1;
    process->dangerous_entitlements = helper_dangerous_entitlements(information);
    if (helper_copy_cf_number_u32(
            information, kSecCodeInfoRuntimeVersion,
            &process->code_runtime_version) != 0 ||
        process->code_runtime_version == 0 || helper_copy_cf_data(
            CFDictionaryGetValue(information, kSecCodeInfoUnique), 20, 64,
            &process->code_directory_hash,
            &process->code_directory_hash_length) != 0) {
        process->code_state = HELPER_CODE_INVALID;
        process->system_error = EPERM;
        goto finalize;
    }
    process->signing_identifier = helper_copy_cf_string(
        CFDictionaryGetValue(information, kSecCodeInfoIdentifier));
    process->team_identifier = helper_copy_cf_string(
        CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier));
    if (process->signing_identifier == NULL || process->team_identifier != NULL) {
        process->code_state = HELPER_CODE_INVALID;
        process->system_error = EPERM;
        goto finalize;
    }

    security_status = SecCodeCopyDesignatedRequirement(
        code, kSecCSDefaultFlags, &designated_requirement);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || designated_requirement == NULL) goto finalize;
    security_status = SecStaticCodeCheckValidity(
        code, kSecCSStrictValidate | kSecCSCheckAllArchitectures,
        designated_requirement);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess) goto finalize;
    security_status = SecRequirementCopyData(
        designated_requirement, kSecCSDefaultFlags,
        &designated_requirement_data);
    process->security_status = (int32_t)security_status;
    if (security_status != errSecSuccess || designated_requirement_data == NULL) goto finalize;
    CFIndex requirement_length = CFDataGetLength(designated_requirement_data);
    if (requirement_length <= 0 || requirement_length > 65536) goto finalize;
    process->designated_requirement = (unsigned char *)malloc((size_t)requirement_length);
    if (process->designated_requirement == NULL) {
        process->system_error = ENOMEM;
        goto finalize;
    }
    memcpy(process->designated_requirement,
        CFDataGetBytePtr(designated_requirement_data), (size_t)requirement_length);
    process->designated_requirement_length = (size_t)requirement_length;
    process->signature_class = HELPER_SIGNATURE_ADHOC;
    process->code_state = HELPER_CODE_ADHOC;

    if (fstat(descriptor, &descriptor_after) != 0 ||
        fcntl(descriptor, F_GETPATH, second_path) != 0 ||
        strcmp(first_path, second_path) != 0 || stat(second_path, &path_after) != 0 ||
        !helper_stat_is_stable(&descriptor_before, &descriptor_after) ||
        !helper_stat_is_stable(&descriptor_before, &path_after)) {
        process->system_error = ESTALE;
        goto finalize;
    }
    process->path = strdup(second_path);
    if (process->path == NULL) {
        process->system_error = ENOMEM;
        goto finalize;
    }
    result = 0;

finalize:
    if (designated_requirement_data != NULL) CFRelease(designated_requirement_data);
    if (designated_requirement != NULL) CFRelease(designated_requirement);
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code);
    if (path_url != NULL) CFRelease(path_url);
    if (result != 0) {
        int system_error = process->system_error;
        int security_error = process->security_status;
        helper_application_process_free(process);
        process->system_error = system_error;
        process->security_status = security_error;
    }
    return result;
}
