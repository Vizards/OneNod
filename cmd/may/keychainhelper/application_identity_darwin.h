#ifndef ONENOD_APPLICATION_IDENTITY_DARWIN_H
#define ONENOD_APPLICATION_IDENTITY_DARWIN_H

#include <bsm/libbsm.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum helper_application_code_state {
    HELPER_CODE_UNAVAILABLE = 0,
    HELPER_CODE_VERIFIED = 1,
    HELPER_CODE_UNSIGNED = 2,
    HELPER_CODE_ADHOC = 3,
    HELPER_CODE_INVALID = 4,
    HELPER_CODE_UNSUPPORTED_SIGNATURE = 5,
};

enum helper_application_signature_class {
    HELPER_SIGNATURE_UNKNOWN = 0,
    HELPER_SIGNATURE_APPLE_PLATFORM = 1,
    HELPER_SIGNATURE_DEVELOPER_ID = 2,
    HELPER_SIGNATURE_MAC_APP_STORE = 3,
    HELPER_SIGNATURE_ADHOC = 4,
};

enum helper_dangerous_code_entitlement {
    HELPER_ENTITLEMENT_GET_TASK_ALLOW = 1U << 0,
    HELPER_ENTITLEMENT_DISABLE_LIBRARY_VALIDATION = 1U << 1,
    HELPER_ENTITLEMENT_ALLOW_DYLD_ENVIRONMENT_VARIABLES = 1U << 2,
    HELPER_ENTITLEMENT_ALLOW_JIT = 1U << 3,
    HELPER_ENTITLEMENT_ALLOW_UNSIGNED_EXECUTABLE_MEMORY = 1U << 4,
    HELPER_ENTITLEMENT_DISABLE_EXECUTABLE_PAGE_PROTECTION = 1U << 5,
    HELPER_ENTITLEMENT_ALLOW_RELATIVE_LIBRARY_LOADS = 1U << 6,
    HELPER_ENTITLEMENT_DEBUGGER = 1U << 7,
    HELPER_ENTITLEMENT_UNKNOWN_RUNTIME_EXCEPTION = 1U << 8,
    HELPER_ENTITLEMENT_MALFORMED = 1U << 9,
};

typedef struct helper_application_process {
    int32_t code_state;
    int32_t signature_class;
    int32_t security_status;
    int32_t system_error;
    int32_t app_bundle;
    int32_t hardened_runtime;
    int32_t linker_signed;
    uint32_t code_runtime_version;
    uint32_t dangerous_entitlements;
    int32_t pid;
    int32_t parent_pid;
    uint64_t start_seconds;
    uint64_t start_microseconds;
    char *path;
    char *display_name;
    char *signing_identifier;
    char *team_identifier;
    char *signer_name;
    unsigned char *designated_requirement;
    size_t designated_requirement_length;
    unsigned char *code_directory_hash;
    size_t code_directory_hash_length;
} helper_application_process;

void helper_application_process_free(helper_application_process *process);
int helper_validate_process_link(
    pid_t child_pid,
    pid_t expected_parent_pid,
    uint64_t start_seconds,
    uint64_t start_microseconds,
    uid_t expected_euid,
    int *system_error
);
int helper_peer_audit_token_at_path(
    int descriptor,
    uid_t expected_euid,
    const char *expected_path,
    size_t expected_path_length,
    audit_token_t *token,
    pid_t *peer_pid,
    int *system_error
);
int helper_peer_audit_token(
    int descriptor,
    uid_t expected_euid,
    audit_token_t *token,
    pid_t *peer_pid,
    int *system_error
);
int helper_inspect_process(
    pid_t pid,
    const audit_token_t *token,
    uid_t expected_euid,
    helper_application_process *process
);
int helper_inspect_static_transport_fd(
    int descriptor,
    helper_application_process *process
);

#endif
