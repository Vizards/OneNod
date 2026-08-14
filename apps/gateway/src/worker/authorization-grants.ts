// These predicates are shared by the consume paths and their SQLite tests.
// A remembered grant is authority, not just request metadata: revoking or
// expiring it must make every not-yet-started request non-consumable.
export const ACTIVE_SECRET_GRANT_CONSUME_PREDICATE = `(
  requests.secret_grant_id IS NULL OR EXISTS (
    SELECT 1
    FROM secret_authorization_grants grant
    JOIN gateway_runtime_state runtime ON runtime.singleton = 1
    WHERE grant.id = requests.secret_grant_id
      AND grant.requester_device_id = requests.requester_device_id
      AND grant.scope_id = requests.application_scope_id
      AND grant.item_id = requests.item_id
      AND grant.field_id = requests.field_id
      AND grant.item_version = requests.expected_version
      AND grant.revoked_at IS NULL
      AND (grant.expires_at IS NULL OR grant.expires_at > ?)
      AND runtime.locked = 0
      AND (
        grant.duration != 'until-lock' OR
        grant.lock_generation = runtime.lock_generation
      )
  )
)`;

export const ACTIVE_SSH_GRANT_CONSUME_PREDICATE = `(
  requests.ssh_grant_id IS NULL OR EXISTS (
    SELECT 1
    FROM ssh_authorization_grants grant
    JOIN gateway_runtime_state runtime ON runtime.singleton = 1
    WHERE grant.id = requests.ssh_grant_id
      AND grant.requester_device_id = requests.requester_device_id
      AND grant.agent_instance_public_key = requests.ssh_agent_instance_public_key
      AND grant.scope_id = requests.ssh_scope_id
      AND grant.scope_kind = requests.ssh_scope_kind
      AND grant.item_id = requests.item_id
      AND grant.item_version = requests.expected_version
      AND grant.fingerprint = requests.field_label
      AND grant.revoked_at IS NULL
      AND (grant.expires_at IS NULL OR grant.expires_at > ?)
      AND runtime.locked = 0
      AND (
        grant.duration != 'until-lock' OR
        grant.lock_generation = runtime.lock_generation
      )
  )
)`;

// The create paths use these predicates to turn a matching remembered grant
// into an automatically approved request. Keep them beside the consume
// predicates so both admission and execution are exercised by the same
// lifecycle tests.
export const ACTIVE_SECRET_GRANT_LOOKUP_PREDICATE = `
  requester_device_id = ?
  AND scope_id = ?
  AND application_principal_scheme = 'macos-designated-requirement-v1'
  AND item_id = ?
  AND field_id = ?
  AND item_version = ?
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > ?)
  AND (duration != 'until-lock' OR lock_generation = ?)`;

export const ACTIVE_SSH_GRANT_LOOKUP_PREDICATE = `
  requester_device_id = ?
  AND agent_instance_public_key = ?
  AND scope_id = ?
  AND scope_kind = ?
  AND application_principal_scheme = 'macos-designated-requirement-v1'
  AND item_id = ?
  AND item_version = ?
  AND fingerprint = ?
  AND revoked_at IS NULL
  AND (expires_at IS NULL OR expires_at > ?)
  AND (duration != 'until-lock' OR lock_generation = ?)`;

export function rejectQueuedRequestsForGrantSql(
  kind: "secret" | "ssh",
): string {
  const grantColumn = kind === "secret" ? "secret_grant_id" : "ssh_grant_id";
  return `UPDATE requests
    SET status = 'rejected', decided_at = ?, authorized_until = NULL,
        error_code = 'authorization_revoked'
    WHERE ${grantColumn} = ? AND status IN ('pending', 'approved')
    RETURNING id`;
}

export const REJECT_QUEUED_REQUESTS_FOR_CREDENTIAL_SQL = `UPDATE requests
  SET status = 'rejected', decided_at = ?, authorized_until = NULL,
      error_code = 'authorization_revoked'
  WHERE status IN ('pending', 'approved')
    AND (
      secret_grant_id IN (
        SELECT id FROM secret_authorization_grants
        WHERE authorized_by_credential_id = ?
      ) OR ssh_grant_id IN (
        SELECT id FROM ssh_authorization_grants
        WHERE authorized_by_credential_id = ?
      )
    )
  RETURNING id`;

export const REJECT_QUEUED_REQUESTS_FOR_REQUESTER_SQL = `UPDATE requests
  SET status = 'rejected', decided_at = ?, authorized_until = NULL,
      error_code = 'requester_revoked'
  WHERE requester_device_id = ? AND status IN ('pending', 'approved')
  RETURNING id`;

export function incrementRememberedGrantUse(
  sql: {
    exec(query: string, ...bindings: unknown[]): {
      toArray(): Record<string, unknown>[];
    };
  },
  kind: "secret" | "ssh",
  grantId: string,
): boolean {
  const table = kind === "secret"
    ? "secret_authorization_grants"
    : "ssh_authorization_grants";
  return sql
    .exec(
      `UPDATE ${table} SET use_count = use_count + 1
       WHERE id = ? RETURNING id`,
      grantId,
    )
    .toArray().length === 1;
}

export function rememberedAuthorizationDurationAvailable(input: {
  action: string;
  applicationAssurance: string;
  applicationPrincipalId: string | null;
  applicationPrincipalScheme: string | null;
  applicationScopeId: string | null;
  applicationSigningIdentifier: string | null;
  decision: string;
  duration: string;
  sshAgentInstancePublicKey: string | null;
  sshScopeId: string | null;
  sshScopeKind: string | null;
}): boolean {
  if (
    input.decision !== "approve" ||
    input.applicationAssurance !== "verified-code-signature" ||
    input.applicationPrincipalScheme !== "macos-designated-requirement-v1" ||
    !input.applicationPrincipalId ||
    !input.applicationSigningIdentifier
  ) {
    return false;
  }
  if (input.action === "secret.read") {
    return input.applicationScopeId === input.applicationPrincipalId &&
      input.duration !== "until-agent-quits";
  }
  if (input.action === "ssh.sign") {
    return Boolean(
      input.sshAgentInstancePublicKey &&
      input.sshScopeId === input.applicationPrincipalId &&
      input.sshScopeKind === "application",
    );
  }
  return false;
}
