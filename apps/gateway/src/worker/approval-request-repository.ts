import type { ApplicationIdentityColumns } from "./approval-types.js";

export interface RequestInsertRecord extends ApplicationIdentityColumns {
  action: string;
  application_scope_id: string | null;
  authorized_until: number | null;
  body_hash: string;
  client_application: string;
  client_source: string;
  consumed_at: number | null;
  created_at: number;
  decided_at: number | null;
  error_code: string | null;
  execution_started_at: number | null;
  expected_version: number;
  expires_at: number;
  field_id: string;
  field_label: string;
  field_type: string;
  id: string;
  idempotency_key: string;
  item_id: string;
  item_title: string;
  requester_device_id: string;
  requester_name: string;
  secret_grant_id: string | null;
  ssh_agent_instance_public_key: string | null;
  ssh_grant_id: string | null;
  ssh_scope_id: string | null;
  ssh_scope_kind: string | null;
  status: string;
}

export interface RequestInsertSql {
  exec(query: string, ...bindings: unknown[]): unknown;
}

export function insertRequest(
  sql: RequestInsertSql,
  record: RequestInsertRecord,
): void {
  sql.exec(
    `INSERT INTO requests
      (id, requester_device_id, requester_name, action, item_id, field_id,
       expected_version, client_application, client_source,
       application_assurance, application_principal_scheme,
       application_principal_id, application_signing_identifier,
       application_team_identifier, application_signer_name,
       application_scope_id, secret_grant_id, ssh_agent_instance_public_key,
       ssh_scope_id, ssh_scope_kind, ssh_grant_id, item_title, field_label,
       field_type, idempotency_key, body_hash, status, created_at, expires_at,
       decided_at, authorized_until, execution_started_at, consumed_at,
       error_code)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
             ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    record.id,
    record.requester_device_id,
    record.requester_name,
    record.action,
    record.item_id,
    record.field_id,
    record.expected_version,
    record.client_application,
    record.client_source,
    record.application_assurance,
    record.application_principal_scheme,
    record.application_principal_id,
    record.application_signing_identifier,
    record.application_team_identifier,
    record.application_signer_name,
    record.application_scope_id,
    record.secret_grant_id,
    record.ssh_agent_instance_public_key,
    record.ssh_scope_id,
    record.ssh_scope_kind,
    record.ssh_grant_id,
    record.item_title,
    record.field_label,
    record.field_type,
    record.idempotency_key,
    record.body_hash,
    record.status,
    record.created_at,
    record.expires_at,
    record.decided_at,
    record.authorized_until,
    record.execution_started_at,
    record.consumed_at,
    record.error_code,
  );
}
