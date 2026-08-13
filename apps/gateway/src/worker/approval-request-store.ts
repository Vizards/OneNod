import {
  GatewayHttpError,
  safeErrorName,
} from "./approval-http.js";
import type {
  RequestActivityRow,
  RequestOperationRow,
  RequestRow,
} from "./approval-types.js";

export class ApprovalRequestStore {
  constructor(private readonly storage: DurableObjectStorage) {}

  private get sql(): SqlStorage {
    return this.storage.sql;
  }

  private first<T>(
    query: string,
    ...bindings: unknown[]
  ): T | undefined {
    return this.rows<T>(query, ...bindings)[0];
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql
      .exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  clearPendingPayload(requestId: string): void {
    this.sql.exec(
      `UPDATE request_operations
       SET payload_aad = NULL, payload_ciphertext = NULL, payload_digest = NULL,
           payload_iv = NULL
       WHERE request_id = ?`,
      requestId,
    );
  }

  requestRow(id: string): RequestRow {
    const row = this.findRequestRow(id);
    if (!row) throw new GatewayHttpError("request_not_found", 404);
    if (row.status === "pending" && row.expires_at <= Date.now()) {
      this.sql.exec(
        `UPDATE requests SET status = 'expired'
         WHERE id = ? AND status = 'pending'`,
        id,
      );
      this.clearPendingPayload(id);
      this.recordTerminalActivity(id);
      row.status = "expired";
    }
    if (
      row.status === "approved" &&
      (row.authorized_until ?? 0) <= Date.now()
    ) {
      this.sql.exec(
        `UPDATE requests SET status = 'expired'
         WHERE id = ? AND status = 'approved'`,
        id,
      );
      this.clearPendingPayload(id);
      this.recordTerminalActivity(id);
      row.status = "expired";
    }
    return row;
  }

  findRequestRow(id: string): RequestRow | undefined {
    return this.first<RequestRow>(
      `SELECT id, requester_device_id, requester_name, action,
              client_application, client_source, application_assurance,
              application_principal_scheme, application_principal_id,
              application_signing_identifier, application_team_identifier,
              application_signer_name,
              application_scope_id, secret_grant_id,
              ssh_agent_instance_public_key, ssh_scope_id, ssh_scope_kind,
              ssh_grant_id, item_id, field_id, expected_version,
              item_title, field_label, field_type,
              (SELECT operation_summary FROM request_operations o
               WHERE o.request_id = requests.id) AS operation_summary,
              status, created_at, expires_at, decided_at, authorized_until,
              execution_started_at, consumed_at, error_code
       FROM requests WHERE id = ?`,
      id,
    );
  }

  requestActivityRow(requestId: string): RequestActivityRow | undefined {
    return this.first<RequestActivityRow>(
      `SELECT request_id, action, status, created_at, terminal_at, expires_at,
              decided_at, consumed_at, item_title, field_label,
              expected_version, requester_name, client_application,
              client_source, application_assurance,
              application_principal_scheme, application_principal_id,
              application_signing_identifier, application_team_identifier,
              application_signer_name, error_code
       FROM request_activity WHERE request_id = ?`,
      requestId,
    );
  }

  recordTerminalActivity(requestId: string): boolean {
    try {
      this.sql.exec(
        `INSERT INTO request_activity
          (request_id, action, status, created_at, terminal_at, expires_at,
           decided_at, consumed_at, item_title, field_label, expected_version,
           requester_name, client_application, client_source,
           application_assurance, application_principal_scheme,
           application_principal_id, application_signing_identifier,
           application_team_identifier, application_signer_name, error_code)
         SELECT id, action, status, created_at, ?, expires_at, decided_at,
                consumed_at, item_title, field_label, expected_version,
                requester_name, client_application, client_source,
                application_assurance, application_principal_scheme,
                application_principal_id, application_signing_identifier,
                application_team_identifier, application_signer_name, error_code
         FROM requests
         WHERE id = ? AND status IN ('rejected', 'expired', 'consumed', 'error')
         ON CONFLICT(request_id) DO UPDATE SET
           status = excluded.status,
           terminal_at = excluded.terminal_at,
           decided_at = excluded.decided_at,
           consumed_at = excluded.consumed_at,
           application_assurance = excluded.application_assurance,
           application_principal_scheme = excluded.application_principal_scheme,
           application_principal_id = excluded.application_principal_id,
           application_signing_identifier = excluded.application_signing_identifier,
           application_team_identifier = excluded.application_team_identifier,
           application_signer_name = excluded.application_signer_name,
           error_code = excluded.error_code`,
        Date.now(),
        requestId,
      );
      return true;
    } catch (error) {
      console.error(
        JSON.stringify({
          errorName: safeErrorName(error),
          event: "request_activity_projection_failed",
          requestId,
        }),
      );
      return false;
    }
  }

  requestOperation(requestId: string): RequestOperationRow {
    const row = this.first<RequestOperationRow>(
      `SELECT request_id, operation_summary, payload_aad, payload_ciphertext,
              payload_digest, payload_iv, reconcile_state,
              reconcile_attempt_count, reconcile_attempted_at, result_item_id,
              result_version
       FROM request_operations WHERE request_id = ?`,
      requestId,
    );
    if (!row) throw new GatewayHttpError("request_operation_not_found", 500);
    return row;
  }
}
