import {
  ACTIVITY_MAX_RECORDS,
  AUDIT_MAX_RECORDS,
  AUDIT_RETENTION_MS,
  CLEANUP_BATCH_SIZE,
  OPERATIONAL_REQUEST_MAX_RECORDS,
  OPERATIONAL_REQUEST_RETENTION_MS,
  REQUESTER_ENROLLMENT_RECEIPT_MS,
  RETENTION_SWEEP_INTERVAL_MS,
  REVOKED_PWA_DEVICE_RETENTION_MS,
} from "./retention-policy.js";
import type { RetentionSweepStateRow } from "./approval-types.js";

const AUTHORIZATION_GRANT_MAX_STORAGE_MS = 365 * 24 * 60 * 60_000;
const EXECUTION_STALE_MS = 5 * 60_000;
const MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS = 3;

export interface ApprovalRetentionCallbacks {
  broadcastHumanEvent(type: string, entityId?: string): void;
  clearPendingPayload(requestId: string): void;
  recordTerminalActivity(requestId: string): boolean;
}

export class ApprovalRetention {
  constructor(
    private readonly storage: DurableObjectStorage,
    private readonly sql: SqlStorage,
    private readonly callbacks: ApprovalRetentionCallbacks,
  ) {}

  private first<T>(
    query: string,
    ...bindings: unknown[]
  ): T | undefined {
    return this.sql.exec(query, ...bindings).toArray()[0] as T | undefined;
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql.exec(query, ...bindings).toArray() as T[];
  }

  async scheduleNextAlarm(reconciliationRetryDelayMs: number): Promise<void> {
    const now = Date.now();
    const deadlines: number[] = [];
    const maintenance = this.first<{ next_retention_at: number }>(
      `SELECT next_retention_at FROM gateway_maintenance_state WHERE singleton = 1`,
    );
    deadlines.push(
      maintenance?.next_retention_at ?? now + RETENTION_SWEEP_INTERVAL_MS,
    );

    const requestDeadline = this.first<{ deadline: number | null }>(
      `SELECT MIN(deadline) AS deadline FROM (
         SELECT MIN(expires_at) AS deadline FROM requests WHERE status = 'pending'
         UNION ALL
         SELECT MIN(authorized_until) AS deadline FROM requests WHERE status = 'approved'
         UNION ALL
         SELECT MIN(execution_started_at + ?) AS deadline
           FROM requests WHERE status = 'executing'
       )`,
      EXECUTION_STALE_MS,
    )?.deadline;
    if (requestDeadline !== null && requestDeadline !== undefined) {
      deadlines.push(requestDeadline);
    }

    for (const query of [
      `SELECT MIN(expires_at) AS deadline FROM requester_enrollments WHERE status = 'pending'`,
      `SELECT MIN(expires_at) AS deadline FROM human_sessions`,
      `SELECT MIN(expires_at) AS deadline FROM requester_nonces`,
      `SELECT MIN(CASE WHEN used_at IS NULL THEN expires_at ELSE used_at + 60000 END)
         AS deadline FROM webauthn_challenges`,
      `SELECT MIN(CASE WHEN consumed_at IS NULL THEN expires_at ELSE consumed_at + 60000 END)
         AS deadline FROM bootstrap_sessions`,
      `SELECT MIN(terminal_at + 300000) AS deadline FROM requester_enrollments
         WHERE status != 'pending' AND terminal_at IS NOT NULL`,
      `SELECT MIN(terminal_at + 300000) AS deadline FROM human_device_enrollments
         WHERE status != 'pending' AND terminal_at IS NOT NULL`,
    ]) {
      const deadline = this.first<{ deadline: number | null }>(query)?.deadline;
      if (deadline !== null && deadline !== undefined) deadlines.push(deadline);
    }

    const reconciliationDeadline = this.first<{ deadline: number | null }>(
      `SELECT MIN(COALESCE(
         o.reconcile_attempted_at, r.execution_started_at, r.created_at
       ) + ?) AS deadline
       FROM requests r
       JOIN request_operations o ON o.request_id = r.id
       WHERE r.status = 'unknown'
         AND r.action IN ('item.create', 'item.patch', 'item.archive')
         AND o.reconcile_attempt_count < ?`,
      reconciliationRetryDelayMs,
      MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS,
    )?.deadline;
    if (
      reconciliationDeadline !== null &&
      reconciliationDeadline !== undefined
    ) {
      deadlines.push(reconciliationDeadline);
    }

    const target = Math.max(now + 1_000, Math.min(...deadlines));
    const current = await this.storage.getAlarm();
    if (current === null || Math.abs(current - target) > 1_000) {
      await this.storage.setAlarm(target);
    }
  }

  expireDueState(now: number): void {
    const dueRequests = this.rows<{ action: string; id: string; status: string }>(
      `SELECT id, action, status FROM requests
       WHERE (status = 'pending' AND expires_at <= ?)
          OR (status = 'approved' AND authorized_until <= ?)
          OR (status = 'executing' AND execution_started_at <= ?)
       ORDER BY COALESCE(execution_started_at, authorized_until, expires_at), id
       LIMIT ?`,
      now,
      now,
      now - EXECUTION_STALE_MS,
      CLEANUP_BATCH_SIZE,
    );
    this.storage.transactionSync(() => {
      for (const row of dueRequests) {
        if (row.status === "executing") {
          const uncertainMutation =
            row.action === "item.create" ||
            row.action === "item.patch" ||
            row.action === "item.archive";
          this.sql.exec(
            `UPDATE requests SET status = ?, error_code = ?
             WHERE id = ? AND status = 'executing'`,
            uncertainMutation ? "unknown" : "error",
            uncertainMutation
              ? "write_outcome_unknown"
              : "execution_outcome_unknown",
            row.id,
          );
          if (!uncertainMutation) this.callbacks.clearPendingPayload(row.id);
        } else {
          this.sql.exec(
            `UPDATE requests SET status = 'expired'
             WHERE id = ? AND status = ?`,
            row.id,
            row.status,
          );
          this.callbacks.clearPendingPayload(row.id);
        }
      }
    });
    for (const row of dueRequests) {
      if (row.status !== "executing" || row.action === "secret.read" || row.action === "ssh.sign") {
        this.callbacks.recordTerminalActivity(row.id);
      }
      this.callbacks.broadcastHumanEvent("request.changed", row.id);
    }

    const expiredRequesterEnrollments = this.rows<{ id: string }>(
      `UPDATE requester_enrollments
       SET status = 'expired', terminal_at = ?
       WHERE id IN (
         SELECT id FROM requester_enrollments
         WHERE status = 'pending' AND expires_at <= ?
         ORDER BY expires_at, id LIMIT ?
       ) RETURNING id`,
      now,
      now,
      CLEANUP_BATCH_SIZE,
    );
    for (const row of expiredRequesterEnrollments) {
      this.callbacks.broadcastHumanEvent("requester-enrollment.changed", row.id);
    }

    this.sql.exec(
      `DELETE FROM ssh_authorization_grants WHERE id IN (
         SELECT id FROM ssh_authorization_grants
         WHERE ((expires_at IS NOT NULL AND expires_at <= ?)
            OR revoked_at IS NOT NULL OR created_at <= ?)
           AND created_at <= ?
         ORDER BY created_at, id LIMIT ?
       )`,
      now,
      now - AUTHORIZATION_GRANT_MAX_STORAGE_MS,
      now - 24 * 60 * 60_000,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM secret_authorization_grants WHERE id IN (
         SELECT id FROM secret_authorization_grants
         WHERE ((expires_at IS NOT NULL AND expires_at <= ?)
            OR revoked_at IS NOT NULL OR created_at <= ?)
           AND created_at <= ?
         ORDER BY created_at, id LIMIT ?
       )`,
      now,
      now - AUTHORIZATION_GRANT_MAX_STORAGE_MS,
      now - 24 * 60 * 60_000,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM requester_nonces WHERE rowid IN (
         SELECT rowid FROM requester_nonces WHERE expires_at <= ?
         ORDER BY expires_at LIMIT ?
       )`,
      now,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM human_sessions WHERE token_hash IN (
         SELECT token_hash FROM human_sessions WHERE expires_at <= ?
         ORDER BY expires_at, token_hash LIMIT ?
       )`,
      now,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM bootstrap_sessions WHERE id IN (
         SELECT id FROM bootstrap_sessions
         WHERE expires_at <= ? OR (consumed_at IS NOT NULL AND consumed_at <= ?)
         ORDER BY expires_at, id LIMIT ?
       )`,
      now,
      now - 60_000,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM webauthn_challenges WHERE id IN (
         SELECT id FROM webauthn_challenges
         WHERE expires_at <= ? OR (used_at IS NOT NULL AND used_at <= ?)
         ORDER BY expires_at, id LIMIT ?
       )`,
      now,
      now - 60_000,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM requester_enrollments WHERE id IN (
         SELECT id FROM requester_enrollments
         WHERE status != 'pending' AND terminal_at <= ?
         ORDER BY terminal_at, id LIMIT ?
       )`,
      now - REQUESTER_ENROLLMENT_RECEIPT_MS,
      CLEANUP_BATCH_SIZE,
    );
    this.sql.exec(
      `DELETE FROM human_device_enrollments WHERE id IN (
         SELECT id FROM human_device_enrollments
         WHERE status != 'pending' AND terminal_at <= ?
         ORDER BY terminal_at, id LIMIT ?
       )`,
      now - REQUESTER_ENROLLMENT_RECEIPT_MS,
      CLEANUP_BATCH_SIZE,
    );
  }

  sweepDue(now: number): boolean {
    const state = this.first<{ next_retention_at: number }>(
      `SELECT next_retention_at FROM gateway_maintenance_state WHERE singleton = 1`,
    );
    return !state || state.next_retention_at <= now;
  }

  runSweep(now: number): void {
    const sweep = this.beginOrResumeRetentionSweep(now);
    const missingActivities = sweep.activity_backfill_done === 1
      ? []
      : this.rows<{ created_at: number; id: string }>(
          `SELECT r.created_at, r.id FROM requests r
           LEFT JOIN request_activity a ON a.request_id = r.id
           WHERE r.status IN ('rejected', 'expired', 'consumed', 'error')
             AND a.request_id IS NULL
             AND (? IS NULL OR r.created_at > ?
               OR (r.created_at = ? AND r.id > ?))
           ORDER BY r.created_at, r.id LIMIT ?`,
          sweep.activity_backfill_cursor_created_at,
          sweep.activity_backfill_cursor_created_at,
          sweep.activity_backfill_cursor_created_at,
          sweep.activity_backfill_cursor_id,
          CLEANUP_BATCH_SIZE,
        );
    const backfilledActivities: typeof missingActivities = [];
    let backfillAttempts = 0;
    let backfillFailed = false;
    for (const row of missingActivities) {
      backfillAttempts += 1;
      if (!this.callbacks.recordTerminalActivity(row.id)) {
        backfillFailed = true;
        break;
      }
      backfilledActivities.push(row);
    }
    const activityBackfillReady =
      sweep.activity_backfill_done === 1 ||
      (!backfillFailed && missingActivities.length < CLEANUP_BATCH_SIZE);

    const purgeRequests =
      sweep.request_trim_done === 1 || !activityBackfillReady
      ? []
      : this.rows<{ id: string }>(
          `SELECT r.id FROM requests r
           JOIN request_activity a ON a.request_id = r.id
           WHERE r.status IN ('rejected', 'expired', 'consumed', 'error')
             AND (
               a.terminal_at <= ?
               OR (? IS NOT NULL AND (
                 r.created_at < ? OR (r.created_at = ? AND r.id <= ?)
               ))
             )
           ORDER BY a.terminal_at, r.id LIMIT ?`,
          sweep.retention_started_at! - OPERATIONAL_REQUEST_RETENTION_MS,
          sweep.request_cutoff_created_at,
          sweep.request_cutoff_created_at,
          sweep.request_cutoff_created_at,
          sweep.request_cutoff_id,
          CLEANUP_BATCH_SIZE,
        );
    this.storage.transactionSync(() => {
      for (const row of purgeRequests) {
        this.sql.exec(`DELETE FROM request_operations WHERE request_id = ?`, row.id);
        this.sql.exec(`DELETE FROM request_secret_fields WHERE request_id = ?`, row.id);
        this.sql.exec(
          `DELETE FROM requests
           WHERE id = ? AND status IN ('rejected', 'expired', 'consumed', 'error')`,
          row.id,
        );
      }
    });

    const purgeAudit = sweep.audit_trim_done === 1
      ? []
      : this.rows<{ id: number }>(
          `SELECT id FROM gateway_audit
           WHERE created_at <= ?
              OR (? IS NOT NULL AND (
                created_at < ? OR (created_at = ? AND id <= ?)
              ))
           ORDER BY created_at, id LIMIT ?`,
          sweep.retention_started_at! - AUDIT_RETENTION_MS,
          sweep.audit_cutoff_created_at,
          sweep.audit_cutoff_created_at,
          sweep.audit_cutoff_created_at,
          sweep.audit_cutoff_id,
          CLEANUP_BATCH_SIZE,
        );
    for (const row of purgeAudit) {
      this.sql.exec(`DELETE FROM gateway_audit WHERE id = ?`, row.id);
    }

    const purgeDevices = this.rows<{ id: string }>(
      `SELECT id FROM human_devices
       WHERE revoked_at IS NOT NULL AND revoked_at <= ?
       ORDER BY revoked_at, id LIMIT ?`,
      now - REVOKED_PWA_DEVICE_RETENTION_MS,
      CLEANUP_BATCH_SIZE,
    );
    for (const row of purgeDevices) {
      this.sql.exec(`DELETE FROM human_devices WHERE id = ? AND revoked_at IS NOT NULL`, row.id);
    }

    const activityBudget = Math.max(0, CLEANUP_BATCH_SIZE - backfillAttempts);
    const requestTrimReady =
      sweep.request_trim_done === 1 ||
      (activityBackfillReady && purgeRequests.length < CLEANUP_BATCH_SIZE);
    const purgeActivities =
      sweep.activity_trim_done === 1 ||
      !requestTrimReady ||
      sweep.activity_cutoff_created_at === null ||
      activityBudget === 0
      ? []
      : this.rows<{ request_id: string }>(
          `SELECT request_id FROM request_activity
           WHERE ? IS NOT NULL AND (
             created_at < ? OR (created_at = ? AND request_id <= ?)
           )
           ORDER BY created_at, request_id LIMIT ?`,
          sweep.activity_cutoff_created_at,
          sweep.activity_cutoff_created_at,
          sweep.activity_cutoff_created_at,
          sweep.activity_cutoff_id,
          activityBudget,
        );
    for (const row of purgeActivities) {
      this.sql.exec(`DELETE FROM request_activity WHERE request_id = ?`, row.request_id);
    }

    const completedBackfill =
      sweep.activity_backfill_done === 0 &&
      !backfillFailed &&
      missingActivities.length < CLEANUP_BATCH_SIZE;
    const completedRequests =
      sweep.request_trim_done === 0 &&
      activityBackfillReady &&
      purgeRequests.length < CLEANUP_BATCH_SIZE;
    const completedAudit =
      sweep.audit_trim_done === 0 && purgeAudit.length < CLEANUP_BATCH_SIZE;
    const completedActivities =
      sweep.activity_trim_done === 0 &&
      requestTrimReady &&
      (sweep.activity_cutoff_created_at === null ||
        (activityBudget > 0 && purgeActivities.length < activityBudget));
    const backfillCursor = backfilledActivities.at(-1);
    if (
      completedBackfill ||
      completedRequests ||
      completedAudit ||
      completedActivities ||
      backfillCursor
    ) {
      this.sql.exec(
        `UPDATE gateway_maintenance_state SET
           activity_backfill_done = CASE WHEN ? = 1 THEN 1 ELSE activity_backfill_done END,
           activity_backfill_cursor_created_at = CASE
             WHEN ? = 1 THEN ? ELSE activity_backfill_cursor_created_at END,
           activity_backfill_cursor_id = CASE
             WHEN ? = 1 THEN ? ELSE activity_backfill_cursor_id END,
           request_trim_done = CASE WHEN ? = 1 THEN 1 ELSE request_trim_done END,
           audit_trim_done = CASE WHEN ? = 1 THEN 1 ELSE audit_trim_done END,
           activity_trim_done = CASE WHEN ? = 1 THEN 1 ELSE activity_trim_done END
         WHERE singleton = 1`,
        completedBackfill ? 1 : 0,
        backfillCursor ? 1 : 0,
        backfillCursor?.created_at ?? null,
        backfillCursor ? 1 : 0,
        backfillCursor?.id ?? null,
        completedRequests ? 1 : 0,
        completedAudit ? 1 : 0,
        completedActivities ? 1 : 0,
      );
    }

    const backlog =
      backfillFailed ||
      (sweep.activity_backfill_done === 0 &&
        missingActivities.length === CLEANUP_BATCH_SIZE) ||
      (sweep.request_trim_done === 0 &&
        purgeRequests.length === CLEANUP_BATCH_SIZE) ||
      (sweep.audit_trim_done === 0 && purgeAudit.length === CLEANUP_BATCH_SIZE) ||
      purgeDevices.length === CLEANUP_BATCH_SIZE ||
      (sweep.activity_trim_done === 0 &&
        requestTrimReady &&
        sweep.activity_cutoff_created_at !== null &&
        purgeActivities.length === activityBudget && activityBudget > 0);
    if (backlog) {
      this.sql.exec(
        `UPDATE gateway_maintenance_state SET next_retention_at = ?
         WHERE singleton = 1`,
        now + 60_000,
      );
      return;
    }
    this.sql.exec(
      `UPDATE gateway_maintenance_state
       SET next_retention_at = ?, retention_active = 0,
           retention_started_at = NULL,
           activity_backfill_done = 0, request_trim_done = 0,
           audit_trim_done = 0, activity_trim_done = 0,
           activity_backfill_cursor_created_at = NULL,
           activity_backfill_cursor_id = NULL,
           request_cutoff_created_at = NULL, request_cutoff_id = NULL,
           audit_cutoff_created_at = NULL, audit_cutoff_id = NULL,
           activity_cutoff_created_at = NULL, activity_cutoff_id = NULL
       WHERE singleton = 1`,
      now + RETENTION_SWEEP_INTERVAL_MS,
    );
  }

  private beginOrResumeRetentionSweep(now: number): RetentionSweepStateRow {
    const existing = this.first<RetentionSweepStateRow>(
      `SELECT retention_active, retention_started_at,
              activity_backfill_done, request_trim_done, audit_trim_done,
              activity_trim_done,
              activity_backfill_cursor_created_at,
              activity_backfill_cursor_id,
              request_cutoff_created_at, request_cutoff_id,
              audit_cutoff_created_at, audit_cutoff_id,
              activity_cutoff_created_at, activity_cutoff_id
       FROM gateway_maintenance_state WHERE singleton = 1`,
    );
    if (!existing) throw new Error("gateway_maintenance_state_missing");
    if (existing.retention_active === 1 && existing.retention_started_at !== null) {
      return existing;
    }

    const requestCutoff = this.first<{ created_at: number; id: string }>(
      `SELECT created_at, id FROM requests
       WHERE status IN ('rejected', 'expired', 'consumed', 'error')
       ORDER BY created_at DESC, id DESC LIMIT 1 OFFSET ?`,
      OPERATIONAL_REQUEST_MAX_RECORDS,
    );
    const auditCutoff = this.first<{ created_at: number; id: number }>(
      `SELECT created_at, id FROM gateway_audit
       ORDER BY created_at DESC, id DESC LIMIT 1 OFFSET ?`,
      AUDIT_MAX_RECORDS,
    );
    const activityCutoff = this.first<{ created_at: number; request_id: string }>(
      `SELECT created_at, request_id FROM request_activity
       ORDER BY created_at DESC, request_id DESC LIMIT 1 OFFSET ?`,
      ACTIVITY_MAX_RECORDS,
    );
    this.sql.exec(
      `UPDATE gateway_maintenance_state
       SET retention_active = 1, retention_started_at = ?,
           activity_backfill_done = 0, request_trim_done = 0,
           audit_trim_done = 0, activity_trim_done = 0,
           activity_backfill_cursor_created_at = NULL,
           activity_backfill_cursor_id = NULL,
           request_cutoff_created_at = ?, request_cutoff_id = ?,
           audit_cutoff_created_at = ?, audit_cutoff_id = ?,
           activity_cutoff_created_at = ?, activity_cutoff_id = ?
       WHERE singleton = 1`,
      now,
      requestCutoff?.created_at ?? null,
      requestCutoff?.id ?? null,
      auditCutoff?.created_at ?? null,
      auditCutoff?.id ?? null,
      activityCutoff?.created_at ?? null,
      activityCutoff?.request_id ?? null,
    );
    return {
      activity_backfill_done: 0,
      activity_backfill_cursor_created_at: null,
      activity_backfill_cursor_id: null,
      activity_cutoff_created_at: activityCutoff?.created_at ?? null,
      activity_cutoff_id: activityCutoff?.request_id ?? null,
      activity_trim_done: 0,
      audit_cutoff_created_at: auditCutoff?.created_at ?? null,
      audit_cutoff_id: auditCutoff?.id ?? null,
      audit_trim_done: 0,
      request_cutoff_created_at: requestCutoff?.created_at ?? null,
      request_cutoff_id: requestCutoff?.id ?? null,
      request_trim_done: 0,
      retention_active: 1,
      retention_started_at: now,
    };
  }
}
