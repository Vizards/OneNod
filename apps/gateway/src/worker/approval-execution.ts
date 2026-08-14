import type {
  ItemMutationExecutorResult,
  ItemReconciliationExecutorResult,
  SecretReadExecutorResult,
  SshSignExecutorResult,
} from "./gateway-envelope.js";
import {
  ACTIVE_SECRET_GRANT_CONSUME_PREDICATE,
  ACTIVE_SSH_GRANT_CONSUME_PREDICATE,
  incrementRememberedGrantUse,
} from "./authorization-grants.js";
import {
  GatewayHttpError,
  assertExactKeys,
  isUncertainWriteFailure,
  json,
  readJsonObject,
} from "./approval-http.js";
import type { RequestOperationRow, RequestRow } from "./approval-types.js";
import { ApprovalExecutor } from "./approval-executor.js";
import { ApprovalRequestStore } from "./approval-request-store.js";
import { HumanAccess } from "./human-access.js";
import { requestPollingAuthorizationAccepted } from "./legacy-consume-bridge.js";
import { decryptPendingPayload } from "./pending-payload.js";
import type { RequesterIdentity } from "./requester-auth.js";

declare const RECONCILIATION_IMMEDIATE_ENABLED: boolean;
const MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS = 3;

export interface ApprovalExecutionCallbacks {
  audit(event: string, requestId?: string, actorId?: string): void;
  authenticateSignedRequest(
    request: Request,
    path: string,
    body: unknown,
  ): Promise<RequesterIdentity>;
  broadcastHumanEvent(type: string, entityId?: string): void;
  requestPollingToken(requestId: string, requesterDeviceId: string): Promise<string>;
  scheduleNextAlarm(): Promise<void>;
}

export class ApprovalExecution {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly executor: ApprovalExecutor,
    private readonly human: HumanAccess,
    private readonly requestStore: ApprovalRequestStore,
    private readonly callbacks: ApprovalExecutionCallbacks,
  ) {}

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql
      .exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  async consumeApprovalRequest(
    request: Request,
    path: string,
    requestId: string,
  ): Promise<Response> {
    const body = await readJsonObject(request);
    assertExactKeys(body, []);
    const requester = await this.callbacks.authenticateSignedRequest(
      request,
      path,
      body,
    );
    if (this.human.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
    const row = this.requestStore.requestRow(requestId);
    if (row.requester_device_id !== requester.deviceId) {
      throw new GatewayHttpError("request_not_found", 404);
    }
    const expectedPollingToken = await this.callbacks.requestPollingToken(
      requestId,
      requester.deviceId,
    );
    const authorizationHeader = request.headers.get("authorization");
    if (!requestPollingAuthorizationAccepted({
      action: row.action,
      authorizationHeader,
      expectedToken: expectedPollingToken,
      legacySshSignedConsume: row.legacy_ssh_signed_consume,
      secretGrantId: row.secret_grant_id,
      sshGrantId: row.ssh_grant_id,
    })) {
      throw new GatewayHttpError("request_not_found", 404);
    }
    if (authorizationHeader === null) {
      this.callbacks.audit(
        "legacy_bearerless_ssh_consume",
        requestId,
        requester.deviceId,
      );
    }
    if (row.action === "ssh.sign") {
      return this.consumeSshSign(row, requester);
    }
    if (row.action !== "secret.read") {
      return this.consumeItemMutation(row, requester);
    }
    const now = Date.now();
    const updated = this.rows<{ id: string }>(
      `UPDATE requests SET status = 'executing', execution_started_at = ?
       WHERE id = ? AND requester_device_id = ? AND status = 'approved'
         AND authorized_until > ?
         AND ${ACTIVE_SECRET_GRANT_CONSUME_PREDICATE}
       RETURNING id`,
      now,
      requestId,
      requester.deviceId,
      now,
      now,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("authorization_not_consumable", 409);
    }
    this.callbacks.audit("request_execution_started", requestId, requester.deviceId);
    this.callbacks.broadcastHumanEvent("request.changed", requestId);

    let result: SecretReadExecutorResult;
    try {
      result = await this.executor.executeSecretRead(row);
    } catch (error) {
      const code =
        error instanceof GatewayHttpError ? error.code : "executor_unavailable";
      this.sql.exec(
        `UPDATE requests SET status = 'error', error_code = ?
         WHERE id = ? AND status = 'executing'`,
        code,
        requestId,
      );
      this.requestStore.recordTerminalActivity(requestId);
      this.callbacks.audit("request_execution_failed", requestId, code);
      this.callbacks.broadcastHumanEvent("request.changed", requestId);
      throw error;
    }

    const consumedAt = Date.now();
    this.ctx.storage.transactionSync(() => {
      const consumed = this.rows<{ id: string }>(
        `UPDATE requests
         SET status = 'consumed', consumed_at = ?, error_code = NULL
         WHERE id = ? AND status = 'executing'
         RETURNING id`,
        consumedAt,
        requestId,
      );
      if (consumed.length !== 1) {
        throw new GatewayHttpError("execution_state_conflict", 409);
      }
      if (row.secret_grant_id) {
        if (!incrementRememberedGrantUse(this.sql, "secret", row.secret_grant_id)) {
          throw new GatewayHttpError("execution_state_conflict", 409);
        }
      }
      this.callbacks.audit("request_consumed", requestId, requester.deviceId);
    });
    this.requestStore.recordTerminalActivity(requestId);
    this.callbacks.broadcastHumanEvent("request.changed", requestId);
    return json({
      ok: true,
      request_id: requestId,
      status: "consumed",
      value: result.value,
    });
  }

  async consumeItemMutation(
    row: RequestRow,
    requester: RequesterIdentity,
  ): Promise<Response> {
    if (
      row.action !== "item.create" &&
      row.action !== "item.patch" &&
      row.action !== "item.archive"
    ) {
      throw new GatewayHttpError("unsupported_action", 400);
    }
    const now = Date.now();
    const updated = this.rows<{ id: string }>(
      `UPDATE requests SET status = 'executing', execution_started_at = ?
       WHERE id = ? AND requester_device_id = ? AND status = 'approved'
         AND authorized_until > ?
       RETURNING id`,
      now,
      row.id,
      requester.deviceId,
      now,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("authorization_not_consumable", 409);
    }
    this.callbacks.audit("request_execution_started", row.id, requester.deviceId);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);

    const operation = this.requestStore.requestOperation(row.id);
    let executorBody: Record<string, unknown>;
    try {
      executorBody = await this.readMutationExecutorBody(row, operation);
    } catch {
      this.failMutation(row.id, "pending_payload_unavailable");
      throw new GatewayHttpError("pending_payload_unavailable", 500);
    }

    try {
      const result = await this.executor.executeItemMutation(row, executorBody);
      return this.completeMutation(row, requester.deviceId, result);
    } catch (error) {
      const code = error instanceof GatewayHttpError
        ? error.code
        : "executor_unavailable";
      if (!isUncertainWriteFailure(code)) {
        this.failMutation(row.id, code);
        throw error;
      }
      this.sql.exec(
        `UPDATE requests SET status = 'unknown', error_code = 'write_outcome_unknown'
         WHERE id = ? AND status = 'executing'`,
        row.id,
      );
      this.sql.exec(
        `UPDATE request_operations SET reconcile_state = 'UNKNOWN'
         WHERE request_id = ?`,
        row.id,
      );
      this.callbacks.audit("request_execution_unknown", row.id, code);
      this.callbacks.broadcastHumanEvent("request.changed", row.id);
    }

    if (!RECONCILIATION_IMMEDIATE_ENABLED) {
      this.ctx.waitUntil(this.callbacks.scheduleNextAlarm());
      return json(
        { ok: true, request_id: row.id, status: "unknown" },
        202,
      );
    }

    let reconciliation: ItemReconciliationExecutorResult;
    try {
      this.recordReconciliationAttempt(row.id);
      reconciliation = await this.executor.reconcileItemMutation(row, executorBody);
    } catch (error) {
      this.callbacks.audit(
        "request_reconcile_deferred",
        row.id,
        error instanceof GatewayHttpError ? error.code : "executor_unavailable",
      );
      this.ctx.waitUntil(this.callbacks.scheduleNextAlarm());
      return json(
        { ok: true, request_id: row.id, status: "unknown" },
        202,
      );
    }
    this.sql.exec(
      `UPDATE request_operations
       SET reconcile_state = ?, result_item_id = ?, result_version = ?
       WHERE request_id = ?`,
      reconciliation.reconciliation,
      reconciliation.item_id ?? null,
      reconciliation.version ?? null,
      row.id,
    );
    if (reconciliation.reconciliation === "APPLIED") {
      if (!reconciliation.item_id) {
        this.failMutation(row.id, "executor_untrusted_response");
        throw new GatewayHttpError("executor_untrusted_response", 502);
      }
      return this.completeMutation(row, requester.deviceId, {
        item_id: reconciliation.item_id,
        ...(reconciliation.version === undefined
          ? {}
          : { version: reconciliation.version }),
      });
    }
    if (reconciliation.reconciliation === "NOT_APPLIED") {
      this.failMutation(row.id, "write_not_applied");
      throw new GatewayHttpError("write_not_applied", 502);
    }
    this.sql.exec(
      `UPDATE requests SET error_code = 'write_outcome_ambiguous'
       WHERE id = ? AND status = 'unknown'`,
      row.id,
    );
    this.callbacks.audit("request_reconcile_ambiguous", row.id, requester.deviceId);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);
    this.ctx.waitUntil(this.callbacks.scheduleNextAlarm());
    return json({ ok: true, request_id: row.id, status: "unknown" }, 202);
  }

  async consumeSshSign(
    row: RequestRow,
    requester: RequesterIdentity,
  ): Promise<Response> {
    const now = Date.now();
    const updated = this.rows<{ id: string }>(
      `UPDATE requests SET status = 'executing', execution_started_at = ?
       WHERE id = ? AND requester_device_id = ? AND status = 'approved'
         AND authorized_until > ? AND action = 'ssh.sign'
         AND ${ACTIVE_SSH_GRANT_CONSUME_PREDICATE}
       RETURNING id`,
      now,
      row.id,
      requester.deviceId,
      now,
      now,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("authorization_not_consumable", 409);
    }
    this.callbacks.audit("request_execution_started", row.id, requester.deviceId);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);

    let executorBody: Record<string, unknown>;
    try {
      executorBody = await this.readSshSignExecutorBody(
        row,
        this.requestStore.requestOperation(row.id),
      );
    } catch {
      this.failMutation(row.id, "pending_payload_unavailable");
      throw new GatewayHttpError("pending_payload_unavailable", 500);
    }

    let result: SshSignExecutorResult;
    try {
      result = await this.executor.executeSshSign(row, executorBody);
    } catch (error) {
      const code =
        error instanceof GatewayHttpError ? error.code : "executor_unavailable";
      this.failMutation(row.id, code);
      throw error;
    }
    this.ctx.storage.transactionSync(() => {
      const consumed = this.rows<{ id: string }>(
        `UPDATE requests
         SET status = 'consumed', consumed_at = ?, error_code = NULL
         WHERE id = ? AND status = 'executing'
         RETURNING id`,
        Date.now(),
        row.id,
      );
      if (consumed.length !== 1) {
        throw new GatewayHttpError("execution_state_conflict", 409);
      }
      if (row.ssh_grant_id) {
        if (!incrementRememberedGrantUse(this.sql, "ssh", row.ssh_grant_id)) {
          throw new GatewayHttpError("execution_state_conflict", 409);
        }
      }
      this.requestStore.clearPendingPayload(row.id);
      this.callbacks.audit("request_consumed", row.id, requester.deviceId);
    });
    this.requestStore.recordTerminalActivity(row.id);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);
    return json({
      algorithm: result.algorithm,
      fingerprint: result.fingerprint,
      item_id: result.item_id,
      ok: true,
      public_key_blob: result.public_key_blob,
      request_id: row.id,
      signature_blob: result.signature_blob,
      status: "consumed",
      version: result.version,
    });
  }

  async tryReconcileUnknownMutation(
    row: RequestRow,
    actorId: string,
    minimumDelayMs: number,
  ): Promise<void> {
    if (
      row.status !== "unknown" ||
      (row.action !== "item.create" &&
        row.action !== "item.patch" &&
        row.action !== "item.archive")
    ) {
      return;
    }
    const operation = this.requestStore.requestOperation(row.id);
    if (
      operation.reconcile_attempt_count >=
      MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS
    ) {
      this.callbacks.audit("request_reconcile_limit_reached", row.id, actorId);
      return;
    }
    if (
      operation.reconcile_attempted_at !== null &&
      operation.reconcile_attempted_at > Date.now() - minimumDelayMs
    ) {
      return;
    }
    this.recordReconciliationAttempt(row.id);
    let executorBody: Record<string, unknown>;
    try {
      executorBody = await this.readMutationExecutorBody(row, operation);
    } catch {
      this.callbacks.audit("request_reconcile_deferred", row.id, "pending_payload_unavailable");
      return;
    }
    let reconciliation: ItemReconciliationExecutorResult;
    try {
      reconciliation = await this.executor.reconcileItemMutation(row, executorBody);
    } catch (error) {
      this.callbacks.audit(
        "request_reconcile_deferred",
        row.id,
        error instanceof GatewayHttpError ? error.code : "executor_unavailable",
      );
      return;
    }
    this.sql.exec(
      `UPDATE request_operations
       SET reconcile_state = ?, result_item_id = ?, result_version = ?
       WHERE request_id = ?`,
      reconciliation.reconciliation,
      reconciliation.item_id ?? null,
      reconciliation.version ?? null,
      row.id,
    );
    if (reconciliation.reconciliation === "APPLIED") {
      if (!reconciliation.item_id) {
        this.failMutation(row.id, "executor_untrusted_response");
        return;
      }
      this.completeMutation(row, actorId, {
        item_id: reconciliation.item_id,
        ...(reconciliation.version === undefined
          ? {}
          : { version: reconciliation.version }),
      });
      return;
    }
    if (reconciliation.reconciliation === "NOT_APPLIED") {
      this.failMutation(row.id, "write_not_applied");
      return;
    }
    this.sql.exec(
      `UPDATE requests SET error_code = 'write_outcome_ambiguous'
       WHERE id = ? AND status = 'unknown'`,
      row.id,
    );
    this.callbacks.audit("request_reconcile_ambiguous", row.id, actorId);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);
  }

  recordReconciliationAttempt(requestId: string): void {
    this.sql.exec(
      `UPDATE request_operations
       SET reconcile_attempt_count = reconcile_attempt_count + 1,
           reconcile_attempted_at = ?
       WHERE request_id = ?`,
      Date.now(),
      requestId,
    );
  }

  async readMutationExecutorBody(
    row: RequestRow,
    operation: RequestOperationRow,
  ): Promise<Record<string, unknown>> {
    if (row.action === "item.archive") {
      return {
        action: "item.archive",
        expected_version: row.expected_version,
        item_id: row.item_id,
      };
    }
    if (
      !this.env.GATEWAY_MASTER_KEY ||
      !operation.payload_aad ||
      !operation.payload_ciphertext ||
      !operation.payload_digest ||
      !operation.payload_iv ||
      (row.action !== "item.create" && row.action !== "item.patch")
    ) {
      throw new Error("pending_payload_unavailable");
    }
    const value = await decryptPendingPayload(
      this.env.GATEWAY_MASTER_KEY,
      {
        action: row.action,
        environment: this.env.APP_ENV,
        expiresAt: row.expires_at,
        requestId: row.id,
        requesterDeviceId: row.requester_device_id,
      },
      {
        aad: operation.payload_aad,
        ciphertext: operation.payload_ciphertext,
        digest: operation.payload_digest,
        iv: operation.payload_iv,
      },
    );
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("pending_payload_invalid");
    }
    return value as Record<string, unknown>;
  }

  async readSshSignExecutorBody(
    row: RequestRow,
    operation: RequestOperationRow,
  ): Promise<Record<string, unknown>> {
    if (
      row.action !== "ssh.sign" ||
      !this.env.GATEWAY_MASTER_KEY ||
      !operation.payload_aad ||
      !operation.payload_ciphertext ||
      !operation.payload_digest ||
      !operation.payload_iv
    ) {
      throw new Error("pending_payload_unavailable");
    }
    const value = await decryptPendingPayload(
      this.env.GATEWAY_MASTER_KEY,
      {
        action: "ssh.sign",
        environment: this.env.APP_ENV,
        expiresAt: row.expires_at,
        requestId: row.id,
        requesterDeviceId: row.requester_device_id,
      },
      {
        aad: operation.payload_aad,
        ciphertext: operation.payload_ciphertext,
        digest: operation.payload_digest,
        iv: operation.payload_iv,
      },
    );
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("pending_payload_invalid");
    }
    return value as Record<string, unknown>;
  }

  completeMutation(
    row: RequestRow,
    actorId: string,
    result: ItemMutationExecutorResult,
  ): Response {
    const consumedAt = Date.now();
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE requests
         SET status = 'consumed', consumed_at = ?, error_code = NULL
         WHERE id = ? AND status IN ('executing', 'unknown')
         RETURNING id`,
        consumedAt,
        row.id,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("execution_state_conflict", 409);
      }
      this.sql.exec(
        `UPDATE request_operations
         SET payload_aad = NULL, payload_ciphertext = NULL, payload_digest = NULL,
             payload_iv = NULL,
             result_item_id = ?, result_version = ?
         WHERE request_id = ?`,
        result.item_id,
        result.version ?? null,
        row.id,
      );
      this.callbacks.audit("request_consumed", row.id, actorId);
    });
    this.executor.invalidateCatalogMetadata(row.item_id, result.item_id);
    this.requestStore.recordTerminalActivity(row.id);
    this.callbacks.broadcastHumanEvent("request.changed", row.id);
    return json({
      item_id: result.item_id,
      ok: true,
      request_id: row.id,
      status: "consumed",
      ...(result.version === undefined ? {} : { version: result.version }),
    });
  }

  failMutation(requestId: string, code: string): void {
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `UPDATE requests SET status = 'error', error_code = ?
         WHERE id = ? AND status IN ('executing', 'unknown')`,
        code,
        requestId,
      );
      this.sql.exec(
        `UPDATE request_operations
         SET payload_aad = NULL, payload_ciphertext = NULL, payload_digest = NULL,
             payload_iv = NULL
         WHERE request_id = ?`,
        requestId,
      );
      this.callbacks.audit("request_execution_failed", requestId, code);
    });
    this.requestStore.recordTerminalActivity(requestId);
    this.callbacks.broadcastHumanEvent("request.changed", requestId);
  }
}
