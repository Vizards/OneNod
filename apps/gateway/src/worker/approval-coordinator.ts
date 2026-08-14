import { DurableObject } from "cloudflare:workers";
import {
  resolveGatewayKeySentinel,
  type GatewayKeySentinelState,
  type GatewayKeySentinelStore,
} from "./gateway-key-sentinel.js";
import { initializeApprovalSchema } from "./approval-schema.js";
import { ApprovalRetention } from "./approval-retention.js";
import {
  GatewayHttpError,
  classifyStorageError,
  decrementCount,
  errorResponse,
  incrementCount,
  json,
  safeErrorName,
} from "./approval-http.js";
import { ApprovalRequestStore } from "./approval-request-store.js";
import { ApprovalRequestAdmission } from "./approval-request-admission.js";
import { ApprovalReview } from "./approval-review.js";
import { ApprovalExecutor } from "./approval-executor.js";
import { ApprovalExecution } from "./approval-execution.js";
import { ApprovalNotifications } from "./approval-notifications.js";
import { HumanAccess } from "./human-access.js";
import { HumanManagement } from "./human-management.js";
import { RequesterAccess } from "./requester-access.js";
import { RequesterAuthenticationError } from "./requester-auth.js";
import { storagePressure } from "./retention-policy.js";
import type { RequestCreationReservation } from "./approval-types.js";

declare const RECONCILIATION_RETRY_DELAY_MS: number;

const MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS = 3;
const REQUEST_CREATE_RATE_WINDOW_MS = 60_000;
const REQUEST_CREATE_RATE_MAX = 60;
const REMEMBERED_SECRET_READ_RATE_MAX = 30;
const REMEMBERED_SSH_SIGN_RATE_MAX = 30;
const REQUESTER_ENROLLMENT_RATE_WINDOW_MS = 5 * 60_000;
const REQUESTER_ENROLLMENT_RATE_MAX = 20;
const GATEWAY_CRYPTO_STATE_PATH = "/internal/gateway/crypto-state";
export class ApprovalCoordinator extends DurableObject<Env> {
  private readonly executor: ApprovalExecutor;
  private readonly execution: ApprovalExecution;
  private readonly human: HumanAccess;
  private readonly humanManagement: HumanManagement;
  private readonly notifications: ApprovalNotifications;
  private readonly requestStore: ApprovalRequestStore;
  private readonly requestAdmission: ApprovalRequestAdmission;
  private readonly review: ApprovalReview;
  private readonly requester: RequesterAccess;
  private gatewayKeySentinelState!: GatewayKeySentinelState;
  private approvalReservationsGlobal = 0;
  private readonly approvalReservationsByRequester = new Map<string, number>();
  private mutationReservations = 0;
  private readonly requestCreationReservations = new Map<string, number>();
  private readonly rememberedSecretCreationReservations = new Map<string, number>();
  private readonly rememberedSshCreationReservations = new Map<string, number>();
  private storageWarningReported = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.executor = new ApprovalExecutor(env);
    this.requestStore = new ApprovalRequestStore(ctx.storage);
    this.human = new HumanAccess(ctx, env, {
      audit: (event, requestId, actorId) =>
        this.audit(event, requestId, actorId),
      broadcastHumanEvent: (type, entityId) =>
        this.notifications.broadcastHumanEvent(type, entityId),
      recordTerminalActivity: (requestId) =>
        this.requestStore.recordTerminalActivity(requestId),
    });
    this.notifications = new ApprovalNotifications(ctx, env, this.human, {
      audit: (event, requestId, actorId) =>
        this.audit(event, requestId, actorId),
    });
    this.humanManagement = new HumanManagement(
      ctx,
      env,
      this.human,
      this.notifications,
      this.requestStore,
      {
        assertStorageGrowthAllowed: () => this.assertStorageGrowthAllowed(),
        audit: (event, requestId, actorId) =>
          this.audit(event, requestId, actorId),
      },
    );
    this.review = new ApprovalReview(
      ctx,
      env,
      this.human,
      this.notifications,
      this.requestStore,
      {
        audit: (event, requestId, actorId) =>
          this.audit(event, requestId, actorId),
      },
    );
    this.requester = new RequesterAccess(
      ctx,
      env,
      this.human,
      this.humanManagement,
      this.notifications,
      {
        assertRequesterEnrollmentRate: () =>
          this.assertRequesterEnrollmentRate(),
        assertStorageGrowthAllowed: () => this.assertStorageGrowthAllowed(),
        audit: (event, requestId, actorId) =>
          this.audit(event, requestId, actorId),
        decisionOptions: (kind, targetId, decision) =>
          this.review.decisionOptions(kind, targetId, decision),
      },
    );
    this.requestAdmission = new ApprovalRequestAdmission(
      ctx,
      env,
      this.executor,
      this.human,
      this.notifications,
      this.requester,
      this.requestStore,
      {
        assertRememberedSecretReadRate: (deviceId, grantId) =>
          this.assertRememberedSecretReadRate(deviceId, grantId),
        assertRememberedSshSignRate: (deviceId, grantId) =>
          this.assertRememberedSshSignRate(deviceId, grantId),
        assertStorageGrowthAllowed: () => this.assertStorageGrowthAllowed(),
        audit: (event, requestId, actorId) =>
          this.audit(event, requestId, actorId),
        releaseRequestCreationRate: (reservation) =>
          this.releaseRequestCreationRate(reservation),
        reserveNewApproval: (deviceId, mutation) =>
          this.reserveNewApproval(deviceId, mutation),
        reserveRequestCreationRate: (deviceId, body) =>
          this.reserveRequestCreationRate(deviceId, body),
      },
    );
    this.execution = new ApprovalExecution(
      ctx,
      env,
      this.executor,
      this.human,
      this.requestStore,
      {
        audit: (event, requestId, actorId) =>
          this.audit(event, requestId, actorId),
        authenticateSignedRequest: (request, path, body) =>
          this.requester.authenticateSignedRequest(request, path, body),
        broadcastHumanEvent: (type, entityId) =>
          this.notifications.broadcastHumanEvent(type, entityId),
        requestPollingToken: (requestId, requesterDeviceId) =>
          this.requester.requestPollingToken(requestId, requesterDeviceId),
        scheduleNextAlarm: () => this.scheduleNextAlarm(),
      },
    );
    this.ctx.blockConcurrencyWhile(async () => {
      initializeApprovalSchema(this.ctx.storage, this.sql);
      this.gatewayKeySentinelState = await resolveGatewayKeySentinel({
        masterKey: this.env.GATEWAY_MASTER_KEY,
        store: this.gatewayKeySentinelStore(),
      });
    });
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const readOnlyRequest =
      request.method === "GET" &&
      (url.pathname === "/v1/requester-self" ||
        /^\/v1\/requests\/[^/]+\/status$/u.test(url.pathname));
    try {
      if (
        request.method === "GET" &&
        url.pathname === GATEWAY_CRYPTO_STATE_PATH
      ) {
        return json({
          initialized: this.gatewayKeySentinelState.initialized,
          matches: this.gatewayKeySentinelState.matches,
        });
      }
      this.requireGatewayKeySentinel();
      try {
        return await this.route(request);
      } finally {
        if (!readOnlyRequest) {
          this.ctx.waitUntil(this.scheduleNextAlarm());
        }
      }
    } catch (error) {
      if (error instanceof GatewayHttpError) {
        if (error.status >= 500) {
          console.error(
            JSON.stringify({
              code: error.code,
              event: "approval_coordinator_http_error",
              status: error.status,
            }),
          );
        }
        return errorResponse(error.code, error.status);
      }
      if (error instanceof RequesterAuthenticationError) {
        const status =
          error.code === "requester_not_found"
            ? 401
            : error.code === "request_replayed"
              ? 409
              : 401;
        return errorResponse(error.code, status);
      }
      if (classifyStorageError(error) === "full") {
        return errorResponse("storage_pressure", 507);
      }
      console.error(
        JSON.stringify({
          errorName: safeErrorName(error),
          event: "approval_coordinator_failed",
        }),
      );
      return errorResponse("internal_error", 500);
    }
  }

  override async alarm(): Promise<void> {
    if (!this.gatewayKeySentinelReady()) {
      console.error(
        JSON.stringify({
          event: "gateway_key_sentinel_alarm_blocked",
          initialized: this.gatewayKeySentinelState.initialized,
          matches: this.gatewayKeySentinelState.matches,
        }),
      );
      return;
    }
    try {
      const now = Date.now();
      const retention = new ApprovalRetention(this.ctx.storage, this.sql, {
        broadcastHumanEvent: (type, entityId) =>
          this.notifications.broadcastHumanEvent(type, entityId),
        clearPendingPayload: (requestId) =>
          this.requestStore.clearPendingPayload(requestId),
        recordTerminalActivity: (requestId) =>
          this.requestStore.recordTerminalActivity(requestId),
      });
      retention.expireDueState(now);
      if (retention.sweepDue(now)) {
        retention.runSweep(now);
      }
      const candidate = this.first<{ id: string }>(
        `SELECT r.id
         FROM requests r
         JOIN request_operations o ON o.request_id = r.id
         WHERE r.status = 'unknown'
           AND r.action IN ('item.create', 'item.patch', 'item.archive')
           AND o.reconcile_attempt_count < ?
         ORDER BY COALESCE(o.reconcile_attempted_at, 0), r.created_at
         LIMIT 1`,
        MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS,
      );
      if (candidate) {
        const row = this.requestStore.requestRow(candidate.id);
        await this.execution.tryReconcileUnknownMutation(
          row,
          row.requester_device_id,
          0,
        );
      }
    } catch (error) {
      console.error(
        JSON.stringify({
          errorName: safeErrorName(error),
          event: "request_reconcile_alarm_failed",
        }),
      );
    } finally {
      await this.scheduleNextAlarm();
    }
  }

  override async webSocketMessage(
    socket: WebSocket,
    message: string | ArrayBuffer,
  ): Promise<void> {
    if (!this.gatewayKeySentinelReady()) {
      this.notifications.safeCloseSocket(
        socket,
        1011,
        "gateway_crypto_unavailable",
      );
      return;
    }
    this.notifications.webSocketMessage(socket, message);
  }

  override webSocketClose(): void {
    // Cloudflare calls this handler after the closing handshake has completed.
    // Calling close() again can throw and unnecessarily restart the Durable Object.
  }

  override webSocketError(socket: WebSocket): void {
    this.notifications.safeCloseSocket(socket, 1011, "socket_error");
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/authorize"
    ) {
      return this.human.authorizeBootstrap(request);
    }
    if (request.method === "GET" && path === "/v1/human/state") {
      return this.human.humanState(request);
    }
    if (request.method === "POST" && path === "/v1/human/lock") {
      return this.human.lockGateway(request);
    }
    if (request.method === "POST" && path === "/v1/human/unlock/options") {
      return this.human.gatewayUnlockOptions(request);
    }
    if (request.method === "POST" && path === "/v1/human/unlock/verify") {
      return this.human.gatewayUnlockVerify(request);
    }
    if (request.method === "GET" && path === "/v1/human/events") {
      return this.notifications.humanEvents(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/registration/options"
    ) {
      return this.human.bootstrapOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/registration/verify"
    ) {
      return this.human.bootstrapVerify(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/session/options"
    ) {
      return this.human.humanSessionOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/session/verify"
    ) {
      return this.human.humanSessionVerify(request);
    }
    if (request.method === "GET" && path === "/v1/human/management") {
      return this.humanManagement.humanManagement(request);
    }
    if (request.method === "GET" && path === "/v1/human/onepassword-quota") {
      await this.human.requireHumanSession(request);
      return json(await this.executor.executeServiceAccountQuota());
    }
    if (
      request.method === "GET" &&
      path === "/v1/human/authorizations/summary"
    ) {
      return this.humanManagement.authorizationSummary(request);
    }
    const sshGrantRevoke = path.match(
      /^\/v1\/human\/ssh-authorizations\/([^/]+)$/u,
    );
    if (request.method === "DELETE" && sshGrantRevoke) {
      return this.humanManagement.revokeSshAuthorization(
        request,
        decodeURIComponent(sshGrantRevoke[1]!),
      );
    }
    const secretGrantRevoke = path.match(
      /^\/v1\/human\/secret-authorizations\/([^/]+)$/u,
    );
    if (request.method === "DELETE" && secretGrantRevoke) {
      return this.humanManagement.revokeSecretAuthorization(
        request,
        decodeURIComponent(secretGrantRevoke[1]!),
      );
    }
    if (request.method === "GET" && path === "/v1/human/push/config") {
      return this.notifications.pushConfig(request);
    }
    if (request.method === "PUT" && path === "/v1/human/push/subscription") {
      return this.notifications.putPushSubscription(request);
    }
    if (request.method === "DELETE" && path === "/v1/human/push/subscription") {
      return this.notifications.deletePushSubscription(request);
    }
    if (request.method === "POST" && path === "/v1/human/devices/registration/options") {
      return this.humanManagement.deviceRegistrationOptions(request);
    }
    if (request.method === "POST" && path === "/v1/human/devices/registration/verify") {
      return this.humanManagement.deviceRegistrationVerify(request);
    }
    const deviceRevokeOptions = path.match(
      /^\/v1\/human\/devices\/([^/]+)\/revoke\/options$/u,
    );
    if (request.method === "POST" && deviceRevokeOptions) {
      return this.humanManagement.deviceRevokeOptions(
        request,
        decodeURIComponent(deviceRevokeOptions[1]!),
      );
    }
    const deviceRevokeVerify = path.match(
      /^\/v1\/human\/devices\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && deviceRevokeVerify) {
      return this.humanManagement.deviceRevokeVerify(
        request,
        decodeURIComponent(deviceRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/options"
    ) {
      return this.humanManagement.credentialRegistrationAuthorizationOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/authorize"
    ) {
      return this.humanManagement.credentialRegistrationAuthorizationVerify(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/verify"
    ) {
      return this.humanManagement.credentialRegistrationVerify(request);
    }
    const credentialRevokeOptions = path.match(
      /^\/v1\/human\/credentials\/([^/]+)\/revoke\/options$/u,
    );
    if (request.method === "POST" && credentialRevokeOptions) {
      return this.humanManagement.credentialRevokeOptions(
        request,
        decodeURIComponent(credentialRevokeOptions[1]!),
      );
    }
    const credentialRevokeVerify = path.match(
      /^\/v1\/human\/credentials\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && credentialRevokeVerify) {
      return this.humanManagement.credentialRevokeVerify(
        request,
        decodeURIComponent(credentialRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/requester-enrollments"
    ) {
      return this.requester.createRequesterEnrollment(request);
    }
    if (request.method === "GET" && path === "/v1/requester-self") {
      return this.requester.requesterSelf(request);
    }
    const enrollmentStatus = path.match(
      /^\/v1\/requester-enrollments\/([^/]+)$/u,
    );
    if (request.method === "GET" && enrollmentStatus) {
      return this.requester.requesterEnrollmentStatus(
        decodeURIComponent(enrollmentStatus[1]!),
      );
    }
    if (
      request.method === "GET" &&
      path === "/v1/human/requester-enrollments"
    ) {
      return this.requester.humanRequesterEnrollments(request);
    }
    const humanEnrollmentOptions = path.match(
      /^\/v1\/human\/requester-enrollments\/([^/]+)\/options$/u,
    );
    if (request.method === "POST" && humanEnrollmentOptions) {
      return this.requester.requesterEnrollmentDecisionOptions(
        request,
        decodeURIComponent(humanEnrollmentOptions[1]!),
      );
    }
    const humanEnrollmentVerify = path.match(
      /^\/v1\/human\/requester-enrollments\/([^/]+)\/verify$/u,
    );
    if (request.method === "POST" && humanEnrollmentVerify) {
      return this.requester.requesterEnrollmentDecisionVerify(
        request,
        decodeURIComponent(humanEnrollmentVerify[1]!),
      );
    }
    const requesterRevokeOptions = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/revoke\/options$/u,
    );
    const requesterRenameOptions = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/rename\/options$/u,
    );
    if (request.method === "POST" && requesterRenameOptions) {
      return this.requester.requesterRenameOptions(
        request,
        decodeURIComponent(requesterRenameOptions[1]!),
      );
    }
    const requesterRenameVerify = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/rename\/verify$/u,
    );
    if (request.method === "POST" && requesterRenameVerify) {
      return this.requester.requesterRenameVerify(
        request,
        decodeURIComponent(requesterRenameVerify[1]!),
      );
    }
    if (request.method === "POST" && requesterRevokeOptions) {
      return this.requester.requesterRevokeOptions(
        request,
        decodeURIComponent(requesterRevokeOptions[1]!),
      );
    }
    const requesterRevokeVerify = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && requesterRevokeVerify) {
      return this.requester.requesterRevokeVerify(
        request,
        decodeURIComponent(requesterRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/catalog/search"
    ) {
      return this.requestAdmission.catalogSearch(request, path);
    }
    if (request.method === "POST" && path === "/v1/requests") {
      return this.requestAdmission.createApprovalRequest(request, path);
    }
    const requesterStatus = path.match(
      /^\/v1\/requests\/([^/]+)\/status$/u,
    );
    if (request.method === "GET" && requesterStatus) {
      return this.requestAdmission.requesterRequestStatus(
        request,
        decodeURIComponent(requesterStatus[1]!),
      );
    }
    const requesterConsume = path.match(
      /^\/v1\/requests\/([^/]+)\/consume$/u,
    );
    if (request.method === "POST" && requesterConsume) {
      return this.execution.consumeApprovalRequest(
        request,
        path,
        decodeURIComponent(requesterConsume[1]!),
      );
    }
    if (request.method === "GET" && path === "/v1/human/requests") {
      return this.review.humanRequests(request);
    }
    const humanRequest = path.match(/^\/v1\/human\/requests\/([^/]+)$/u);
    if (request.method === "GET" && humanRequest) {
      return this.review.humanRequestDetail(
        request,
        decodeURIComponent(humanRequest[1]!),
      );
    }
    const approvalOptions = path.match(
      /^\/v1\/human\/approvals\/([^/]+)\/options$/u,
    );
    if (request.method === "POST" && approvalOptions) {
      return this.review.approvalOptions(
        request,
        decodeURIComponent(approvalOptions[1]!),
      );
    }
    const approvalVerify = path.match(
      /^\/v1\/human\/approvals\/([^/]+)\/verify$/u,
    );
    if (request.method === "POST" && approvalVerify) {
      return this.review.approvalVerify(
        request,
        decodeURIComponent(approvalVerify[1]!),
      );
    }
    return errorResponse("not_found", 404);
  }

  private async scheduleNextAlarm(): Promise<void> {
    const retention = new ApprovalRetention(this.ctx.storage, this.sql, {
      broadcastHumanEvent: (type, entityId) =>
        this.notifications.broadcastHumanEvent(type, entityId),
      clearPendingPayload: (requestId) =>
        this.requestStore.clearPendingPayload(requestId),
      recordTerminalActivity: (requestId) =>
        this.requestStore.recordTerminalActivity(requestId),
    });
    await retention.scheduleNextAlarm(RECONCILIATION_RETRY_DELAY_MS);
  }

  private gatewayKeySentinelReady(): boolean {
    return this.gatewayKeySentinelState.matches;
  }

  private requireGatewayKeySentinel(): void {
    if (this.gatewayKeySentinelReady()) return;
    const code =
      this.gatewayKeySentinelState.reason === "missing_key"
        ? "gateway_master_key_not_configured"
        : this.gatewayKeySentinelState.reason === "invalid_key"
          ? "gateway_master_key_invalid"
          : "gateway_master_key_mismatch";
    throw new GatewayHttpError(code, 503);
  }

  private gatewayKeySentinelStore(): GatewayKeySentinelStore {
    return {
      claimIfSafe: (record) => {
        let claimed = false;
        this.ctx.storage.transactionSync(() => {
          if (
            this.readGatewayKeySentinel() ||
            this.hasEncryptedPendingPayloads()
          ) {
            return;
          }
          this.sql.exec(
            `INSERT INTO gateway_crypto_state
              (singleton, generation, master_key_fingerprint, initialized_at)
             VALUES (1, ?, ?, ?)`,
            record.generation,
            record.fingerprint,
            Date.now(),
          );
          claimed = true;
        });
        return claimed;
      },
      hasEncryptedPayloads: () => this.hasEncryptedPendingPayloads(),
      read: () => this.readGatewayKeySentinel(),
    };
  }

  private hasEncryptedPendingPayloads(): boolean {
    return Boolean(
      this.first<{ request_id: string }>(
        `SELECT request_id FROM request_operations
         WHERE payload_aad IS NOT NULL
            OR payload_ciphertext IS NOT NULL
            OR payload_digest IS NOT NULL
            OR payload_iv IS NOT NULL
         LIMIT 1`,
      ),
    );
  }

  private readGatewayKeySentinel():
    | { fingerprint: string; generation: number }
    | undefined {
    return this.first<{ fingerprint: string; generation: number }>(
      `SELECT generation, master_key_fingerprint AS fingerprint
       FROM gateway_crypto_state WHERE singleton = 1`,
    );
  }

  private assertStorageGrowthAllowed(): void {
    const pressure = storagePressure(this.sql.databaseSize);
    if (pressure === "critical") {
      throw new GatewayHttpError("storage_pressure", 507);
    }
    if (pressure === "warning" && !this.storageWarningReported) {
      this.storageWarningReported = true;
      console.warn(
        JSON.stringify({
          databaseSize: this.sql.databaseSize,
          event: "gateway_storage_pressure",
          level: "warning",
        }),
      );
    }
  }

  private assertRequesterEnrollmentRate(): void {
    const recent = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requester_enrollments
       WHERE created_at >= ?`,
      Date.now() - REQUESTER_ENROLLMENT_RATE_WINDOW_MS,
    )?.count ?? 0;
    if (recent >= REQUESTER_ENROLLMENT_RATE_MAX) {
      throw new GatewayHttpError("enrollment_rate_limited", 429);
    }
  }

  private reserveRequestCreationRate(
    requesterDeviceId: string,
    body: unknown,
  ): RequestCreationReservation | undefined {
    const input = body as Record<string, unknown>;
    const idempotencyKey = input.idempotency_key;
    if (
      typeof idempotencyKey === "string" &&
      idempotencyKey.length <= 128 &&
      this.first<{ id: string }>(
        `SELECT id FROM requests
         WHERE requester_device_id = ? AND idempotency_key = ? LIMIT 1`,
        requesterDeviceId,
        idempotencyKey,
      )
    ) {
      return undefined;
    }
    const recent = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requests
       WHERE requester_device_id = ? AND created_at >= ?`,
      requesterDeviceId,
      Date.now() - REQUEST_CREATE_RATE_WINDOW_MS,
    )?.count ?? 0;
    const reserved = this.requestCreationReservations.get(requesterDeviceId) ?? 0;
    if (recent + reserved >= REQUEST_CREATE_RATE_MAX) {
      throw new GatewayHttpError("request_rate_limited", 429);
    }
    const rememberedSsh = Boolean(
      input.action === "ssh.sign" &&
      input.authorization_session &&
      typeof input.authorization_session === "object"
    );
    const rememberedSecret = Boolean(
      input.action === "secret.read" &&
      input.authorization_scope &&
      typeof input.authorization_scope === "object"
    );
    if (rememberedSecret) {
      const remembered = this.first<{ count: number }>(
        `SELECT COUNT(*) AS count FROM requests
         WHERE requester_device_id = ? AND action = 'secret.read'
           AND secret_grant_id IS NOT NULL AND created_at >= ?`,
        requesterDeviceId,
        Date.now() - REQUEST_CREATE_RATE_WINDOW_MS,
      )?.count ?? 0;
      const rememberedReserved =
        this.rememberedSecretCreationReservations.get(requesterDeviceId) ?? 0;
      if (remembered + rememberedReserved >= REMEMBERED_SECRET_READ_RATE_MAX) {
        throw new GatewayHttpError("secret_read_rate_limited", 429);
      }
    }
    if (rememberedSsh) {
      const remembered = this.first<{ count: number }>(
        `SELECT COUNT(*) AS count FROM requests
         WHERE requester_device_id = ? AND action = 'ssh.sign'
           AND ssh_grant_id IS NOT NULL AND created_at >= ?`,
        requesterDeviceId,
        Date.now() - REQUEST_CREATE_RATE_WINDOW_MS,
      )?.count ?? 0;
      const rememberedReserved =
        this.rememberedSshCreationReservations.get(requesterDeviceId) ?? 0;
      if (remembered + rememberedReserved >= REMEMBERED_SSH_SIGN_RATE_MAX) {
        throw new GatewayHttpError("ssh_sign_rate_limited", 429);
      }
    }
    incrementCount(this.requestCreationReservations, requesterDeviceId);
    if (rememberedSecret) {
      incrementCount(this.rememberedSecretCreationReservations, requesterDeviceId);
    }
    if (rememberedSsh) {
      incrementCount(this.rememberedSshCreationReservations, requesterDeviceId);
    }
    return { rememberedSecret, rememberedSsh, requesterDeviceId };
  }

  private releaseRequestCreationRate(
    reservation: RequestCreationReservation,
  ): void {
    decrementCount(this.requestCreationReservations, reservation.requesterDeviceId);
    if (reservation.rememberedSecret) {
      decrementCount(
        this.rememberedSecretCreationReservations,
        reservation.requesterDeviceId,
      );
    }
    if (reservation.rememberedSsh) {
      decrementCount(
        this.rememberedSshCreationReservations,
        reservation.requesterDeviceId,
      );
    }
  }

  private assertRememberedSecretReadRate(
    requesterDeviceId: string,
    grantId: string,
  ): void {
    const recent = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requests
       WHERE requester_device_id = ? AND secret_grant_id = ?
         AND created_at >= ?`,
      requesterDeviceId,
      grantId,
      Date.now() - REQUEST_CREATE_RATE_WINDOW_MS,
    )?.count ?? 0;
    if (recent >= REMEMBERED_SECRET_READ_RATE_MAX) {
      throw new GatewayHttpError("secret_read_rate_limited", 429);
    }
  }

  private assertRememberedSshSignRate(
    requesterDeviceId: string,
    grantId: string,
  ): void {
    const recent = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requests
       WHERE requester_device_id = ? AND ssh_grant_id = ?
         AND created_at >= ?`,
      requesterDeviceId,
      grantId,
      Date.now() - REQUEST_CREATE_RATE_WINDOW_MS,
    )?.count ?? 0;
    if (recent >= REMEMBERED_SSH_SIGN_RATE_MAX) {
      throw new GatewayHttpError("ssh_sign_rate_limited", 429);
    }
  }

  private reserveNewApproval(
    requesterDeviceId: string,
    mutation: boolean,
  ): () => void {
    const globalPending = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requests
       WHERE status IN ('pending', 'approved')`,
    )?.count ?? 0;
    if (globalPending + this.approvalReservationsGlobal >= 100) {
      throw new GatewayHttpError("approval_capacity", 429);
    }
    const requesterPending = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requests
       WHERE requester_device_id = ? AND status IN ('pending', 'approved')`,
      requesterDeviceId,
    )?.count ?? 0;
    const requesterReserved =
      this.approvalReservationsByRequester.get(requesterDeviceId) ?? 0;
    if (requesterPending + requesterReserved >= 20) {
      throw new GatewayHttpError("approval_capacity", 429);
    }
    if (mutation) {
      const mutationActive = this.first<{ count: number }>(
        `SELECT COUNT(*) AS count FROM requests
         WHERE action IN ('item.create', 'item.patch', 'item.archive')
           AND status IN ('pending', 'approved', 'executing', 'unknown')`,
      )?.count ?? 0;
      if (mutationActive + this.mutationReservations >= 20) {
        throw new GatewayHttpError("mutation_reconciliation_capacity", 429);
      }
    }

    this.approvalReservationsGlobal += 1;
    incrementCount(this.approvalReservationsByRequester, requesterDeviceId);
    if (mutation) this.mutationReservations += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.approvalReservationsGlobal = Math.max(
        0,
        this.approvalReservationsGlobal - 1,
      );
      decrementCount(this.approvalReservationsByRequester, requesterDeviceId);
      if (mutation) {
        this.mutationReservations = Math.max(0, this.mutationReservations - 1);
      }
    };
  }

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
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

  private audit(
    event: string,
    requestId?: string,
    actorId?: string,
  ): void {
    try {
      this.sql.exec(
        `INSERT INTO gateway_audit (event, request_id, actor_id, created_at)
         VALUES (?, ?, ?, ?)`,
        event,
        requestId ?? null,
        actorId ?? null,
        Date.now(),
      );
    } catch (error) {
      if (classifyStorageError(error) !== "full") throw error;
      console.warn(JSON.stringify({ event: "gateway_audit_dropped", reason: "storage_full" }));
    }
  }

}
