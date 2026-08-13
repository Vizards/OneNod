import {
  requesterPublicKeyFingerprint,
  type ApprovalDecision,
  type RequesterEnrollmentRequest,
} from "@onenod/protocol";

import {
  GatewayHttpError,
  iso,
  json,
  parseJsonObject,
  readChallengeVerifyBody,
  readDecisionBody,
  readDecisionVerifyBody,
  readJsonObject,
  safeBase64Url,
  safeDeviceId,
  safeText,
} from "./approval-http.js";
import { ApprovalNotifications } from "./approval-notifications.js";
import { projectEnrollment } from "./approval-projection.js";
import type { EnrollmentRow } from "./approval-types.js";
import { HumanAccess } from "./human-access.js";
import { HumanManagement } from "./human-management.js";
import { deriveRequestPollingToken } from "./request-polling.js";
import {
  RequesterAuthenticationError,
  STORE_ACTIVE_REQUESTER_NONCE_SQL,
  authenticateRequester,
  authenticateRequesterSelf,
  type RequesterIdentity,
} from "./requester-auth.js";

const ENROLLMENT_TTL_MS = 10 * 60_000;

export interface RequesterAccessCallbacks {
  assertRequesterEnrollmentRate(): void;
  assertStorageGrowthAllowed(): void;
  audit(event: string, requestId?: string, actorId?: string): void;
  decisionOptions(
    kind: "requester_enrollment",
    targetId: string,
    decision: ApprovalDecision,
  ): Promise<Response>;
}

/** Requester enrollment, lifecycle administration, and signed identity checks. */
export class RequesterAccess {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly human: HumanAccess,
    private readonly humanManagement: HumanManagement,
    private readonly notifications: ApprovalNotifications,
    private readonly callbacks: RequesterAccessCallbacks,
  ) {}

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private first<T>(query: string, ...bindings: unknown[]): T | undefined {
    return this.rows<T>(query, ...bindings)[0];
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql
      .exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  async createRequesterEnrollment(
    request: Request,
  ): Promise<Response> {
    if (!this.human.hasHumanCredential()) {
      throw new GatewayHttpError("not_initialized", 409);
    }
    const body = await readJsonObject<RequesterEnrollmentRequest>(request);
    const deviceId = safeDeviceId(body.device_id);
    const displayName = safeText(body.display_name, 80);
    const publicKey = safeBase64Url(body.public_key, 32, "public_key");
    const publicKeyFingerprint =
      await requesterPublicKeyFingerprint(publicKey);
    this.human.assertGatewayUnlocked();
    const requester = this.first<{
      display_name: string;
      public_key: string;
      revoked_at: number | null;
    }>(
      `SELECT display_name, public_key, revoked_at FROM requesters
       WHERE device_id = ?`,
      deviceId,
    );
    if (requester) {
      if (requester.revoked_at !== null) {
        throw new GatewayHttpError("requester_revoked", 409);
      }
      if (requester.public_key !== publicKey) {
        throw new GatewayHttpError("device_id_conflict", 409);
      }
      return json({
        already_enrolled: true,
        device_id: deviceId,
        display_name: requester.display_name,
        public_key_fingerprint: publicKeyFingerprint,
        status: "approved",
      });
    }
    const existing = this.first<EnrollmentRow>(
      `SELECT id, device_id, display_name, public_key, public_key_fingerprint,
              status, created_at, expires_at
       FROM requester_enrollments
       WHERE device_id = ? AND status = 'pending' AND expires_at > ?
       ORDER BY created_at DESC LIMIT 1`,
      deviceId,
      Date.now(),
    );
    if (existing) {
      if (
        existing.public_key !== publicKey ||
        existing.display_name !== displayName
      ) {
        throw new GatewayHttpError("enrollment_conflict", 409);
      }
      return json(
        {
          enrollment_id: existing.id,
          expires_at: iso(existing.expires_at),
          public_key_fingerprint: existing.public_key_fingerprint,
          status: "pending",
        },
        202,
      );
    }
    this.callbacks.assertStorageGrowthAllowed();
    this.callbacks.assertRequesterEnrollmentRate();
    const pending = this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM requester_enrollments
       WHERE status = 'pending' AND expires_at > ?`,
      Date.now(),
    )?.count;
    if ((pending ?? 0) >= 20) {
      throw new GatewayHttpError("enrollment_capacity", 429);
    }
    const id = crypto.randomUUID();
    const now = Date.now();
    const expiresAt = now + ENROLLMENT_TTL_MS;
    this.sql.exec(
      `INSERT INTO requester_enrollments
        (id, device_id, display_name, public_key, public_key_fingerprint,
         status, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`,
      id,
      deviceId,
      displayName,
      publicKey,
      publicKeyFingerprint,
      now,
      expiresAt,
    );
    this.callbacks.audit("requester_enrollment_created", undefined, deviceId);
    this.notifications.broadcastHumanEvent("requester-enrollment.changed", id);
    this.notifications.queueApprovalPush({
      body: "Open the approval app to verify the Agent device fingerprint.",
      tag: `requester-${id}`,
      title: "New Agent device registration",
      url: "/requests",
    });
    return json(
      {
        enrollment_id: id,
        expires_at: iso(expiresAt),
        public_key_fingerprint: publicKeyFingerprint,
        status: "pending",
      },
      202,
    );
  }

  async requesterSelf(
    request: Request,
  ): Promise<Response> {
    try {
      const response = await authenticateRequesterSelf({
        audience: new URL(this.env.ORIGIN).host,
        lookupRequester: (deviceId) => {
          const row = this.first<{
            display_name: string;
            public_key: string;
          }>(
            `SELECT display_name, public_key FROM requesters
             WHERE device_id = ? AND revoked_at IS NULL`,
            deviceId,
          );
          return row
            ? { displayName: row.display_name, publicKey: row.public_key }
            : undefined;
        },
        request,
      });
      this.assertRequesterActive(response.device_id);
      return json(response);
    } catch (error) {
      if (
        error instanceof RequesterAuthenticationError &&
        error.code === "requester_not_found"
      ) {
        throw new GatewayHttpError("requester_not_found", 404);
      }
      throw error;
    }
  }

  requesterEnrollmentStatus(id: string): Response {
    const enrollment = this.enrollment(id);
    return json(projectEnrollment(enrollment));
  }

  async humanRequesterEnrollments(
    request: Request,
  ): Promise<Response> {
    await this.human.requireHumanSession(request);
    const enrollments = this.rows<EnrollmentRow>(
        `SELECT id, device_id, display_name, public_key,
                public_key_fingerprint, status, created_at, expires_at
         FROM requester_enrollments
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY created_at ASC LIMIT 20`,
        Date.now(),
      ).map(projectEnrollment);
    return json({ enrollments });
  }

  async requesterEnrollmentDecisionOptions(
    request: Request,
    enrollmentId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readDecisionBody(request);
    const enrollment = this.enrollment(enrollmentId);
    if (enrollment.status !== "pending" || enrollment.expires_at <= Date.now()) {
      throw new GatewayHttpError("enrollment_not_pending", 409);
    }
    return this.callbacks.decisionOptions(
      "requester_enrollment",
      enrollmentId,
      body.decision,
    );
  }

  async requesterEnrollmentDecisionVerify(
    request: Request,
    enrollmentId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readDecisionVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "requester_enrollment",
      enrollmentId,
      body.decision,
    );
    const credentialId = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
    const status = body.decision === "approve" ? "approved" : "rejected";
    const enrollment = this.enrollment(enrollmentId);
    if (status === "approved") {
      const requester = this.first<{ revoked_at: number | null }>(
        `SELECT revoked_at FROM requesters WHERE device_id = ?`,
        enrollment.device_id,
      );
      if (requester) {
        throw new GatewayHttpError(
          requester.revoked_at === null
            ? "device_id_conflict"
            : "requester_revoked",
          409,
        );
      }
    }
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE requester_enrollments
         SET status = ?, terminal_at = ?
         WHERE id = ? AND status = 'pending' AND expires_at > ?
         RETURNING id`,
        status,
        now,
        enrollmentId,
        now,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("enrollment_not_pending", 409);
      }
      if (status === "approved") {
        this.sql.exec(
          `INSERT INTO requesters
            (device_id, display_name, public_key, created_at, revoked_at)
           VALUES (?, ?, ?, ?, NULL)`,
          enrollment.device_id,
          enrollment.display_name,
          enrollment.public_key,
          now,
        );
      }
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit(
        status === "approved"
          ? "requester_enrollment_approved"
          : "requester_enrollment_rejected",
        undefined,
        credentialId,
      );
    });
    this.notifications.broadcastHumanEvent("requester-enrollment.changed", enrollmentId);
    return json({ ok: true, status });
  }

  async requesterRenameOptions(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const body = await readJsonObject<{ display_name?: unknown }>(request);
    const displayName = safeText(body.display_name, 80);
    const requester = this.first<{ device_id: string }>(
      `SELECT device_id FROM requesters
       WHERE device_id = ? AND revoked_at IS NULL`,
      deviceId,
    );
    if (!requester) {
      throw new GatewayHttpError("requester_not_found", 404);
    }
    return this.human.freshAuthenticationOptions(
      "requester_rename",
      deviceId,
      { display_name: displayName },
    );
  }

  async requesterRenameVerify(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "requester_rename",
      deviceId,
      undefined,
    );
    const displayName = safeText(
      parseJsonObject(challenge.payload).display_name,
      80,
    );
    const authorizedBy = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ device_id: string }>(
        `UPDATE requesters SET display_name = ?
         WHERE device_id = ? AND revoked_at IS NULL RETURNING device_id`,
        displayName,
        deviceId,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("requester_not_found", 404);
      }
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit("requester_renamed", undefined, deviceId);
      this.callbacks.audit("requester_rename_authorized", undefined, authorizedBy);
    });
    this.notifications.broadcastHumanEvent("management.changed", deviceId);
    return json({ display_name: displayName, ok: true });
  }

  async requesterRevokeOptions(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const requester = this.first<{ device_id: string }>(
      `SELECT device_id FROM requesters
       WHERE device_id = ? AND revoked_at IS NULL`,
      deviceId,
    );
    if (!requester) {
      throw new GatewayHttpError("requester_not_found", 404);
    }
    return this.human.freshAuthenticationOptions("requester_revoke", deviceId);
  }

  async requesterRevokeVerify(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "requester_revoke",
      deviceId,
      undefined,
    );
    const authorizedBy = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
    let affectedRequests: string[] = [];
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ device_id: string }>(
        `UPDATE requesters SET revoked_at = ?
         WHERE device_id = ? AND revoked_at IS NULL RETURNING device_id`,
        now,
        deviceId,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("requester_not_found", 404);
      }
      this.sql.exec(
        `DELETE FROM requester_nonces WHERE device_id = ?`,
        deviceId,
      );
      this.sql.exec(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE requester_device_id = ? AND revoked_at IS NULL`,
        now,
        deviceId,
      );
      this.sql.exec(
        `UPDATE secret_authorization_grants SET revoked_at = ?
         WHERE requester_device_id = ? AND revoked_at IS NULL`,
        now,
        deviceId,
      );
      affectedRequests = this.humanManagement.rejectQueuedRequestsForRequester(
        deviceId,
        now,
      );
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit("requester_revoked", undefined, deviceId);
      this.callbacks.audit("requester_revoke_authorized", undefined, authorizedBy);
    });
    this.humanManagement.publishRejectedGrantRequests(affectedRequests);
    this.notifications.broadcastHumanEvent("management.changed", deviceId);
    return json({ ok: true, status: "revoked" });
  }

  async authenticateSignedRequest(
    request: Request,
    path: string,
    body: unknown,
    beforeUseNonce?: (identity: RequesterIdentity) => void,
  ): Promise<RequesterIdentity> {
    return authenticateRequester({
      audience: new URL(this.env.ORIGIN).host,
      beforeUseNonce: (identity) => {
        beforeUseNonce?.(identity);
      },
      body,
      lookupRequester: (deviceId) => {
        const row = this.first<{
          display_name: string;
          public_key: string;
        }>(
          `SELECT display_name, public_key FROM requesters
           WHERE device_id = ? AND revoked_at IS NULL`,
          deviceId,
        );
        return row
          ? { displayName: row.display_name, publicKey: row.public_key }
          : undefined;
      },
      method: request.method,
      path,
      request,
      useNonce: (deviceId, nonce, expiresAt) => {
        try {
          const inserted = this.rows<{ nonce: string }>(
            STORE_ACTIVE_REQUESTER_NONCE_SQL,
            deviceId,
            nonce,
            expiresAt,
            deviceId,
          );
          return inserted.length === 1;
        } catch {
          return false;
        }
      },
    });
  }

  assertRequesterActive(deviceId: string): void {
    if (
      !this.first<{ device_id: string }>(
        `SELECT device_id FROM requesters
         WHERE device_id = ? AND revoked_at IS NULL`,
        deviceId,
      )
    ) {
      throw new GatewayHttpError("requester_not_found", 404);
    }
  }

  async requestPollingToken(
    requestId: string,
    requesterDeviceId: string,
  ): Promise<string> {
    if (!this.env.GATEWAY_MASTER_KEY) {
      throw new GatewayHttpError("gateway_master_key_not_configured", 503);
    }
    try {
      return await deriveRequestPollingToken({
        deviceId: requesterDeviceId,
        masterKey: this.env.GATEWAY_MASTER_KEY,
        origin: this.env.ORIGIN,
        requestId,
      });
    } catch {
      throw new GatewayHttpError("gateway_master_key_invalid", 503);
    }
  }













  private enrollment(id: string): EnrollmentRow {
    const row = this.first<EnrollmentRow>(
      `SELECT id, device_id, display_name, public_key,
              public_key_fingerprint, status, created_at, expires_at, terminal_at
       FROM requester_enrollments WHERE id = ?`,
      id,
    );
    if (!row) throw new GatewayHttpError("enrollment_not_found", 404);
    if (row.status === "pending" && row.expires_at <= Date.now()) {
      this.sql.exec(
        `UPDATE requester_enrollments SET status = 'expired', terminal_at = ?
         WHERE id = ? AND status = 'pending'`,
        Date.now(),
        id,
      );
      row.status = "expired";
      row.terminal_at = Date.now();
    }
    return row;
  }









}
