import { generateAuthenticationOptions } from "@simplewebauthn/server";
import {
  canonicalJsonSha256Base64Url,
  encodeBase64Url,
  type ApprovalDecision,
  type SecretAuthorizationDuration,
  type SshAuthorizationDuration,
} from "@onenod/protocol";

import {
  rememberedAuthorizationDurationAvailable,
} from "./authorization-grants.js";
import {
  assertLegacyAuthorizationDurationMatches,
  GatewayHttpError,
  json,
  parseJsonObject,
  parseTransports,
  readDecisionBody,
  readDecisionVerifyBody,
} from "./approval-http.js";
import { ApprovalNotifications } from "./approval-notifications.js";
import {
  projectHumanActivityDetail,
  projectHumanActivitySummary,
  projectHumanRequestDetail,
  projectHumanRequestSummary,
} from "./approval-projection.js";
import { ApprovalRequestStore } from "./approval-request-store.js";
import type { RequestActivityRow, RequestRow } from "./approval-types.js";
import { HumanAccess } from "./human-access.js";
import {
  ACTIVITY_PAGE_SIZE,
  decodeActivityCursor,
  encodeActivityCursor,
  type ActivityCursor,
} from "./retention-policy.js";

const AUTHORIZATION_TTL_MS = 30_000;
const AUTHORIZATION_DURATION_MS: Partial<Record<SshAuthorizationDuration, number>> = {
  "4-hours": 4 * 60 * 60_000,
  "12-hours": 12 * 60 * 60_000,
  "24-hours": 24 * 60 * 60_000,
};

export interface ApprovalReviewCallbacks {
  audit(event: string, requestId?: string, actorId?: string): void;
}

/** Human approval queue projections and WebAuthn decision ceremony. */
export class ApprovalReview {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly human: HumanAccess,
    private readonly notifications: ApprovalNotifications,
    private readonly requestStore: ApprovalRequestStore,
    private readonly callbacks: ApprovalReviewCallbacks,
  ) {}

  private get sql(): SqlStorage { return this.ctx.storage.sql; }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql.exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  async humanRequests(request: Request): Promise<Response> {
    await this.human.requireHumanSession(request);
    const searchParams = new URL(request.url).searchParams;
    if (searchParams.get("pending") === "true") {
      const pending = this.rows<RequestRow>(
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
         FROM requests
         WHERE status = 'pending' AND expires_at > ?
         ORDER BY created_at DESC, id DESC LIMIT 100`,
        Date.now(),
      );
      return json({ requests: pending.map(projectHumanRequestSummary) });
    }
    const cursorValue = searchParams.get("cursor");
    let cursor: ActivityCursor | undefined;
    if (cursorValue !== null) {
      try {
        cursor = decodeActivityCursor(cursorValue);
      } catch {
        throw new GatewayHttpError("activity_cursor_invalid", 400);
      }
    }
    const cursorWhere = cursor
      ? `AND (created_at < ? OR (created_at = ? AND id < ?))`
      : "";
    const cursorBindings = cursor
      ? [cursor.createdAt, cursor.createdAt, cursor.requestId]
      : [];
    const active = this.rows<RequestRow>(
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
       FROM requests
       WHERE status IN ('pending', 'approved', 'executing', 'unknown')
         ${cursorWhere}
       ORDER BY created_at DESC, id DESC LIMIT ?`,
      ...cursorBindings,
      ACTIVITY_PAGE_SIZE + 1,
    ).map((row) => ({
      createdAt: row.created_at,
      requestId: row.id,
      summary: projectHumanRequestSummary(row),
    }));
    const activityCursorWhere = cursor
      ? `AND (created_at < ? OR (created_at = ? AND request_id < ?))`
      : "";
    const activity = this.rows<RequestActivityRow>(
      `SELECT request_id, action, status, created_at, terminal_at, expires_at,
              decided_at, consumed_at, item_title, field_label,
              expected_version, requester_name, client_application,
              client_source, application_assurance,
              application_principal_scheme, application_principal_id,
              application_signing_identifier, application_team_identifier,
              application_signer_name, error_code
       FROM request_activity
       WHERE 1 = 1 ${activityCursorWhere}
       ORDER BY created_at DESC, request_id DESC LIMIT ?`,
      ...cursorBindings,
      ACTIVITY_PAGE_SIZE + 1,
    ).map((row) => ({
      createdAt: row.created_at,
      requestId: row.request_id,
      summary: projectHumanActivitySummary(row),
    }));
    const merged = [...active, ...activity]
      .sort((left, right) =>
        right.createdAt - left.createdAt || right.requestId.localeCompare(left.requestId),
      )
      .slice(0, ACTIVITY_PAGE_SIZE + 1);
    const page = merged.slice(0, ACTIVITY_PAGE_SIZE);
    const last = page.at(-1);
    return json({
      ...(merged.length > ACTIVITY_PAGE_SIZE && last
        ? {
            next_cursor: encodeActivityCursor({
              createdAt: last.createdAt,
              requestId: last.requestId,
            }),
          }
        : {}),
      requests: page.map((entry) => entry.summary),
    });
  }

  async humanRequestDetail(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.human.requireHumanSession(request);
    const operational = this.requestStore.findRequestRow(requestId);
    if (operational) return json(projectHumanRequestDetail(operational));
    const activity = this.requestStore.requestActivityRow(requestId);
    if (!activity) throw new GatewayHttpError("request_not_found", 404);
    return json(projectHumanActivityDetail(activity));
  }

  async approvalOptions(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readDecisionBody(request);
    const row = this.requestStore.requestRow(requestId);
    if (row.status !== "pending" || row.expires_at <= Date.now()) {
      throw new GatewayHttpError("request_not_pending", 409);
    }
    const authorizationDuration = this.approvalAuthorizationDuration(
      row,
      body.decision,
      body.authorization_duration,
    );
    return this.decisionOptions(
      "approval",
      requestId,
      body.decision,
      authorizationDuration,
    );
  }

  async approvalVerify(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readDecisionVerifyBody(request, {
      allowLegacyAuthorizationDuration: true,
    });
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "approval",
      requestId,
      body.decision,
    );
    const challengePayload = challenge.payload
      ? parseJsonObject(challenge.payload)
      : {};
    const authorizationDuration = this.approvalAuthorizationDuration(
      this.requestStore.requestRow(requestId),
      body.decision,
      challengePayload.authorization_duration,
    );
    assertLegacyAuthorizationDurationMatches(
      body.authorization_duration,
      authorizationDuration,
    );
    const credentialId = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
    const status = body.decision === "approve" ? "approved" : "rejected";
    const authorizedUntil =
      status === "approved" ? now + AUTHORIZATION_TTL_MS : null;
    const row = this.requestStore.requestRow(requestId);
    const grantId =
      status === "approved" && authorizationDuration
        ? crypto.randomUUID()
        : undefined;
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE requests
         SET status = ?, decided_at = ?, authorized_until = ?,
             secret_grant_id = COALESCE(?, secret_grant_id),
             ssh_grant_id = COALESCE(?, ssh_grant_id)
         WHERE id = ? AND status = 'pending' AND expires_at > ?
         RETURNING id`,
        status,
        now,
        authorizedUntil,
        row.action === "secret.read" ? grantId ?? null : null,
        row.action === "ssh.sign" ? grantId ?? null : null,
        requestId,
        now,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("request_not_pending", 409);
      }
      if (status === "rejected") this.requestStore.clearPendingPayload(requestId);
      if (grantId && authorizationDuration) {
        const runtime = this.human.gatewayRuntimeState();
        const durationMs = AUTHORIZATION_DURATION_MS[authorizationDuration];
        if (row.action === "secret.read") {
          this.sql.exec(
            `INSERT INTO secret_authorization_grants
              (id, requester_device_id, scope_id, client_application,
               application_principal_scheme, application_signing_identifier,
               application_team_identifier, application_signer_name,
               item_id, item_title, field_id, field_label, field_type,
               item_version, duration, lock_generation, created_at, expires_at,
               revoked_at, authorized_by_credential_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
            grantId,
            row.requester_device_id,
            row.application_scope_id!,
            row.client_application,
            row.application_principal_scheme!,
            row.application_signing_identifier!,
            row.application_team_identifier,
            row.application_signer_name,
            row.item_id,
            row.item_title,
            row.field_id,
            row.field_label,
            row.field_type,
            row.expected_version,
            authorizationDuration as SecretAuthorizationDuration,
            runtime.lock_generation,
            now,
            durationMs === undefined ? null : now + durationMs,
            credentialId,
          );
          this.callbacks.audit("secret_authorization_created", requestId, grantId);
        } else {
          this.sql.exec(
            `INSERT INTO ssh_authorization_grants
              (id, requester_device_id, agent_instance_public_key, scope_id,
               scope_kind, client_application, application_principal_scheme,
               application_signing_identifier, application_team_identifier,
               application_signer_name, item_id, item_title, item_version, fingerprint, duration,
               lock_generation, created_at, expires_at, revoked_at,
               authorized_by_credential_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
            grantId,
            row.requester_device_id,
            row.ssh_agent_instance_public_key!,
            row.ssh_scope_id!,
            row.ssh_scope_kind!,
            row.client_application,
            row.application_principal_scheme!,
            row.application_signing_identifier!,
            row.application_team_identifier,
            row.application_signer_name,
            row.item_id,
            row.item_title,
            row.expected_version,
            row.field_label,
            authorizationDuration,
            runtime.lock_generation,
            now,
            durationMs === undefined ? null : now + durationMs,
            credentialId,
          );
          this.callbacks.audit("ssh_authorization_created", requestId, grantId);
        }
      }
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit(
        status === "approved" ? "request_approved" : "request_rejected",
        requestId,
        credentialId,
      );
    });
    if (status === "rejected") this.requestStore.recordTerminalActivity(requestId);
    this.notifications.broadcastHumanEvent("request.changed", requestId);
    if (grantId) {
      this.notifications.broadcastHumanEvent("management.changed", grantId);
    }
    return json({ ...(grantId ? { grant_id: grantId } : {}), ok: true, status });
  }

  private approvalAuthorizationDuration(
    row: RequestRow,
    decision: ApprovalDecision,
    value: unknown,
  ): SshAuthorizationDuration | undefined {
    if (value === undefined) return undefined;
    if (
      value !== "until-lock" &&
      value !== "until-agent-quits" &&
      value !== "4-hours" &&
      value !== "12-hours" &&
      value !== "24-hours"
    ) {
      throw new GatewayHttpError("authorization_duration_invalid", 400);
    }
    if (!rememberedAuthorizationDurationAvailable({
      action: row.action,
      applicationAssurance: row.application_assurance,
      applicationPrincipalId: row.application_principal_id,
      applicationPrincipalScheme: row.application_principal_scheme,
      applicationScopeId: row.application_scope_id,
      applicationSigningIdentifier: row.application_signing_identifier,
      decision,
      duration: value,
      sshAgentInstancePublicKey: row.ssh_agent_instance_public_key,
      sshScopeId: row.ssh_scope_id,
      sshScopeKind: row.ssh_scope_kind,
    })) {
      throw new GatewayHttpError("authorization_unavailable", 409);
    }
    return value;
  }

  async decisionOptions(
    kind: "requester_enrollment" | "approval",
    targetId: string,
    decision: ApprovalDecision,
    authorizationDuration?: SshAuthorizationDuration,
  ): Promise<Response> {
    const credentials = this.human.listHumanCredentials();
    const challengeSeed = {
      decision,
      kind,
      nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
      target_id: targetId,
      ...(authorizationDuration
        ? { authorization_duration: authorizationDuration }
        : {}),
    };
    const challenge = await canonicalJsonSha256Base64Url(challengeSeed);
    const options = await generateAuthenticationOptions({
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: parseTransports(credential.transports),
      })),
      challenge,
      rpID: this.env.RP_ID,
      timeout: 60_000,
      userVerification: "required",
    });
    const challengeId = this.human.storeChallenge({
      challenge: options.challenge,
      decision,
      kind,
      ...(authorizationDuration
        ? {
            payload: JSON.stringify({
              authorization_duration: authorizationDuration,
            }),
          }
        : {}),
      targetId,
    });
    return json({ challenge_id: challengeId, options });
  }



}
