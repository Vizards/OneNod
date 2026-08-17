import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import {
  encodeBase64Url,
  requesterPublicKeyFingerprint,
} from "@onenod/protocol";

import {
  PASSKEY_RP_NAME,
  PASSKEY_USER_DISPLAY_NAME,
  PASSKEY_USER_HANDLE,
  PASSKEY_USER_NAME,
} from "../passkey-identity.js";
import {
  REJECT_QUEUED_REQUESTS_FOR_CREDENTIAL_SQL,
  REJECT_QUEUED_REQUESTS_FOR_REQUESTER_SQL,
  rejectQueuedRequestsForGrantSql,
} from "./authorization-grants.js";
import {
  GatewayHttpError,
  assertExactKeys,
  deviceProofMessage,
  iso,
  json,
  parseJsonObject,
  parseTransports,
  readChallengeVerifyBody,
  readJsonObject,
  record,
  safeHumanDeviceInput,
  safeIdentifier,
  safeText,
} from "./approval-http.js";
import { ApprovalNotifications } from "./approval-notifications.js";
import { projectGrantApplicationIdentity } from "./approval-projection.js";
import { ApprovalRequestStore } from "./approval-request-store.js";
import type {
  HumanCredentialRow,
  HumanDeviceRow,
  RequesterRow,
  SecretAuthorizationGrantRow,
  SshAuthorizationGrantRow,
} from "./approval-types.js";
import { HumanAccess } from "./human-access.js";
import { storagePressure } from "./retention-policy.js";

export interface HumanManagementCallbacks {
  assertStorageGrowthAllowed(): void;
  audit(event: string, requestId?: string, actorId?: string): void;
}

/** Human devices, passkeys, remembered grants, and their revocation cascades. */
export class HumanManagement {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly human: HumanAccess,
    private readonly notifications: ApprovalNotifications,
    private readonly requestStore: ApprovalRequestStore,
    private readonly callbacks: HumanManagementCallbacks,
  ) {}

  private get sql(): SqlStorage {
    return this.ctx.storage.sql;
  }

  private rows<T>(query: string, ...bindings: unknown[]): T[] {
    return this.sql
      .exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray() as unknown as T[];
  }

  private first<T>(query: string, ...bindings: unknown[]): T | undefined {
    return this.rows<T>(query, ...bindings)[0];
  }

  async humanManagement(request: Request): Promise<Response> {
    const session = await this.human.requireHumanSession(request);
    const credentials = this.rows<HumanCredentialRow>(
      `SELECT id, public_key, counter, transports, device_type, backed_up, label,
              created_at, last_used_at, revoked_at
       FROM human_credentials WHERE revoked_at IS NULL ORDER BY created_at ASC`,
    ).map((credential) => ({
      backed_up: credential.backed_up === 1,
      created_at: iso(credential.created_at),
      current: credential.id === session.credential_id,
      device_type: credential.device_type,
      id: credential.id,
      label: credential.label,
      last_used_at: credential.last_used_at ? iso(credential.last_used_at) : undefined,
    }));
    const devices = this.rows<HumanDeviceRow & { push_enabled: number }>(
      `SELECT d.id, d.label, d.platform, d.public_key, d.created_at,
              d.last_seen_at, d.revoked_at,
              CASE WHEN p.device_id IS NULL THEN 0 ELSE 1 END AS push_enabled
       FROM human_devices d
       LEFT JOIN push_subscriptions p ON p.device_id = d.id
       WHERE d.revoked_at IS NULL ORDER BY d.created_at ASC`,
    ).map((device) => ({
      created_at: iso(device.created_at),
      current: device.id === session.device_id,
      id: device.id,
      label: device.label,
      last_seen_at: iso(device.last_seen_at),
      platform: device.platform,
      push_enabled: device.push_enabled === 1,
    }));
    const requesterRows = this.rows<RequesterRow>(
      `SELECT device_id, display_name, public_key, created_at, revoked_at
       FROM requesters WHERE revoked_at IS NULL ORDER BY created_at ASC`,
    );
    const requesters = await Promise.all(
      requesterRows.map(async (requester) => ({
        created_at: iso(requester.created_at),
        device_id: requester.device_id,
        display_name: requester.display_name,
        public_key_fingerprint: await requesterPublicKeyFingerprint(
          requester.public_key,
        ),
      })),
    );
    const now = Date.now();
    const lockGeneration = this.human.gatewayRuntimeState().lock_generation;
    const secretAuthorizations = this.rows<SecretAuthorizationGrantRow>(
      `SELECT id, requester_device_id, scope_id, client_application,
              application_principal_scheme, application_signing_identifier,
              application_team_identifier, application_signer_name,
              item_id, item_title, field_id, field_label, field_type,
              item_version, duration, lock_generation, created_at, expires_at,
              revoked_at, use_count, authorized_by_credential_id
       FROM secret_authorization_grants
       WHERE revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)
         AND (duration != 'until-lock' OR lock_generation = ?)
       ORDER BY created_at DESC`,
      now,
      lockGeneration,
    ).map((grant) => ({
      client_application: grant.client_application,
      application_identity: projectGrantApplicationIdentity(grant),
      created_at: iso(grant.created_at),
      duration: grant.duration,
      expires_at: grant.expires_at ? iso(grant.expires_at) : undefined,
      field_id: grant.field_id,
      field_label: grant.field_label,
      field_type: grant.field_type,
      id: grant.id,
      item_id: grant.item_id,
      item_title: grant.item_title,
      item_version: grant.item_version,
      requester_device_id: grant.requester_device_id,
      use_count: grant.use_count,
    }));
    const sshAuthorizations = this.rows<SshAuthorizationGrantRow>(
      `SELECT id, requester_device_id, agent_instance_public_key, scope_id,
              scope_kind, client_application, application_principal_scheme,
              application_signing_identifier, application_team_identifier,
              application_signer_name, item_id, item_title, item_version,
              fingerprint, duration,
              lock_generation, created_at, expires_at, revoked_at,
              use_count, authorized_by_credential_id
       FROM ssh_authorization_grants
       WHERE revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)
         AND (duration != 'until-lock' OR lock_generation = ?)
       ORDER BY created_at DESC`,
      now,
      lockGeneration,
    ).map((grant) => ({
      created_at: iso(grant.created_at),
      client_application: grant.client_application,
      application_identity: projectGrantApplicationIdentity(grant),
      duration: grant.duration,
      expires_at: grant.expires_at ? iso(grant.expires_at) : undefined,
      fingerprint: grant.fingerprint,
      id: grant.id,
      item_id: grant.item_id,
      item_title: grant.item_title,
      item_version: grant.item_version,
      requester_device_id: grant.requester_device_id,
      scope_kind: grant.scope_kind,
      use_count: grant.use_count,
    }));
    return json({
      credentials,
      devices,
      requesters,
      server_time: new Date(now).toISOString(),
      secret_authorizations: secretAuthorizations,
      ssh_authorizations: sshAuthorizations,
      storage: {
        database_size_bytes: this.sql.databaseSize,
        pressure: storagePressure(this.sql.databaseSize),
      },
    });
  }

  async authorizationSummary(request: Request): Promise<Response> {
    await this.human.requireHumanSession(request);
    const now = Date.now();
    const lockGeneration = this.human.gatewayRuntimeState().lock_generation;
    const secret = this.activeAuthorizationCount(
      "secret_authorization_grants",
      now,
      lockGeneration,
    );
    const ssh = this.activeAuthorizationCount(
      "ssh_authorization_grants",
      now,
      lockGeneration,
    );
    const expiries = [secret.next_expiry_at, ssh.next_expiry_at].filter(
      (value): value is number => typeof value === "number",
    );
    const nextExpiry = expiries.length > 0 ? Math.min(...expiries) : undefined;
    return json({
      active_count: secret.count + ssh.count,
      ...(nextExpiry === undefined
        ? {}
        : { next_expiry_at: new Date(nextExpiry).toISOString() }),
      server_time: new Date(now).toISOString(),
    });
  }

  private activeAuthorizationCount(
    table: "secret_authorization_grants" | "ssh_authorization_grants",
    now: number,
    lockGeneration: number,
  ): { count: number; next_expiry_at: number | null } {
    return this.first<{ count: number; next_expiry_at: number | null }>(
      `SELECT COUNT(*) AS count, MIN(expires_at) AS next_expiry_at
       FROM ${table}
       WHERE revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)
         AND (duration != 'until-lock' OR lock_generation = ?)`,
      now,
      lockGeneration,
    ) ?? { count: 0, next_expiry_at: null };
  }

  async revokeSecretAuthorization(
    request: Request,
    grantIdValue: string,
  ): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    assertExactKeys(await readJsonObject(request), []);
    const grantId = safeIdentifier(grantIdValue, "grant_id");
    const now = Date.now();
    let affected: string[] = [];
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE secret_authorization_grants SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL RETURNING id`,
        now,
        grantId,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("secret_authorization_not_found", 404);
      }
      affected = this.rejectQueuedRequestsForGrant("secret", grantId, now);
      this.callbacks.audit("secret_authorization_revoked", undefined, session.credential_id);
    });
    this.publishRejectedGrantRequests(affected);
    this.notifications.broadcastHumanEvent("management.changed", grantId);
    return json({ ok: true, status: "revoked" });
  }

  async revokeSshAuthorization(
    request: Request,
    grantIdValue: string,
  ): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    assertExactKeys(await readJsonObject(request), []);
    const grantId = safeIdentifier(grantIdValue, "grant_id");
    const now = Date.now();
    let affected: string[] = [];
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL RETURNING id`,
        now,
        grantId,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("ssh_authorization_not_found", 404);
      }
      affected = this.rejectQueuedRequestsForGrant("ssh", grantId, now);
      this.callbacks.audit("ssh_authorization_revoked", undefined, session.credential_id);
    });
    this.publishRejectedGrantRequests(affected);
    this.notifications.broadcastHumanEvent("management.changed", grantId);
    return json({ ok: true, status: "revoked" });
  }

  private rejectQueuedRequestsForGrant(
    kind: "secret" | "ssh",
    grantId: string,
    now: number,
  ): string[] {
    const affected = this.rows<{ id: string }>(
      rejectQueuedRequestsForGrantSql(kind),
      now,
      grantId,
      ...(kind === "secret" ? [grantId] : []),
    );
    for (const row of affected) {
      this.requestStore.clearPendingPayload(row.id);
      this.callbacks.audit("request_rejected_authorization_revoked", row.id, grantId);
    }
    return affected.map((row) => row.id);
  }

  private rejectQueuedRequestsForCredential(
    credentialId: string,
    now: number,
  ): string[] {
    const affected = this.rows<{ id: string }>(
      REJECT_QUEUED_REQUESTS_FOR_CREDENTIAL_SQL,
      now,
      credentialId,
      credentialId,
      credentialId,
    );
    for (const row of affected) {
      this.requestStore.clearPendingPayload(row.id);
      this.callbacks.audit(
        "request_rejected_authorization_revoked",
        row.id,
        credentialId,
      );
    }
    return affected.map((row) => row.id);
  }

  rejectQueuedRequestsForRequester(
    requesterDeviceId: string,
    now: number,
  ): string[] {
    const affected = this.rows<{ id: string }>(
      REJECT_QUEUED_REQUESTS_FOR_REQUESTER_SQL,
      now,
      requesterDeviceId,
    );
    for (const row of affected) {
      this.requestStore.clearPendingPayload(row.id);
      this.callbacks.audit("request_rejected_requester_revoked", row.id, requesterDeviceId);
    }
    return affected.map((row) => row.id);
  }

  publishRejectedGrantRequests(requestIds: string[]): void {
    for (const requestId of requestIds) {
      this.requestStore.recordTerminalActivity(requestId);
      this.notifications.broadcastHumanEvent("request.changed", requestId);
    }
  }

  async deviceRegistrationOptions(request: Request): Promise<Response> {
    const session = await this.human.requireHumanBaseMutation(request);
    this.callbacks.assertStorageGrowthAllowed();
    const input = safeHumanDeviceInput(await readJsonObject(request));
    const credentials = this.human.listHumanCredentials();
    const options = await generateAuthenticationOptions({
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: parseTransports(credential.transports),
      })),
      rpID: this.env.RP_ID,
      timeout: 60_000,
      userVerification: "required",
    });
    const challengeId = this.human.storeChallenge({
      challenge: options.challenge,
      kind: "device_registration",
      payload: JSON.stringify({ ...input, session_hash: session.token_hash }),
      targetId: input.device_id,
    });
    return json({ challenge_id: challengeId, device_challenge: options.challenge, options });
  }

  async deviceRegistrationVerify(request: Request): Promise<Response> {
    const session = await this.human.requireHumanBaseMutation(request);
    const body = await readJsonObject<{
      challenge_id?: unknown;
      device_signature?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.human.getChallenge(
      challengeId,
      "device_registration",
      undefined,
      undefined,
    );
    const payload = safeHumanDeviceInput(parseJsonObject(challenge.payload));
    if (parseJsonObject(challenge.payload).session_hash !== session.token_hash) {
      throw new GatewayHttpError("device_registration_session_mismatch", 403);
    }
    const credentialId = await this.human.verifyHumanAuthentication(
      record(body.response),
      challenge.challenge,
    );
    await this.human.verifyDeviceProof(
      payload.public_key,
      deviceProofMessage(
        "device_registration",
        challengeId,
        challenge.challenge,
        payload.device_id,
      ),
      body.device_signature,
    );
    this.callbacks.assertStorageGrowthAllowed();
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `INSERT INTO human_devices
          (id, label, platform, public_key, created_at, last_seen_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)
         ON CONFLICT(id) DO UPDATE SET
           label = excluded.label,
           platform = excluded.platform,
           public_key = excluded.public_key,
           created_at = excluded.created_at,
           last_seen_at = excluded.last_seen_at,
           revoked_at = NULL`,
        payload.device_id,
        payload.label,
        payload.platform,
        payload.public_key,
        now,
        now,
      );
      this.sql.exec(
        `UPDATE human_sessions SET device_id = ?, last_seen_at = ?
         WHERE token_hash = ?`,
        payload.device_id,
        now,
        session.token_hash,
      );
      this.human.markChallengeUsed(challengeId);
      this.callbacks.audit("human_device_registered", undefined, payload.device_id);
      this.callbacks.audit("human_device_registration_authorized", undefined, credentialId);
    });
    this.notifications.broadcastHumanEvent("management.changed", payload.device_id);
    return json({ device_id: payload.device_id, device_trusted: true, ok: true });
  }

  async deviceRevokeOptions(request: Request, deviceId: string): Promise<Response> {
    await this.human.requireHumanMutation(request);
    if (!this.human.activeHumanDevice(deviceId)) {
      throw new GatewayHttpError("device_not_found", 404);
    }
    if (this.human.activeHumanDeviceCount() <= 1) {
      throw new GatewayHttpError("last_device_cannot_be_revoked", 409);
    }
    return this.human.freshAuthenticationOptions("device_revoke", deviceId);
  }

  async deviceRevokeVerify(request: Request, deviceId: string): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "device_revoke",
      deviceId,
      undefined,
    );
    const credentialId = await this.human.verifyHumanAuthentication(body.response, challenge.challenge);
    if (this.human.activeHumanDeviceCount() <= 1) {
      throw new GatewayHttpError("last_device_cannot_be_revoked", 409);
    }
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE human_devices SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL RETURNING id`,
        now,
        deviceId,
      );
      if (updated.length !== 1) throw new GatewayHttpError("device_not_found", 404);
      this.sql.exec(`DELETE FROM human_sessions WHERE device_id = ?`, deviceId);
      this.sql.exec(`DELETE FROM push_subscriptions WHERE device_id = ?`, deviceId);
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit("human_device_revoked", undefined, deviceId);
      this.callbacks.audit("human_device_revoke_authorized", undefined, credentialId);
    });
    this.notifications.broadcastHumanEvent("management.changed", deviceId);
    this.notifications.closeDeviceSockets(deviceId);
    return json({ ok: true, status: "revoked" });
  }

  async credentialRegistrationAuthorizationOptions(
    request: Request,
  ): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    this.callbacks.assertStorageGrowthAllowed();
    const body = await readJsonObject<{ label?: unknown }>(request);
    const label = safeText(body.label, 80);
    return this.human.freshAuthenticationOptions(
      "credential_authorization",
      session.token_hash,
      { label, session_hash: session.token_hash },
    );
  }

  async credentialRegistrationAuthorizationVerify(
    request: Request,
  ): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "credential_authorization",
      session.token_hash,
      undefined,
    );
    const payload = parseJsonObject(challenge.payload);
    if (payload.session_hash !== session.token_hash) {
      throw new GatewayHttpError("credential_session_mismatch", 403);
    }
    const authorizedBy = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const label = safeText(payload.label, 80);
    const credentials = this.human.listHumanCredentials();
    const options = await generateRegistrationOptions({
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: parseTransports(credential.transports),
      })),
      rpID: this.env.RP_ID,
      rpName: PASSKEY_RP_NAME,
      supportedAlgorithmIDs: [-7],
      timeout: 60_000,
      userDisplayName: PASSKEY_USER_DISPLAY_NAME,
      userID: new TextEncoder().encode(PASSKEY_USER_HANDLE),
      userName: PASSKEY_USER_NAME,
    });
    const registrationChallengeId = this.human.storeChallenge({
      challenge: options.challenge,
      kind: "credential_registration",
      payload: JSON.stringify({
        authorized_by: authorizedBy,
        label,
        session_hash: session.token_hash,
      }),
      targetId: session.token_hash,
    });
    this.human.markChallengeUsed(body.challenge_id);
    return json({ challenge_id: registrationChallengeId, options });
  }

  async credentialRegistrationVerify(request: Request): Promise<Response> {
    const session = await this.human.requireHumanMutation(request);
    const body = await readJsonObject<{
      challenge_id?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.human.getChallenge(
      challengeId,
      "credential_registration",
      session.token_hash,
      undefined,
    );
    const payload = parseJsonObject(challenge.payload);
    if (payload.session_hash !== session.token_hash) {
      throw new GatewayHttpError("credential_session_mismatch", 403);
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        expectedChallenge: challenge.challenge,
        expectedOrigin: this.env.ORIGIN,
        expectedRPID: this.env.RP_ID,
        requireUserPresence: true,
        requireUserVerification: true,
        response: record(body.response) as unknown as RegistrationResponseJSON,
        supportedAlgorithmIDs: [-7],
      });
    } catch {
      throw new GatewayHttpError("webauthn_verification_failed", 401);
    }
    if (!verification.verified) {
      throw new GatewayHttpError("webauthn_verification_failed", 401);
    }
    this.callbacks.assertStorageGrowthAllowed();
    const info = verification.registrationInfo;
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `INSERT INTO human_credentials
          (id, public_key, counter, transports, device_type, backed_up, label,
           created_at, last_used_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
        info.credential.id,
        encodeBase64Url(info.credential.publicKey),
        info.credential.counter,
        JSON.stringify(info.credential.transports ?? []),
        info.credentialDeviceType,
        info.credentialBackedUp ? 1 : 0,
        safeText(payload.label, 80),
        now,
        now,
      );
      this.human.markChallengeUsed(challengeId);
      this.callbacks.audit("human_credential_registered", undefined, info.credential.id);
    });
    this.notifications.broadcastHumanEvent("management.changed", info.credential.id);
    return json({ credential_id: info.credential.id, ok: true });
  }

  async credentialRevokeOptions(
    request: Request,
    credentialId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    this.human.humanCredential(credentialId);
    if (this.human.listHumanCredentials().length <= 1) {
      throw new GatewayHttpError("last_credential_cannot_be_revoked", 409);
    }
    return this.human.freshAuthenticationOptions("credential_revoke", credentialId);
  }

  async credentialRevokeVerify(
    request: Request,
    credentialId: string,
  ): Promise<Response> {
    await this.human.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.human.getChallenge(
      body.challenge_id,
      "credential_revoke",
      credentialId,
      undefined,
    );
    const authorizedBy = await this.human.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    if (this.human.listHumanCredentials().length <= 1) {
      throw new GatewayHttpError("last_credential_cannot_be_revoked", 409);
    }
    const now = Date.now();
    let affectedRequests: string[] = [];
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE human_credentials SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL RETURNING id`,
        now,
        credentialId,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("credential_not_found", 404);
      }
      this.sql.exec(`DELETE FROM human_sessions WHERE credential_id = ?`, credentialId);
      this.sql.exec(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE authorized_by_credential_id = ? AND revoked_at IS NULL`,
        now,
        credentialId,
      );
      this.sql.exec(
        `UPDATE secret_authorization_grants SET revoked_at = ?
         WHERE authorized_by_credential_id = ? AND revoked_at IS NULL`,
        now,
        credentialId,
      );
      affectedRequests = this.rejectQueuedRequestsForCredential(
        credentialId,
        now,
      );
      this.human.markChallengeUsed(body.challenge_id);
      this.callbacks.audit("human_credential_revoked", undefined, credentialId);
      this.callbacks.audit("human_credential_revoke_authorized", undefined, authorizedBy);
    });
    this.publishRejectedGrantRequests(affectedRequests);
    this.notifications.broadcastHumanEvent("management.changed", credentialId);
    this.notifications.closeCredentialSockets(credentialId);
    return json({ ok: true, status: "revoked" });
  }

}
