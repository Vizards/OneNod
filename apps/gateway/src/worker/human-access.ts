import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  decodeBase64Url,
  encodeBase64Url,
  sha256Base64Url,
  type HumanBootstrapRequest,
} from "@onenod/protocol";

import {
  DEFAULT_PASSKEY_LABEL,
  PASSKEY_RP_NAME,
  PASSKEY_USER_DISPLAY_NAME,
  PASSKEY_USER_HANDLE,
  PASSKEY_USER_NAME,
} from "../passkey-identity.js";
import { ownedBytes } from "../shared/owned-bytes.js";
import { bootstrapTokensMatch } from "./bootstrap-authorization.js";
import {
  GatewayHttpError,
  assertExactKeys,
  bootstrapRequestIdForToken,
  constantTimeStringEquals,
  deviceProofMessage,
  iso,
  json,
  parseJsonObject,
  parseTransports,
  randomToken,
  readChallengeVerifyBody,
  readCookie,
  readJsonObject,
  record,
  safeDeviceId,
  safeIdentifier,
  safeText,
} from "./approval-http.js";
import type {
  BootstrapSessionRow,
  ChallengeKind,
  ChallengeRow,
  GatewayRuntimeStateRow,
  HumanCredentialRow,
  HumanDeviceRow,
  SessionRow,
} from "./approval-types.js";
import { REVALIDATE_HUMAN_CREDENTIAL_SQL } from "./requester-auth.js";
import {
  HUMAN_SESSION_TTL_MS,
  absoluteHumanSessionExpiry,
} from "./retention-policy.js";

const SESSION_COOKIE = "__Host-approval_session";
const BOOTSTRAP_SESSION_COOKIE = "__Host-bootstrap_session";
const BOOTSTRAP_SESSION_TTL_MS = 10 * 60_000;
const CHALLENGE_TTL_MS = 2 * 60_000;
const BOOTSTRAP_AUTHORIZATION_TTL_MS = 2 * 60_000;
const HUMAN_DEVICE_LAST_SEEN_WRITE_INTERVAL_MS = 5 * 60_000;

export interface HumanAccessCallbacks {
  audit(event: string, requestId?: string, actorId?: string): void;
  broadcastHumanEvent(type: string, entityId?: string): void;
  recordTerminalActivity(requestId: string): boolean;
}
export class HumanAccess {
  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly callbacks: HumanAccessCallbacks,
  ) {}

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

  async authorizeBootstrap(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    if (this.bootstrapWasUsed() || this.hasHumanCredential()) {
      throw new GatewayHttpError("already_initialized", 409);
    }
    const body = await readJsonObject<{ token?: unknown }>(request);
    assertExactKeys(body, ["token"]);
    const now = Date.now();
    if (
      !(await bootstrapTokensMatch(body.token, this.env.BOOTSTRAP_TOKEN))
    ) {
      throw new GatewayHttpError("bootstrap_unavailable", 403);
    }

    const bootstrap = await this.ensureBootstrapSession(request);
    const expiresAt = now + BOOTSTRAP_SESSION_TTL_MS;
    const armedUntil = now + BOOTSTRAP_AUTHORIZATION_TTL_MS;
    this.ctx.storage.transactionSync(() => {
      const otherSession = this.first<{ id: string }>(
        `SELECT id FROM bootstrap_sessions
         WHERE id != ? AND consumed_at IS NULL AND armed_until > ?
         LIMIT 1`,
        bootstrap.id,
        now,
      );
      if (otherSession) {
        throw new GatewayHttpError("bootstrap_unavailable", 403);
      }
      this.sql.exec(
        `INSERT INTO bootstrap_sessions
          (id, expires_at, armed_until, consumed_at)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT(id) DO UPDATE SET
           expires_at = excluded.expires_at,
           armed_until = excluded.armed_until
         WHERE bootstrap_sessions.consumed_at IS NULL`,
        bootstrap.id,
        expiresAt,
        armedUntil,
      );
    });
    return json({ armed_until: iso(armedUntil), ok: true }, 200, bootstrap.headers);
  }

  async humanState(request: Request): Promise<Response> {
    const session = await this.readSession(request);
    const initialized = this.bootstrapWasUsed() || this.hasHumanCredential();
    if (initialized) {
      return json({
        authenticated: Boolean(session),
        current_device_id: session?.device_id ?? undefined,
        device_trusted: Boolean(session?.device_id),
        ...(session ? { csrf_token: session.csrf_token } : {}),
        initialized: true,
        locked: this.gatewayRuntimeState().locked === 1,
      });
    }
    const bootstrap = await this.ensureBootstrapSession(request);
    return json({
      authenticated: Boolean(session),
      ...(this.env.BOOTSTRAP_TOKEN === undefined
        ? { bootstrap_request_id: bootstrap.id }
        : {}),
      initialized: false,
    }, 200, bootstrap.headers);
  }

  async lockGateway(request: Request): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    assertExactKeys(await readJsonObject(request), []);
    const state = this.gatewayRuntimeState();
    if (state.locked === 1) {
      return json({ locked: true, ok: true });
    }
    const now = Date.now();
    const affected = this.rows<{ id: string }>(
      `SELECT id FROM requests
       WHERE status IN ('pending', 'approved')`,
    );
    const affectedEnrollments = this.rows<{ id: string }>(
      `SELECT id FROM requester_enrollments
       WHERE status = 'pending' AND expires_at > ?`,
      now,
    );
    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `UPDATE gateway_runtime_state
         SET locked = 1, lock_generation = lock_generation + 1,
             changed_at = ?, changed_by = ?
         WHERE singleton = 1`,
        now,
        session.credential_id,
      );
      this.sql.exec(
        `UPDATE requests
         SET status = 'rejected', decided_at = ?, authorized_until = NULL
         WHERE status IN ('pending', 'approved')`,
        now,
      );
      this.sql.exec(
        `UPDATE request_operations
         SET payload_aad = NULL, payload_ciphertext = NULL, payload_digest = NULL,
             payload_iv = NULL
         WHERE request_id IN (
           SELECT id FROM requests WHERE status = 'rejected' AND decided_at = ?
         )`,
        now,
      );
      this.sql.exec(
        `UPDATE ssh_authorization_grants SET revoked_at = ?
         WHERE duration = 'until-lock' AND revoked_at IS NULL`,
        now,
      );
      this.sql.exec(
        `UPDATE secret_authorization_grants SET revoked_at = ?
         WHERE duration = 'until-lock' AND revoked_at IS NULL`,
        now,
      );
      this.sql.exec(
        `UPDATE requester_enrollments SET status = 'rejected', terminal_at = ?
         WHERE status = 'pending' AND expires_at > ?`,
        now,
        now,
      );
      this.callbacks.audit("gateway_locked", undefined, session.credential_id);
    });
    for (const row of affected) {
      this.callbacks.recordTerminalActivity(row.id);
      this.callbacks.broadcastHumanEvent("request.changed", row.id);
    }
    for (const row of affectedEnrollments) {
      this.callbacks.broadcastHumanEvent("requester-enrollment.changed", row.id);
    }
    this.callbacks.broadcastHumanEvent("lock.changed", "locked");
    this.callbacks.broadcastHumanEvent("management.changed", "remembered-authorizations");
    return json({ locked: true, ok: true });
  }

  async gatewayUnlockOptions(request: Request): Promise<Response> {
    await this.requireHumanMutation(request);
    assertExactKeys(await readJsonObject(request), []);
    if (this.gatewayRuntimeState().locked !== 1) {
      throw new GatewayHttpError("gateway_not_locked", 409);
    }
    return this.freshAuthenticationOptions(
      "gateway_unlock",
      "gateway",
    );
  }

  async gatewayUnlockVerify(request: Request): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "gateway_unlock",
      "gateway",
      undefined,
    );
    const authorizedBy = await this.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ singleton: number }>(
        `UPDATE gateway_runtime_state
         SET locked = 0, changed_at = ?, changed_by = ?
         WHERE singleton = 1 AND locked = 1
         RETURNING singleton`,
        now,
        authorizedBy,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("gateway_not_locked", 409);
      }
      this.markChallengeUsed(body.challenge_id);
      this.callbacks.audit("gateway_unlocked", undefined, authorizedBy);
    });
    this.callbacks.broadcastHumanEvent("lock.changed", "unlocked");
    return json({ locked: false, ok: true });
  }

  gatewayRuntimeState(): GatewayRuntimeStateRow {
    const state = this.first<GatewayRuntimeStateRow>(
      `SELECT locked, lock_generation, changed_at, changed_by
       FROM gateway_runtime_state WHERE singleton = 1`,
    );
    if (!state) {
      throw new Error("gateway_runtime_state_missing");
    }
    return state;
  }

  assertGatewayUnlocked(): void {
    if (this.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
  }

  async bootstrapOptions(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    if (this.bootstrapWasUsed() || this.hasHumanCredential()) {
      throw new GatewayHttpError("already_initialized", 409);
    }
    const bootstrap = await this.readBootstrapSession(request);
    if ((bootstrap.armed_until ?? 0) < Date.now()) {
      throw new GatewayHttpError("bootstrap_not_armed", 403);
    }
    const body = await readJsonObject<HumanBootstrapRequest>(request);
    const label = safeText(body.label, 80, DEFAULT_PASSKEY_LABEL);
    const credentials = this.listHumanCredentials();
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
    const challengeId = this.storeChallenge({
      challenge: options.challenge,
      kind: "bootstrap",
      payload: JSON.stringify({
        bootstrap_session_id: bootstrap.id,
        label,
      }),
    });
    return json({ challenge_id: challengeId, options });
  }

  async bootstrapVerify(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    if (this.bootstrapWasUsed() || this.hasHumanCredential()) {
      throw new GatewayHttpError("already_initialized", 409);
    }
    const body = await readJsonObject<{
      challenge_id?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.getChallenge(
      challengeId,
      "bootstrap",
      undefined,
      undefined,
    );
    const payload = parseJsonObject(challenge.payload);
    const bootstrapSessionId = safeIdentifier(
      payload.bootstrap_session_id,
      "bootstrap_session_id",
    );
    const bootstrap = await this.readBootstrapSession(
      request,
      bootstrapSessionId,
    );
    if ((bootstrap.armed_until ?? 0) < Date.now()) {
      throw new GatewayHttpError("bootstrap_not_armed", 403);
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
    const info = verification.registrationInfo;
    const label = safeText(payload.label, 80, DEFAULT_PASSKEY_LABEL);
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      const bootstrapClaim = this.rows<{ singleton: number }>(
        `INSERT INTO gateway_bootstrap_state (singleton, used_at)
         VALUES (1, ?)
         ON CONFLICT(singleton) DO NOTHING
         RETURNING singleton`,
        now,
      );
      if (bootstrapClaim.length !== 1) {
        throw new GatewayHttpError("already_initialized", 409);
      }
      const consumed = this.rows<{ id: string }>(
        `UPDATE bootstrap_sessions SET consumed_at = ?
         WHERE id = ? AND consumed_at IS NULL AND expires_at > ?
           AND armed_until > ?
         RETURNING id`,
        now,
        bootstrap.id,
        now,
        now,
      );
      if (consumed.length !== 1) {
        throw new GatewayHttpError("bootstrap_session_invalid", 409);
      }
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
        label,
        now,
        now,
      );
      this.markChallengeUsed(challengeId);
      this.callbacks.audit("human_registered", undefined, info.credential.id);
    });
    return this.createHumanSessionResponse(info.credential.id, null);
  }

  async humanSessionOptions(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    const body = await readJsonObject<{ device_id?: unknown }>(request);
    const deviceId =
      body.device_id === undefined ? undefined : safeDeviceId(body.device_id);
    const device = deviceId ? this.activeHumanDevice(deviceId) : undefined;
    const credentials = this.listHumanCredentials();
    if (credentials.length === 0) {
      throw new GatewayHttpError("not_initialized", 409);
    }
    const options = await generateAuthenticationOptions({
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: parseTransports(credential.transports),
      })),
      rpID: this.env.RP_ID,
      timeout: 60_000,
      userVerification: "required",
    });
    const challengeId = this.storeChallenge({
      challenge: options.challenge,
      kind: "human_session",
      payload: JSON.stringify({
        device_id: deviceId ?? null,
        device_trusted: Boolean(device),
      }),
    });
    return json({
      challenge_id: challengeId,
      device_challenge: options.challenge,
      device_trusted: Boolean(device),
      options,
    });
  }

  async humanSessionVerify(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    const body = await readJsonObject<{
      challenge_id?: unknown;
      device_signature?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.getChallenge(
      challengeId,
      "human_session",
      undefined,
      undefined,
    );
    const credentialId = await this.verifyHumanAuthentication(
      record(body.response),
      challenge.challenge,
    );
    const payload = parseJsonObject(challenge.payload);
    const deviceId =
      payload.device_trusted === true
        ? safeDeviceId(payload.device_id)
        : null;
    if (deviceId) {
      const device = this.activeHumanDevice(deviceId);
      if (!device) throw new GatewayHttpError("device_revoked", 403);
      await this.verifyDeviceProof(
        device.public_key,
        deviceProofMessage(
          "human_session",
          challengeId,
          challenge.challenge,
          deviceId,
        ),
        body.device_signature,
      );
    }
    this.markChallengeUsed(challengeId);
    return this.createHumanSessionResponse(credentialId, deviceId);
  }

  async freshAuthenticationOptions(
    kind:
      | "device_revoke"
      | "credential_authorization"
      | "credential_revoke"
      | "gateway_unlock"
      | "requester_rename"
      | "requester_revoke",
    targetId: string,
    payload?: Record<string, unknown>,
  ): Promise<Response> {
    const credentials = this.listHumanCredentials();
    const options = await generateAuthenticationOptions({
      allowCredentials: credentials.map((credential) => ({
        id: credential.id,
        transports: parseTransports(credential.transports),
      })),
      rpID: this.env.RP_ID,
      timeout: 60_000,
      userVerification: "required",
    });
    const challengeId = this.storeChallenge({
      challenge: options.challenge,
      kind,
      ...(payload ? { payload: JSON.stringify(payload) } : {}),
      targetId,
    });
    return json({ challenge_id: challengeId, options });
  }

  async verifyHumanAuthentication(
    responseValue: Record<string, unknown>,
    expectedChallenge: string,
  ): Promise<string> {
    const credentialId = safeIdentifier(responseValue.id, "credential_id");
    const row = this.humanCredential(credentialId);
    const credential: WebAuthnCredential = {
      counter: row.counter,
      id: row.id,
      publicKey: ownedBytes(decodeBase64Url(row.public_key)),
      transports: parseTransports(row.transports),
    };
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        credential,
        expectedChallenge,
        expectedOrigin: this.env.ORIGIN,
        expectedRPID: this.env.RP_ID,
        requireUserVerification: true,
        response: responseValue as unknown as AuthenticationResponseJSON,
      });
    } catch {
      throw new GatewayHttpError("webauthn_verification_failed", 401);
    }
    if (!verification.verified || !verification.authenticationInfo.userVerified) {
      throw new GatewayHttpError("webauthn_verification_failed", 401);
    }
    const updated = this.rows<{ id: string }>(
      REVALIDATE_HUMAN_CREDENTIAL_SQL,
      verification.authenticationInfo.newCounter,
      verification.authenticationInfo.credentialDeviceType,
      verification.authenticationInfo.credentialBackedUp ? 1 : 0,
      Date.now(),
      credentialId,
      row.counter,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("webauthn_verification_failed", 401);
    }
    return credentialId;
  }

  async requireHumanSession(
    request: Request,
  ): Promise<SessionRow> {
    const session = await this.requireHumanBaseSession(request);
    if (!session.device_id || !this.activeHumanDevice(session.device_id)) {
      throw new GatewayHttpError("device_not_enrolled", 403);
    }
    const now = Date.now();
    this.sql.exec(
      `UPDATE human_devices SET last_seen_at = ?
       WHERE id = ? AND revoked_at IS NULL AND last_seen_at <= ?`,
      now,
      session.device_id,
      now - HUMAN_DEVICE_LAST_SEEN_WRITE_INTERVAL_MS,
    );
    return session;
  }

  async requireHumanBaseSession(request: Request): Promise<SessionRow> {
    const session = await this.readSession(request);
    if (!session) throw new GatewayHttpError("session_expired", 401);
    return session;
  }

  async requireHumanMutation(
    request: Request,
  ): Promise<SessionRow> {
    this.requireExpectedOrigin(request);
    const session = await this.requireHumanSession(request);
    const csrf = request.headers.get("x-csrf-token");
    if (!csrf || !constantTimeStringEquals(csrf, session.csrf_token)) {
      throw new GatewayHttpError("csrf_invalid", 403);
    }
    return session;
  }

  async requireHumanBaseMutation(request: Request): Promise<SessionRow> {
    this.requireExpectedOrigin(request);
    const session = await this.requireHumanBaseSession(request);
    const csrf = request.headers.get("x-csrf-token");
    if (!csrf || !constantTimeStringEquals(csrf, session.csrf_token)) {
      throw new GatewayHttpError("csrf_invalid", 403);
    }
    return session;
  }

  requireExpectedOrigin(request: Request): void {
    if (request.headers.get("origin") !== this.env.ORIGIN) {
      throw new GatewayHttpError("origin_invalid", 403);
    }
  }

  async readSession(
    request: Request,
  ): Promise<SessionRow | undefined> {
    const token = readCookie(request.headers.get("cookie"), SESSION_COOKIE);
    if (!token) return undefined;
    const tokenHash = await sha256Base64Url(token);
    return this.first<SessionRow>(
      `SELECT token_hash, credential_id, device_id, csrf_token, expires_at
       FROM human_sessions
       WHERE token_hash = ? AND expires_at > ?`,
      tokenHash,
      Date.now(),
    );
  }

  async ensureBootstrapSession(request: Request): Promise<{
    headers: Record<string, string>;
    id: string;
  }> {
    const token = readCookie(
      request.headers.get("cookie"),
      BOOTSTRAP_SESSION_COOKIE,
    );
    if (token && /^[A-Za-z0-9_-]{43}$/u.test(token)) {
      return {
        headers: {},
        id: await bootstrapRequestIdForToken(token),
      };
    }

    const newToken = randomToken(32);
    return {
      headers: {
        "set-cookie": `${BOOTSTRAP_SESSION_COOKIE}=${newToken}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${String(
          Math.floor(BOOTSTRAP_SESSION_TTL_MS / 1_000),
        )}`,
      },
      id: await bootstrapRequestIdForToken(newToken),
    };
  }

  async readBootstrapSession(
    request: Request,
    expectedId?: string,
  ): Promise<BootstrapSessionRow> {
    const token = readCookie(
      request.headers.get("cookie"),
      BOOTSTRAP_SESSION_COOKIE,
    );
    if (!token) {
      throw new GatewayHttpError("bootstrap_session_invalid", 403);
    }
    if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) {
      throw new GatewayHttpError("bootstrap_session_invalid", 403);
    }
    const tokenId = await bootstrapRequestIdForToken(token);
    if (expectedId !== undefined && tokenId !== expectedId) {
      throw new GatewayHttpError("bootstrap_session_invalid", 403);
    }
    const session = this.first<BootstrapSessionRow>(
      `SELECT id, armed_until, consumed_at, expires_at
       FROM bootstrap_sessions
       WHERE id = ? AND consumed_at IS NULL AND expires_at > ?`,
      tokenId,
      Date.now(),
    );
    if (!session) {
      throw new GatewayHttpError("bootstrap_session_invalid", 403);
    }
    return session;
  }

  async createHumanSessionResponse(
    credentialId: string,
    deviceId: string | null,
  ): Promise<Response> {
    const token = randomToken(32);
    const csrfToken = randomToken(24);
    const createdAt = Date.now();
    const expiresAt = absoluteHumanSessionExpiry(createdAt);
    this.sql.exec(
      `INSERT INTO human_sessions
        (token_hash, credential_id, device_id, csrf_token, created_at,
         last_seen_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      await sha256Base64Url(token),
      credentialId,
      deviceId,
      csrfToken,
      createdAt,
      createdAt,
      expiresAt,
    );
    return json(
      { csrf_token: csrfToken, device_trusted: Boolean(deviceId), ok: true },
      200,
      {
        "set-cookie": `${SESSION_COOKIE}=${token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${String(
          Math.floor(HUMAN_SESSION_TTL_MS / 1_000),
        )}`,
        "x-csrf-token": csrfToken,
      },
    );
  }

  storeChallenge(input: {
    challenge: string;
    decision?: string;
    kind: ChallengeKind;
    payload?: string;
    targetId?: string;
  }): string {
    const id = crypto.randomUUID();
    this.sql.exec(
      `INSERT INTO webauthn_challenges
        (id, kind, challenge, target_id, decision, payload, expires_at, used_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      id,
      input.kind,
      input.challenge,
      input.targetId ?? null,
      input.decision ?? null,
      input.payload ?? null,
      Date.now() + CHALLENGE_TTL_MS,
    );
    return id;
  }

  getChallenge(
    id: string,
    kind: ChallengeKind,
    targetId: string | undefined,
    decision: string | undefined,
  ): ChallengeRow {
    const row = this.first<ChallengeRow>(
      `SELECT id, kind, challenge, target_id, decision, payload, expires_at, used_at
       FROM webauthn_challenges WHERE id = ?`,
      id,
    );
    if (
      !row ||
      row.kind !== kind ||
      row.used_at !== null ||
      row.expires_at <= Date.now() ||
      (targetId !== undefined && row.target_id !== targetId) ||
      (decision !== undefined && row.decision !== decision)
    ) {
      throw new GatewayHttpError("challenge_invalid", 409);
    }
    return row;
  }

  markChallengeUsed(id: string): void {
    const updated = this.rows<{ id: string }>(
      `UPDATE webauthn_challenges SET used_at = ?
       WHERE id = ? AND used_at IS NULL
       RETURNING id`,
      Date.now(),
      id,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("challenge_invalid", 409);
    }
  }

  activeHumanDevice(id: string): HumanDeviceRow | undefined {
    return this.first<HumanDeviceRow>(
      `SELECT id, label, platform, public_key, created_at, last_seen_at, revoked_at
       FROM human_devices WHERE id = ? AND revoked_at IS NULL`,
      id,
    );
  }

  activeHumanDeviceCount(): number {
    return (
      this.first<{ count: number }>(
        `SELECT COUNT(*) AS count FROM human_devices WHERE revoked_at IS NULL`,
      )?.count ?? 0
    );
  }

  async verifyDeviceProof(
    publicKeyJson: string,
    message: string,
    signatureValue: unknown,
  ): Promise<void> {
    if (typeof signatureValue !== "string") {
      throw new GatewayHttpError("device_proof_invalid", 401);
    }
    let publicKey: CryptoKey;
    let signature: Uint8Array<ArrayBuffer>;
    try {
      publicKey = await crypto.subtle.importKey(
        "jwk",
        JSON.parse(publicKeyJson) as JsonWebKey,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      signature = ownedBytes(decodeBase64Url(signatureValue));
    } catch {
      throw new GatewayHttpError("device_proof_invalid", 401);
    }
    const verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      signature,
      new TextEncoder().encode(message),
    );
    if (!verified) throw new GatewayHttpError("device_proof_invalid", 401);
  }

  humanCredential(id: string): HumanCredentialRow {
    const row = this.first<HumanCredentialRow>(
      `SELECT id, public_key, counter, transports, device_type, backed_up, label,
              created_at, last_used_at, revoked_at
       FROM human_credentials WHERE id = ? AND revoked_at IS NULL`,
      id,
    );
    if (!row) throw new GatewayHttpError("credential_not_found", 401);
    return row;
  }

  listHumanCredentials(): HumanCredentialRow[] {
    return this.rows<HumanCredentialRow>(
        `SELECT id, public_key, counter, transports, device_type, backed_up, label,
                created_at, last_used_at, revoked_at
         FROM human_credentials WHERE revoked_at IS NULL ORDER BY created_at ASC`,
      );
  }

  hasHumanCredential(): boolean {
    return Boolean(
      this.first<{ id: string }>(
        `SELECT id FROM human_credentials
         WHERE revoked_at IS NULL LIMIT 1`,
      ),
    );
  }

  bootstrapWasUsed(): boolean {
    return Boolean(
      this.first<{ singleton: number }>(
        `SELECT singleton FROM gateway_bootstrap_state WHERE singleton = 1`,
      ),
    );
  }
}
