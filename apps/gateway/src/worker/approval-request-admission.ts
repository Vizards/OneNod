import {
  canonicalJsonSha256Base64Url,
  decodeBase64Url,
  type ApplicationAuthorizationScopeRequest,
  type CatalogSearchRequest,
  type ItemMutationRequest,
  type SecretReadCreateRequest,
  type SshSignCreateRequest,
} from "@onenod/protocol";

import { ownedBytes } from "../shared/owned-bytes.js";
import {
  type CatalogExecutorItem,
} from "./gateway-envelope.js";
import {
  describeItemMutation,
  mutationExecutorBody,
  parseItemMutationRequest,
} from "./item-mutation.js";
import {
  ACTIVE_SECRET_GRANT_LOOKUP_PREDICATE,
  ACTIVE_SSH_GRANT_LOOKUP_PREDICATE,
} from "./authorization-grants.js";
import {
  publicRequestState,
  projectRequesterStatus,
  readOnlyRequestState,
} from "./approval-projection.js";
import {
  GatewayHttpError,
  advanceRateWindow,
  applicationIdentityColumns,
  assertExactKeys,
  classifyStorageError,
  iso,
  json,
  readJsonObject,
  safeApplicationAuthorizationScope,
  safeErrorName,
  safeIdentifier,
  safePositiveInteger,
  safeText,
  verifiedClientObservation,
} from "./approval-http.js";
import { insertRequest } from "./approval-request-repository.js";
import { ApprovalRequestStore } from "./approval-request-store.js";
import { ApprovalExecutor } from "./approval-executor.js";
import { ApprovalNotifications } from "./approval-notifications.js";
import { HumanAccess } from "./human-access.js";
import {
  encryptPendingPayload,
  type EncryptedPendingPayload,
} from "./pending-payload.js";
import {
  applicationBoundSshAuthorizationSession,
  describeAuthorizedSshSign,
  describeSshSign,
  parseSshSignRequest,
  sshAuthorizationProofMaterial,
  sshSignExecutorBody,
} from "./ssh-sign.js";
import {
  pollingTokensMatch,
  readRequestPollingBearer,
} from "./request-polling.js";
import { RequesterAccess } from "./requester-access.js";
import type { RequesterIdentity } from "./requester-auth.js";
import type {
  RateWindow,
  RequestCreationReservation,
  SecretAuthorizationGrantRow,
  SshAuthorizationGrantRow,
  ValidatedClientObservation,
} from "./approval-types.js";

const APPROVAL_TTL_MS = 2 * 60_000;
const AUTHORIZATION_TTL_MS = 30_000;
const CATALOG_RATE_WINDOW_MS = 60_000;
const CATALOG_RATE_MAX = 30;
const CATALOG_RATE_MAX_ENTRIES = 2_048;

export interface ApprovalRequestAdmissionCallbacks {
  assertRememberedSecretReadRate(requesterDeviceId: string, grantId: string): void;
  assertRememberedSshSignRate(requesterDeviceId: string, grantId: string): void;
  assertStorageGrowthAllowed(): void;
  audit(event: string, requestId?: string, actorId?: string): void;
  releaseRequestCreationRate(reservation: RequestCreationReservation): void;
  reserveNewApproval(requesterDeviceId: string, mutation: boolean): () => void;
  reserveRequestCreationRate(
    requesterDeviceId: string,
    body: unknown,
  ): RequestCreationReservation | undefined;
}

/** Authenticated request admission, idempotent creation, and grant lookup. */
export class ApprovalRequestAdmission {
  private readonly catalogWindows = new Map<string, RateWindow>();

  constructor(
    private readonly ctx: DurableObjectState,
    private readonly env: Env,
    private readonly executor: ApprovalExecutor,
    private readonly human: HumanAccess,
    private readonly notifications: ApprovalNotifications,
    private readonly requester: RequesterAccess,
    private readonly requestStore: ApprovalRequestStore,
    private readonly callbacks: ApprovalRequestAdmissionCallbacks,
  ) {}

  private get sql(): SqlStorage { return this.ctx.storage.sql; }

  private first<T>(query: string, ...bindings: unknown[]): T | undefined {
    return this.sql.exec<Record<string, SqlStorageValue>>(query, ...bindings)
      .toArray()[0] as unknown as T | undefined;
  }

  private assertCatalogRate(requesterDeviceId: string): void {
    const now = Date.now();
    const current = this.catalogWindows.get(requesterDeviceId) ?? {
      count: 0,
      startedAt: now,
    };
    this.catalogWindows.delete(requesterDeviceId);
    this.catalogWindows.set(
      requesterDeviceId,
      advanceRateWindow(
        current,
        now,
        CATALOG_RATE_WINDOW_MS,
        CATALOG_RATE_MAX,
        "catalog_rate_limited",
      ),
    );
    while (this.catalogWindows.size > CATALOG_RATE_MAX_ENTRIES) {
      const oldest = this.catalogWindows.keys().next().value as
        | string
        | undefined;
      if (!oldest) break;
      this.catalogWindows.delete(oldest);
    }
  }

  async catalogSearch(
    request: Request,
    path: string,
  ): Promise<Response> {
    const body = await readJsonObject<CatalogSearchRequest>(request);
    const requester = await this.requester.authenticateSignedRequest(
      request,
      path,
      body,
    );
    if (this.human.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
    // Best-effort protection for the external 1Password quota and runaway
    // requester loops. This in-memory window is deliberately not an auth gate.
    this.assertCatalogRate(requester.deviceId);
    const query =
      body.query === ""
        ? ""
        : safeText(body.query, 128);
    const items = await this.executor.executeCatalog(query);
    this.human.assertGatewayUnlocked();
    this.requester.assertRequesterActive(requester.deviceId);
    return json({ items });
  }

  async createApprovalRequest(
    request: Request,
    path: string,
  ): Promise<Response> {
    const body = await readJsonObject<
      SecretReadCreateRequest | ItemMutationRequest | SshSignCreateRequest
    >(request);
    let rateReservation: RequestCreationReservation | undefined;
    try {
      const requester = await this.requester.authenticateSignedRequest(
        request,
        path,
        body,
        (identity) => {
          // Storage pressure is independent of requester identity, but running
          // this hook after signature verification avoids exposing diagnostics
          // to unauthenticated callers while still rejecting before nonce growth.
          this.callbacks.assertStorageGrowthAllowed();
          rateReservation = this.callbacks.reserveRequestCreationRate(identity.deviceId, body);
        },
      );
      if (this.human.gatewayRuntimeState().locked === 1) {
        this.callbacks.audit("locked_request_rejected", undefined, requester.deviceId);
        throw new GatewayHttpError("gateway_locked", 423);
      }
      const context = await verifiedClientObservation(
        body.client,
        request,
        requester,
      );
      if (
        body.action === "item.create" ||
        body.action === "item.patch" ||
        body.action === "item.archive"
      ) {
        return await this.createItemMutationRequest(body, requester, context);
      }
      if (body.action === "ssh.sign") {
        return await this.createSshSignRequest(body, requester, context);
      }
      if (body.action !== "secret.read") {
        throw new GatewayHttpError("unsupported_action", 400);
      }
      assertExactKeys(body, [
        "action",
        ...(body.authorization_scope === undefined ? [] : ["authorization_scope"]),
        "client",
        "expected_version",
        "field_id",
        "idempotency_key",
        "item_id",
      ]);
      const authorizationScope = body.authorization_scope === undefined
        ? undefined
        : safeApplicationAuthorizationScope(body.authorization_scope);
      if (
        authorizationScope &&
        (context.identity.assurance !== "verified-code-signature" ||
          authorizationScope.scope_id !== context.identity.principal_id)
      ) {
        throw new GatewayHttpError("authorization_scope_invalid", 400);
      }
      const itemId = safeIdentifier(body.item_id, "item_id");
      const fieldId = safeIdentifier(body.field_id, "field_id");
      const expectedVersion = safePositiveInteger(
        body.expected_version,
        "expected_version",
      );
      const idempotencyKey = safeIdentifier(
        body.idempotency_key,
        "idempotency_key",
      );
      const bodyHash = await canonicalJsonSha256Base64Url(body);
      const existing = this.first<{
        body_hash: string;
        expires_at: number;
        id: string;
        status: string;
      }>(
        `SELECT id, status, expires_at, body_hash FROM requests
         WHERE requester_device_id = ? AND idempotency_key = ?`,
        requester.deviceId,
        idempotencyKey,
      );
      if (existing) {
        if (existing.body_hash !== bodyHash) {
          throw new GatewayHttpError("idempotency_conflict", 409);
        }
        return json({
          expires_at: iso(existing.expires_at),
          poll_token: await this.requester.requestPollingToken(
            existing.id,
            requester.deviceId,
          ),
          request_id: existing.id,
          status: publicRequestState(existing.status),
        });
      }
      const releaseApproval = this.callbacks.reserveNewApproval(requester.deviceId, false);
      try {
        const grant = authorizationScope
          ? this.activeSecretAuthorization(
              requester.deviceId,
              authorizationScope,
              itemId,
              fieldId,
              expectedVersion,
            )
          : undefined;
        if (grant) {
          this.callbacks.assertRememberedSecretReadRate(requester.deviceId, grant.id);
        }
        const metadata = grant
          ? {
              field_label: grant.field_label,
              field_type: grant.field_type,
              item_title: grant.item_title,
              version: grant.item_version,
            }
          : this.executor.cachedSecretMetadata(itemId, fieldId, expectedVersion) ??
            (await this.executor.executeSecretMetadata(itemId, fieldId));
        if (metadata.version !== expectedVersion) {
          throw new GatewayHttpError("item_stale", 409);
        }
        const now = Date.now();
        const expiresAt = now + APPROVAL_TTL_MS;
        const requestId = crypto.randomUUID();
        const initialStatus = grant ? "approved" : "pending";
        const authorizedUntil = grant ? now + AUTHORIZATION_TTL_MS : null;
        const requestRecord = {
          action: "secret.read",
          application_scope_id: authorizationScope?.scope_id ?? null,
          authorized_until: authorizedUntil,
          body_hash: bodyHash,
          client_application: context.application,
          client_source: context.source,
          consumed_at: null,
          created_at: now,
          decided_at: grant ? now : null,
          error_code: null,
          execution_started_at: null,
          expected_version: expectedVersion,
          expires_at: expiresAt,
          field_id: fieldId,
          field_label: metadata.field_label,
          field_type: metadata.field_type,
          id: requestId,
          idempotency_key: idempotencyKey,
          item_id: itemId,
          item_title: metadata.item_title,
          requester_device_id: requester.deviceId,
          requester_name: requester.displayName,
          secret_grant_id: grant?.id ?? null,
          ssh_agent_instance_public_key: null,
          ssh_grant_id: null,
          ssh_scope_id: null,
          ssh_scope_kind: null,
          status: initialStatus,
          ...applicationIdentityColumns(context.identity),
        };
        try {
          this.callbacks.assertStorageGrowthAllowed();
          this.human.assertGatewayUnlocked();
          insertRequest(this.sql, requestRecord);
        } catch (error) {
          console.error(
            JSON.stringify({
              errorName: safeErrorName(error),
              event: "request_creation_stage_failed",
              stage: "persist_request",
              storageErrorClass: classifyStorageError(error),
            }),
          );
          throw error;
        }
        try {
          this.callbacks.audit(
            grant ? "request_auto_approved" : "request_created",
            requestId,
            grant?.id ?? requester.deviceId,
          );
        } catch (error) {
          console.error(
            JSON.stringify({
              errorName: safeErrorName(error),
              event: "request_creation_stage_failed",
              stage: "persist_audit",
            }),
          );
          throw error;
        }
        this.notifications.broadcastHumanEvent("request.changed", requestId);
        if (!grant) {
          this.notifications.queueApprovalPush({
            body: "Open the approval queue to approve or deny this request.",
            requestId,
            tag: `request-${requestId}`,
            title: "New 1Password approval request",
            url: `/requests#request-${requestId}`,
          });
        }
        return json(
          {
            expires_at: iso(expiresAt),
            poll_token: await this.requester.requestPollingToken(requestId, requester.deviceId),
            request_id: requestId,
            status: initialStatus,
          },
          201,
        );
      } finally {
        releaseApproval();
      }
    } finally {
      if (rateReservation) this.callbacks.releaseRequestCreationRate(rateReservation);
    }
  }

  private async createItemMutationRequest(
    rawBody: ItemMutationRequest,
    requester: RequesterIdentity,
    context: ValidatedClientObservation,
  ): Promise<Response> {
    let body: ItemMutationRequest;
    try {
      body = parseItemMutationRequest(rawBody);
    } catch {
      throw new GatewayHttpError("item_operation_invalid", 400);
    }
    const bodyHash = await canonicalJsonSha256Base64Url(rawBody);
    const existing = this.first<{
      body_hash: string;
      expires_at: number;
      id: string;
      status: string;
    }>(
      `SELECT id, status, expires_at, body_hash FROM requests
       WHERE requester_device_id = ? AND idempotency_key = ?`,
      requester.deviceId,
      body.idempotency_key,
    );
    if (existing) {
      if (existing.body_hash !== bodyHash) {
        throw new GatewayHttpError("idempotency_conflict", 409);
      }
      return json({
        expires_at: iso(existing.expires_at),
        poll_token: await this.requester.requestPollingToken(
          existing.id,
          requester.deviceId,
        ),
        request_id: existing.id,
        status: publicRequestState(existing.status),
      });
    }

    const releaseApproval = this.callbacks.reserveNewApproval(requester.deviceId, true);
    try {
      const requestId = crypto.randomUUID();
      const now = Date.now();
      const expiresAt = now + APPROVAL_TTL_MS;
      let metadata: CatalogExecutorItem | undefined;
      if (body.action !== "item.create") {
        metadata = await this.executor.executeItemMetadata(body.item_id);
        if (metadata.version !== body.expected_version) {
          throw new GatewayHttpError("item_stale", 409);
        }
      }
      let encrypted: EncryptedPendingPayload | undefined;
      if (body.action !== "item.archive") {
        if (!this.env.GATEWAY_MASTER_KEY) {
          throw new GatewayHttpError("gateway_master_key_not_configured", 503);
        }
        try {
          encrypted = await encryptPendingPayload(
            this.env.GATEWAY_MASTER_KEY,
            {
              action: body.action,
              environment: this.env.APP_ENV,
              expiresAt,
              requestId,
              requesterDeviceId: requester.deviceId,
            },
            mutationExecutorBody(body, requestId),
          );
        } catch {
          throw new GatewayHttpError("gateway_master_key_invalid", 503);
        }
      }
      let description;
      try {
        description = describeItemMutation(body, metadata, encrypted?.digest);
      } catch (error) {
        if (error instanceof Error && error.message === "item_stale") {
          throw new GatewayHttpError("item_stale", 409);
        }
        if (error instanceof Error && error.message === "field_not_found") {
          throw new GatewayHttpError("field_not_found", 404);
        }
        throw new GatewayHttpError("item_operation_invalid", 400);
      }
      const requestRecord = {
        action: body.action,
        application_scope_id: null,
        authorized_until: null,
        body_hash: bodyHash,
        client_application: context.application,
        client_source: context.source,
        consumed_at: null,
        created_at: now,
        decided_at: null,
        error_code: null,
        execution_started_at: null,
        expected_version: description.expectedVersion,
        expires_at: expiresAt,
        field_id: "",
        field_label: description.fieldLabel,
        field_type: description.fieldType,
        id: requestId,
        idempotency_key: body.idempotency_key,
        item_id: description.itemId,
        item_title: description.itemTitle,
        requester_device_id: requester.deviceId,
        requester_name: requester.displayName,
        secret_grant_id: null,
        ssh_agent_instance_public_key: null,
        ssh_grant_id: null,
        ssh_scope_id: null,
        ssh_scope_kind: null,
        status: "pending",
        ...applicationIdentityColumns(context.identity),
      };
      this.ctx.storage.transactionSync(() => {
        this.callbacks.assertStorageGrowthAllowed();
        this.human.assertGatewayUnlocked();
        insertRequest(this.sql, requestRecord);
        this.sql.exec(
          `INSERT INTO request_operations
            (request_id, operation_summary, payload_aad, payload_ciphertext,
             payload_digest, payload_iv, reconcile_state, result_item_id,
             result_version)
           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
          requestId,
          JSON.stringify(description.summary),
          encrypted?.aad ?? null,
          encrypted?.ciphertext ?? null,
          encrypted?.digest ?? null,
          encrypted?.iv ?? null,
        );
        this.callbacks.audit("request_created", requestId, requester.deviceId);
      });
      this.notifications.broadcastHumanEvent("request.changed", requestId);
      this.notifications.queueApprovalPush({
        body: "Open the approval queue to approve or deny this request.",
        requestId,
        tag: `request-${requestId}`,
        title: "New 1Password approval request",
        url: `/requests#request-${requestId}`,
      });
      return json(
        {
          expires_at: iso(expiresAt),
          poll_token: await this.requester.requestPollingToken(requestId, requester.deviceId),
          request_id: requestId,
          status: "pending",
        },
        201,
      );
    } finally {
      releaseApproval();
    }
  }

  private async createSshSignRequest(
    rawBody: SshSignCreateRequest,
    requester: RequesterIdentity,
    context: ValidatedClientObservation,
  ): Promise<Response> {
    let body: SshSignCreateRequest;
    try {
      body = parseSshSignRequest(rawBody);
    } catch {
      throw new GatewayHttpError("ssh_sign_request_invalid", 400);
    }
    const claimedAuthorizationSession =
      await this.verifySshAuthorizationSession(body);
    let authorizationSession: SshSignCreateRequest["authorization_session"];
    try {
      authorizationSession = applicationBoundSshAuthorizationSession(
        context.identity,
        claimedAuthorizationSession,
      );
    } catch {
      throw new GatewayHttpError("ssh_authorization_session_invalid", 401);
    }
    const bodyHash = await canonicalJsonSha256Base64Url(rawBody);
    const existing = this.first<{
      body_hash: string;
      expires_at: number;
      id: string;
      status: string;
    }>(
      `SELECT id, status, expires_at, body_hash FROM requests
       WHERE requester_device_id = ? AND idempotency_key = ?`,
      requester.deviceId,
      body.idempotency_key,
    );
    if (existing) {
      if (existing.body_hash !== bodyHash) {
        throw new GatewayHttpError("idempotency_conflict", 409);
      }
      return json({
        expires_at: iso(existing.expires_at),
        poll_token: await this.requester.requestPollingToken(
          existing.id,
          requester.deviceId,
        ),
        request_id: existing.id,
        status: publicRequestState(existing.status),
      });
    }
    const releaseApproval = this.callbacks.reserveNewApproval(requester.deviceId, false);
    try {
      const grant = authorizationSession
        ? this.activeSshAuthorization(
            requester.deviceId,
            authorizationSession,
            body.item_id,
            body.expected_version,
            body.expected_fingerprint,
          )
        : undefined;
      if (grant) {
        this.callbacks.assertRememberedSshSignRate(requester.deviceId, grant.id);
      }
      const metadata = grant
        ? undefined
        : await this.executor.executeItemMetadata(body.item_id);
      if (!this.env.GATEWAY_MASTER_KEY) {
        throw new GatewayHttpError("gateway_master_key_not_configured", 503);
      }
      const requestId = crypto.randomUUID();
      const now = Date.now();
      const expiresAt = now + APPROVAL_TTL_MS;
      let encrypted: EncryptedPendingPayload;
      try {
        encrypted = await encryptPendingPayload(
          this.env.GATEWAY_MASTER_KEY,
          {
            action: "ssh.sign",
            environment: this.env.APP_ENV,
            expiresAt,
            requestId,
            requesterDeviceId: requester.deviceId,
          },
          sshSignExecutorBody(body),
        );
      } catch {
        throw new GatewayHttpError("gateway_master_key_invalid", 503);
      }
      let description;
      try {
        description = grant
          ? describeAuthorizedSshSign(
              body,
              {
                fingerprint: grant.fingerprint,
                itemId: grant.item_id,
                itemTitle: grant.item_title,
                itemVersion: grant.item_version,
              },
              encrypted.digest,
            )
          : describeSshSign(body, metadata!, encrypted.digest);
      } catch (error) {
        if (error instanceof Error && error.message === "item_stale") {
          throw new GatewayHttpError("item_stale", 409);
        }
        if (error instanceof Error && error.message === "ssh_key_mismatch") {
          throw new GatewayHttpError("ssh_key_mismatch", 409);
        }
        if (error instanceof Error && error.message === "ssh_algorithm_mismatch") {
          throw new GatewayHttpError("ssh_algorithm_mismatch", 400);
        }
        throw new GatewayHttpError("ssh_sign_request_invalid", 400);
      }
      const initialStatus = grant ? "approved" : "pending";
      const authorizedUntil = grant ? now + AUTHORIZATION_TTL_MS : null;
      const requestRecord = {
        action: "ssh.sign",
        application_scope_id: null,
        authorized_until: authorizedUntil,
        body_hash: bodyHash,
        client_application: context.application,
        client_source: context.source,
        consumed_at: null,
        created_at: now,
        decided_at: grant ? now : null,
        error_code: null,
        execution_started_at: null,
        expected_version: description.expectedVersion,
        expires_at: expiresAt,
        field_id: "",
        field_label: description.fingerprint,
        field_type: description.signatureAlgorithm,
        id: requestId,
        idempotency_key: body.idempotency_key,
        item_id: description.itemId,
        item_title: description.itemTitle,
        requester_device_id: requester.deviceId,
        requester_name: requester.displayName,
        secret_grant_id: null,
        ssh_agent_instance_public_key:
          authorizationSession?.agent_instance_public_key ?? null,
        ssh_grant_id: grant?.id ?? null,
        ssh_scope_id: authorizationSession?.scope_id ?? null,
        ssh_scope_kind: authorizationSession?.scope_kind ?? null,
        status: initialStatus,
        ...applicationIdentityColumns(context.identity),
      };
      this.ctx.storage.transactionSync(() => {
        this.callbacks.assertStorageGrowthAllowed();
        this.human.assertGatewayUnlocked();
        insertRequest(this.sql, requestRecord);
        this.sql.exec(
          `INSERT INTO request_operations
            (request_id, operation_summary, payload_aad, payload_ciphertext,
             payload_digest, payload_iv, reconcile_state, result_item_id,
             result_version)
           VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL)`,
          requestId,
          JSON.stringify(description.summary),
          encrypted.aad,
          encrypted.ciphertext,
          encrypted.digest,
          encrypted.iv,
        );
        this.callbacks.audit(
          grant ? "request_auto_approved" : "request_created",
          requestId,
          grant?.id ?? requester.deviceId,
        );
      });
      this.notifications.broadcastHumanEvent("request.changed", requestId);
      if (!grant) {
        this.notifications.queueApprovalPush({
          body: "Open the approval queue to approve or deny this request.",
          requestId,
          tag: `request-${requestId}`,
          title: "New 1Password approval request",
          url: `/requests#request-${requestId}`,
        });
      }
      return json(
        {
          expires_at: iso(expiresAt),
          poll_token: await this.requester.requestPollingToken(requestId, requester.deviceId),
          request_id: requestId,
          status: initialStatus,
        },
        201,
      );
    } finally {
      releaseApproval();
    }
  }

  private async verifySshAuthorizationSession(
    body: SshSignCreateRequest,
  ): Promise<SshSignCreateRequest["authorization_session"] | undefined> {
    const session = body.authorization_session;
    if (!session) return undefined;
    let publicKeyBytes: Uint8Array<ArrayBuffer>;
    let proofBytes: Uint8Array<ArrayBuffer>;
    try {
      publicKeyBytes = ownedBytes(
        decodeBase64Url(session.agent_instance_public_key),
      );
      proofBytes = ownedBytes(decodeBase64Url(session.proof));
    } catch {
      throw new GatewayHttpError("ssh_authorization_session_invalid", 400);
    }
    if (publicKeyBytes.byteLength !== 32 || proofBytes.byteLength !== 64) {
      throw new GatewayHttpError("ssh_authorization_session_invalid", 400);
    }
    let valid = false;
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        publicKeyBytes,
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      valid = await crypto.subtle.verify(
        "Ed25519",
        key,
        proofBytes,
        ownedBytes(sshAuthorizationProofMaterial(body)),
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new GatewayHttpError("ssh_authorization_session_invalid", 401);
    }
    return session;
  }

  private activeSshAuthorization(
    requesterDeviceId: string,
    session: NonNullable<SshSignCreateRequest["authorization_session"]>,
    itemId: string,
    itemVersion: number,
    fingerprint: string,
  ): SshAuthorizationGrantRow | undefined {
    const runtime = this.human.gatewayRuntimeState();
    if (runtime.locked === 1) return undefined;
    return this.first<SshAuthorizationGrantRow>(
      `SELECT id, requester_device_id, agent_instance_public_key, scope_id,
              scope_kind, item_id, item_title, item_version, fingerprint, duration,
              lock_generation, created_at, expires_at, revoked_at,
              authorized_by_credential_id
       FROM ssh_authorization_grants
       WHERE ${ACTIVE_SSH_GRANT_LOOKUP_PREDICATE}
       ORDER BY created_at DESC LIMIT 1`,
      requesterDeviceId,
      session.agent_instance_public_key,
      session.scope_id,
      session.scope_kind,
      itemId,
      itemVersion,
      fingerprint,
      Date.now(),
      runtime.lock_generation,
    );
  }

  private activeSecretAuthorization(
    requesterDeviceId: string,
    scope: ApplicationAuthorizationScopeRequest,
    itemId: string,
    fieldId: string,
    itemVersion: number,
  ): SecretAuthorizationGrantRow | undefined {
    const runtime = this.human.gatewayRuntimeState();
    if (runtime.locked === 1) return undefined;
    return this.first<SecretAuthorizationGrantRow>(
      `SELECT id, requester_device_id, scope_id, client_application,
              item_id, item_title, field_id, field_label, field_type,
              item_version, duration, lock_generation, created_at, expires_at,
              revoked_at, authorized_by_credential_id
       FROM secret_authorization_grants
       WHERE ${ACTIVE_SECRET_GRANT_LOOKUP_PREDICATE}
       ORDER BY created_at DESC LIMIT 1`,
      requesterDeviceId,
      scope.scope_id,
      itemId,
      fieldId,
      itemVersion,
      Date.now(),
      runtime.lock_generation,
    );
  }

  async requesterRequestStatus(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    const row = this.requestStore.findRequestRow(requestId);
    if (!row) throw new GatewayHttpError("request_not_found", 404);
    const activeRequester = this.first<{ device_id: string }>(
      `SELECT device_id FROM requesters
       WHERE device_id = ? AND revoked_at IS NULL`,
      row.requester_device_id,
    );
    if (!activeRequester) {
      // A polling capability is scoped to its requester identity. Revocation
      // invalidates it immediately without adding a nonce or any other write.
      throw new GatewayHttpError("request_not_found", 404);
    }
    const expected = await this.requester.requestPollingToken(
      requestId,
      row.requester_device_id,
    );
    if (!pollingTokensMatch(readRequestPollingBearer(request), expected)) {
      throw new GatewayHttpError("request_not_found", 404);
    }
    const projected = readOnlyRequestState(row, Date.now());
    return json(
      projectRequesterStatus(
        projected,
        projected.action === "secret.read"
          ? undefined
          : this.requestStore.requestOperation(projected.id),
      ),
    );
  }






}
