import { DurableObject } from "cloudflare:workers";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  canonicalJsonSha256Base64Url,
  decodeBase64Url,
  encodeBase64Url,
  requesterPublicKeyFingerprint,
  sha256Base64Url,
  type ApprovalDecision,
  type CatalogSearchRequest,
  type ClientObservationRequest,
  type HumanBootstrapRequest,
  type ItemMutationRequest,
  type RequesterEnrollmentRequest,
  type SecretReadCreateRequest,
  type SshAuthorizationDuration,
  type SshSignCreateRequest,
} from "@onenod/protocol";

import {
  DEFAULT_PASSKEY_LABEL,
  LEGACY_DEFAULT_PASSKEY_LABEL,
  PASSKEY_RP_NAME,
  PASSKEY_USER_DISPLAY_NAME,
  PASSKEY_USER_HANDLE,
  PASSKEY_USER_NAME,
} from "../passkey-identity.js";
import { ownedBytes } from "../shared/owned-bytes.js";

import {
  sanitizeCatalogEnvelope,
  sanitizeGatewayError,
  sanitizeItemMetadataEnvelope,
  sanitizeItemMutationEnvelope,
  sanitizeItemReconciliationEnvelope,
  sanitizeSecretMetadataEnvelope,
  sanitizeSecretReadEnvelope,
  sanitizeSshSignEnvelope,
  type CatalogExecutorItem,
  type ItemMutationExecutorResult,
  type ItemReconciliationExecutorResult,
  type SecretMetadataExecutorResult,
  type SecretReadExecutorResult,
  type SshSignExecutorResult,
} from "./gateway-envelope.js";
import {
  describeItemMutation,
  mutationExecutorBody,
  parseItemMutationRequest,
} from "./item-mutation.js";
import {
  resolveGatewayKeySentinel,
  type GatewayKeySentinelState,
  type GatewayKeySentinelStore,
} from "./gateway-key-sentinel.js";
import { bootstrapTokensMatch } from "./bootstrap-authorization.js";
import {
  decryptPendingPayload,
  encryptPendingPayload,
  type EncryptedPendingPayload,
} from "./pending-payload.js";
import {
  describeAuthorizedSshSign,
  describeSshSign,
  parseSshSignRequest,
  sshAuthorizationProofMaterial,
  sshSignExecutorBody,
} from "./ssh-sign.js";
import {
  RequesterAuthenticationError,
  authenticateRequester,
  type RequesterIdentity,
} from "./requester-auth.js";
import {
  deriveRequestPollingToken,
  pollingTokensMatch,
  readRequestPollingBearer,
} from "./request-polling.js";
import {
  ExecutorTransportError,
} from "./executor-transport.js";
import {
  callExecutorService,
  type ExecutorExecutionIdentity,
} from "./executor-service-transport.js";
import {
  deliverWebPush,
  validatePushSubscription,
  type ApprovalPushMessage,
  type PushDeliveryResult,
  type StoredPushSubscription,
} from "./web-push.js";
import {
  ACTIVITY_MAX_RECORDS,
  ACTIVITY_PAGE_SIZE,
  AUDIT_MAX_RECORDS,
  AUDIT_RETENTION_MS,
  CLEANUP_BATCH_SIZE,
  HUMAN_SESSION_TTL_MS,
  OPERATIONAL_REQUEST_MAX_RECORDS,
  OPERATIONAL_REQUEST_RETENTION_MS,
  REQUESTER_ENROLLMENT_RECEIPT_MS,
  RETENTION_SWEEP_INTERVAL_MS,
  REVOKED_PWA_DEVICE_RETENTION_MS,
  absoluteHumanSessionExpiry,
  decodeActivityCursor,
  encodeActivityCursor,
  storagePressure,
  type ActivityCursor,
} from "./retention-policy.js";

declare const EXECUTOR_FETCH_TIMEOUT_MS: number;
declare const RECONCILIATION_IMMEDIATE_ENABLED: boolean;
declare const RECONCILIATION_RETRY_DELAY_MS: number;

const SESSION_COOKIE = "__Host-approval_session";
const BOOTSTRAP_SESSION_COOKIE = "__Host-bootstrap_session";
const BOOTSTRAP_SESSION_TTL_MS = 10 * 60_000;
const CHALLENGE_TTL_MS = 2 * 60_000;
const ENROLLMENT_TTL_MS = 10 * 60_000;
const APPROVAL_TTL_MS = 2 * 60_000;
const AUTHORIZATION_TTL_MS = 30_000;
const SSH_GRANT_MAX_STORAGE_MS = 365 * 24 * 60 * 60_000;
const SSH_GRANT_DURATION_MS: Partial<Record<SshAuthorizationDuration, number>> = {
  "4-hours": 4 * 60 * 60_000,
  "12-hours": 12 * 60 * 60_000,
  "24-hours": 24 * 60 * 60_000,
};
const BOOTSTRAP_AUTHORIZATION_TTL_MS = 2 * 60_000;
const EXECUTION_STALE_MS = 5 * 60_000;
const MAX_JSON_BYTES = 64 * 1024;
const MAX_JSON_RESPONSE_BYTES = 256 * 1024;
const HUMAN_EVENT_SOCKET_TAG = "human-events";
const CATALOG_METADATA_CACHE_TTL_MS = 2 * 60_000;
const CATALOG_METADATA_CACHE_MAX_ENTRIES = 2_048;
const HUMAN_DEVICE_LAST_SEEN_WRITE_INTERVAL_MS = 5 * 60_000;
const MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS = 3;
const REQUEST_CREATE_RATE_WINDOW_MS = 60_000;
const REQUEST_CREATE_RATE_MAX = 60;
const REMEMBERED_SSH_SIGN_RATE_MAX = 30;
const REQUESTER_ENROLLMENT_RATE_WINDOW_MS = 5 * 60_000;
const REQUESTER_ENROLLMENT_RATE_MAX = 20;
const INGRESS_RATE_WINDOW_MS = 60_000;
const INGRESS_RATE_GLOBAL_MAX = 600;
const INGRESS_RATE_CLIENT_MAX = 120;
const INGRESS_RATE_CLIENT_MAX_ENTRIES = 512;
const REQUESTER_AUTH_RATE_MAX = 180;
const REQUESTER_AUTH_RATE_MAX_ENTRIES = 2_048;
const MAX_PUSH_FANOUT = 16;
const MAX_PUSH_CONCURRENCY = 4;
const PUSH_FAILURE_DELETE_THRESHOLD = 5;
const MAX_EXECUTOR_CONCURRENCY = 4;
const GATEWAY_CRYPTO_STATE_PATH = "/internal/gateway/crypto-state";
const REQUEST_INSERT_COLUMNS = [
  "id",
  "requester_device_id",
  "requester_name",
  "action",
  "item_id",
  "field_id",
  "expected_version",
  "client_application",
  "client_source",
  "ssh_agent_instance_public_key",
  "ssh_scope_id",
  "ssh_scope_kind",
  "ssh_grant_id",
  "item_title",
  "field_label",
  "field_type",
  "idempotency_key",
  "body_hash",
  "status",
  "created_at",
  "expires_at",
  "decided_at",
  "authorized_until",
  "execution_started_at",
  "consumed_at",
  "error_code",
] as const;
const REQUEST_INSERT_SQL = `INSERT INTO requests
  (${REQUEST_INSERT_COLUMNS.join(", ")})
  VALUES (${REQUEST_INSERT_COLUMNS.map(() => "?").join(", ")})`;

type ChallengeKind =
  | "bootstrap"
  | "human_session"
  | "requester_enrollment"
  | "approval"
  | "device_registration"
  | "device_revoke"
  | "credential_authorization"
  | "credential_registration"
  | "credential_revoke"
  | "gateway_unlock"
  | "requester_rename"
  | "requester_revoke";

type RequestState =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | "executing"
  | "consumed"
  | "error"
  | "unknown";

interface HumanCredentialRow {
  backed_up: number;
  counter: number;
  created_at: number;
  device_type: string;
  id: string;
  label: string;
  last_used_at: number | null;
  public_key: string;
  revoked_at: number | null;
  transports: string;
}

interface ChallengeRow {
  challenge: string;
  decision: string | null;
  expires_at: number;
  id: string;
  kind: string;
  payload: string | null;
  target_id: string | null;
  used_at: number | null;
}

interface SessionRow {
  credential_id: string;
  csrf_token: string;
  device_id: string | null;
  expires_at: number;
  token_hash: string;
}

interface HumanDeviceRow {
  created_at: number;
  id: string;
  label: string;
  last_seen_at: number;
  platform: string;
  public_key: string;
  revoked_at: number | null;
}

interface PushSubscriptionRow {
  auth: string;
  device_id: string;
  endpoint: string;
  expiration_time: number | null;
  failure_count: number;
  p256dh: string;
}

interface CatalogMetadataCacheRow {
  cached_at: number;
  field_id: string;
  field_label: string;
  field_type: string;
  item_id: string;
  item_title: string;
  version: number;
}

interface RequestActivityRow {
  action: string;
  client_application: string;
  client_source: string;
  consumed_at: number | null;
  created_at: number;
  decided_at: number | null;
  error_code: string | null;
  expected_version: number;
  expires_at: number;
  field_label: string;
  item_title: string;
  request_id: string;
  requester_name: string;
  status: string;
  terminal_at: number;
}

interface EventSocketAttachment {
  credentialId: string;
  deviceId: string;
  expiresAt: number;
  sessionHash: string;
}

interface RateWindow {
  count: number;
  startedAt: number;
}

interface RequestCreationReservation {
  rememberedSsh: boolean;
  requesterDeviceId: string;
}

interface RetentionSweepStateRow {
  activity_backfill_done: number;
  activity_backfill_cursor_created_at: number | null;
  activity_backfill_cursor_id: string | null;
  activity_cutoff_created_at: number | null;
  activity_cutoff_id: string | null;
  activity_trim_done: number;
  audit_cutoff_created_at: number | null;
  audit_cutoff_id: number | null;
  audit_trim_done: number;
  request_cutoff_created_at: number | null;
  request_cutoff_id: string | null;
  request_trim_done: number;
  retention_active: number;
  retention_started_at: number | null;
}

interface BootstrapSessionRow {
  armed_until: number | null;
  consumed_at: number | null;
  expires_at: number;
  id: string;
}

interface EnrollmentRow {
  created_at: number;
  device_id: string;
  display_name: string;
  expires_at: number;
  id: string;
  public_key: string;
  public_key_fingerprint: string;
  status: string;
  terminal_at: number | null;
}

interface RequesterRow {
  created_at: number;
  device_id: string;
  display_name: string;
  public_key: string;
  revoked_at: number | null;
}

interface RequestRow {
  action: string;
  authorized_until: number | null;
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
  item_id: string;
  item_title: string;
  operation_summary: string | null;
  requester_device_id: string;
  requester_name: string;
  ssh_agent_instance_public_key: string | null;
  ssh_grant_id: string | null;
  ssh_scope_id: string | null;
  ssh_scope_kind: string | null;
  status: string;
}

interface SshAuthorizationGrantRow {
  agent_instance_public_key: string;
  authorized_by_credential_id: string;
  client_application?: string;
  created_at: number;
  duration: string;
  expires_at: number | null;
  fingerprint: string;
  id: string;
  item_id: string;
  item_title: string;
  item_version: number;
  lock_generation: number;
  requester_device_id: string;
  revoked_at: number | null;
  scope_id: string;
  scope_kind: string;
}

interface GatewayRuntimeStateRow {
  changed_at: number;
  changed_by: string;
  lock_generation: number;
  locked: number;
}

interface RequestOperationRow {
  operation_summary: string;
  payload_aad: string | null;
  payload_ciphertext: string | null;
  payload_digest: string | null;
  payload_iv: string | null;
  reconcile_state: string | null;
  reconcile_attempt_count: number;
  reconcile_attempted_at: number | null;
  request_id: string;
  result_item_id: string | null;
  result_version: number | null;
}

class GatewayHttpError extends Error {
  override readonly name = "GatewayHttpError";

  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(code);
  }
}

export class ApprovalCoordinator extends DurableObject<Env> {
  private readonly catalogMetadataCache = new Map<string, CatalogMetadataCacheRow>();
  private executorInFlight = 0;
  private gatewayKeySentinelState!: GatewayKeySentinelState;
  private ingressGlobalWindow: RateWindow = { count: 0, startedAt: 0 };
  private readonly ingressClientWindows = new Map<string, RateWindow>();
  private readonly requesterAuthWindows = new Map<string, RateWindow>();
  private approvalReservationsGlobal = 0;
  private readonly approvalReservationsByRequester = new Map<string, number>();
  private mutationReservations = 0;
  private readonly requestCreationReservations = new Map<string, number>();
  private readonly rememberedSshCreationReservations = new Map<string, number>();
  private storageWarningReported = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.blockConcurrencyWhile(async () => {
      this.initializeSchema();
      this.gatewayKeySentinelState = await resolveGatewayKeySentinel({
        masterKey: this.env.GATEWAY_MASTER_KEY,
        store: this.gatewayKeySentinelStore(),
      });
    });
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const readOnlyStatusPoll =
      request.method === "GET" &&
      /^\/v1\/requests\/[^/]+\/status$/u.test(url.pathname);
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
      this.assertIngressRate(request);
      this.requireGatewayKeySentinel();
      try {
        return await this.route(request);
      } finally {
        if (!readOnlyStatusPoll) {
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
      this.expireDueState(now);
      if (this.retentionSweepDue(now)) {
        this.runRetentionSweep(now);
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
        const row = this.requestRow(candidate.id);
        await this.tryReconcileUnknownMutation(
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
      this.safeCloseSocket(socket, 1011, "gateway_crypto_unavailable");
      return;
    }
    const attachment = socket.deserializeAttachment() as EventSocketAttachment | null;
    if (!attachment || attachment.expiresAt <= Date.now() || !this.isActiveEventSession(attachment)) {
      this.safeCloseSocket(socket, 4401, "session_expired");
      return;
    }
    if (message === "ping") {
      try {
        socket.send(JSON.stringify({ at: iso(Date.now()), type: "pong" }));
      } catch {
        this.safeCloseSocket(socket, 1011, "send_failed");
      }
      return;
    }
    this.safeCloseSocket(socket, 4400, "unsupported_message");
  }

  override webSocketClose(): void {
    // Cloudflare calls this handler after the closing handshake has completed.
    // Calling close() again can throw and unnecessarily restart the Durable Object.
  }

  override webSocketError(socket: WebSocket): void {
    socket.close(1011, "socket_error");
  }

  private async route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/authorize"
    ) {
      return this.authorizeBootstrap(request);
    }
    if (request.method === "GET" && path === "/v1/human/state") {
      return this.humanState(request);
    }
    if (request.method === "POST" && path === "/v1/human/lock") {
      return this.lockGateway(request);
    }
    if (request.method === "POST" && path === "/v1/human/unlock/options") {
      return this.gatewayUnlockOptions(request);
    }
    if (request.method === "POST" && path === "/v1/human/unlock/verify") {
      return this.gatewayUnlockVerify(request);
    }
    if (request.method === "GET" && path === "/v1/human/events") {
      return this.humanEvents(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/registration/options"
    ) {
      return this.bootstrapOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/bootstrap/registration/verify"
    ) {
      return this.bootstrapVerify(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/session/options"
    ) {
      return this.humanSessionOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/session/verify"
    ) {
      return this.humanSessionVerify(request);
    }
    if (request.method === "GET" && path === "/v1/human/management") {
      return this.humanManagement(request);
    }
    const sshGrantRevoke = path.match(
      /^\/v1\/human\/ssh-authorizations\/([^/]+)$/u,
    );
    if (request.method === "DELETE" && sshGrantRevoke) {
      return this.revokeSshAuthorization(
        request,
        decodeURIComponent(sshGrantRevoke[1]!),
      );
    }
    if (request.method === "GET" && path === "/v1/human/push/config") {
      return this.pushConfig(request);
    }
    if (request.method === "PUT" && path === "/v1/human/push/subscription") {
      return this.putPushSubscription(request);
    }
    if (request.method === "DELETE" && path === "/v1/human/push/subscription") {
      return this.deletePushSubscription(request);
    }
    if (request.method === "POST" && path === "/v1/human/devices/registration/options") {
      return this.deviceRegistrationOptions(request);
    }
    if (request.method === "POST" && path === "/v1/human/devices/registration/verify") {
      return this.deviceRegistrationVerify(request);
    }
    const deviceRevokeOptions = path.match(
      /^\/v1\/human\/devices\/([^/]+)\/revoke\/options$/u,
    );
    if (request.method === "POST" && deviceRevokeOptions) {
      return this.deviceRevokeOptions(
        request,
        decodeURIComponent(deviceRevokeOptions[1]!),
      );
    }
    const deviceRevokeVerify = path.match(
      /^\/v1\/human\/devices\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && deviceRevokeVerify) {
      return this.deviceRevokeVerify(
        request,
        decodeURIComponent(deviceRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/options"
    ) {
      return this.credentialRegistrationAuthorizationOptions(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/authorize"
    ) {
      return this.credentialRegistrationAuthorizationVerify(request);
    }
    if (
      request.method === "POST" &&
      path === "/v1/human/credentials/registration/verify"
    ) {
      return this.credentialRegistrationVerify(request);
    }
    const credentialRevokeOptions = path.match(
      /^\/v1\/human\/credentials\/([^/]+)\/revoke\/options$/u,
    );
    if (request.method === "POST" && credentialRevokeOptions) {
      return this.credentialRevokeOptions(
        request,
        decodeURIComponent(credentialRevokeOptions[1]!),
      );
    }
    const credentialRevokeVerify = path.match(
      /^\/v1\/human\/credentials\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && credentialRevokeVerify) {
      return this.credentialRevokeVerify(
        request,
        decodeURIComponent(credentialRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/requester-enrollments"
    ) {
      return this.createRequesterEnrollment(request);
    }
    const enrollmentStatus = path.match(
      /^\/v1\/requester-enrollments\/([^/]+)$/u,
    );
    if (request.method === "GET" && enrollmentStatus) {
      return this.requesterEnrollmentStatus(
        decodeURIComponent(enrollmentStatus[1]!),
      );
    }
    if (
      request.method === "GET" &&
      path === "/v1/human/requester-enrollments"
    ) {
      return this.humanRequesterEnrollments(request);
    }
    const humanEnrollmentOptions = path.match(
      /^\/v1\/human\/requester-enrollments\/([^/]+)\/options$/u,
    );
    if (request.method === "POST" && humanEnrollmentOptions) {
      return this.requesterEnrollmentDecisionOptions(
        request,
        decodeURIComponent(humanEnrollmentOptions[1]!),
      );
    }
    const humanEnrollmentVerify = path.match(
      /^\/v1\/human\/requester-enrollments\/([^/]+)\/verify$/u,
    );
    if (request.method === "POST" && humanEnrollmentVerify) {
      return this.requesterEnrollmentDecisionVerify(
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
      return this.requesterRenameOptions(
        request,
        decodeURIComponent(requesterRenameOptions[1]!),
      );
    }
    const requesterRenameVerify = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/rename\/verify$/u,
    );
    if (request.method === "POST" && requesterRenameVerify) {
      return this.requesterRenameVerify(
        request,
        decodeURIComponent(requesterRenameVerify[1]!),
      );
    }
    if (request.method === "POST" && requesterRevokeOptions) {
      return this.requesterRevokeOptions(
        request,
        decodeURIComponent(requesterRevokeOptions[1]!),
      );
    }
    const requesterRevokeVerify = path.match(
      /^\/v1\/human\/requesters\/([^/]+)\/revoke\/verify$/u,
    );
    if (request.method === "POST" && requesterRevokeVerify) {
      return this.requesterRevokeVerify(
        request,
        decodeURIComponent(requesterRevokeVerify[1]!),
      );
    }
    if (
      request.method === "POST" &&
      path === "/v1/catalog/search"
    ) {
      return this.catalogSearch(request, path);
    }
    if (request.method === "POST" && path === "/v1/requests") {
      return this.createApprovalRequest(request, path);
    }
    const requesterStatus = path.match(
      /^\/v1\/requests\/([^/]+)\/status$/u,
    );
    if (request.method === "GET" && requesterStatus) {
      return this.requesterRequestStatus(
        request,
        decodeURIComponent(requesterStatus[1]!),
      );
    }
    const requesterConsume = path.match(
      /^\/v1\/requests\/([^/]+)\/consume$/u,
    );
    if (request.method === "POST" && requesterConsume) {
      return this.consumeApprovalRequest(
        request,
        path,
        decodeURIComponent(requesterConsume[1]!),
      );
    }
    if (request.method === "GET" && path === "/v1/human/requests") {
      return this.humanRequests(request);
    }
    const humanRequest = path.match(/^\/v1\/human\/requests\/([^/]+)$/u);
    if (request.method === "GET" && humanRequest) {
      return this.humanRequestDetail(
        request,
        decodeURIComponent(humanRequest[1]!),
      );
    }
    const approvalOptions = path.match(
      /^\/v1\/human\/approvals\/([^/]+)\/options$/u,
    );
    if (request.method === "POST" && approvalOptions) {
      return this.approvalOptions(
        request,
        decodeURIComponent(approvalOptions[1]!),
      );
    }
    const approvalVerify = path.match(
      /^\/v1\/human\/approvals\/([^/]+)\/verify$/u,
    );
    if (request.method === "POST" && approvalVerify) {
      return this.approvalVerify(
        request,
        decodeURIComponent(approvalVerify[1]!),
      );
    }
    return errorResponse("not_found", 404);
  }

  private async authorizeBootstrap(request: Request): Promise<Response> {
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

  private async humanState(request: Request): Promise<Response> {
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

  private async lockGateway(request: Request): Promise<Response> {
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
        `UPDATE requester_enrollments SET status = 'rejected', terminal_at = ?
         WHERE status = 'pending' AND expires_at > ?`,
        now,
        now,
      );
      this.audit("gateway_locked", undefined, session.credential_id);
    });
    for (const row of affected) {
      this.recordTerminalActivity(row.id);
      this.broadcastHumanEvent("request.changed", row.id);
    }
    for (const row of affectedEnrollments) {
      this.broadcastHumanEvent("requester-enrollment.changed", row.id);
    }
    this.broadcastHumanEvent("lock.changed", "locked");
    this.broadcastHumanEvent("management.changed", "ssh-authorizations");
    return json({ locked: true, ok: true });
  }

  private async gatewayUnlockOptions(request: Request): Promise<Response> {
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

  private async gatewayUnlockVerify(request: Request): Promise<Response> {
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
      this.audit("gateway_unlocked", undefined, authorizedBy);
    });
    this.broadcastHumanEvent("lock.changed", "unlocked");
    return json({ locked: false, ok: true });
  }

  private gatewayRuntimeState(): GatewayRuntimeStateRow {
    const state = this.first<GatewayRuntimeStateRow>(
      `SELECT locked, lock_generation, changed_at, changed_by
       FROM gateway_runtime_state WHERE singleton = 1`,
    );
    if (!state) {
      throw new Error("gateway_runtime_state_missing");
    }
    return state;
  }

  private assertGatewayUnlocked(): void {
    if (this.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
  }

  private async bootstrapOptions(request: Request): Promise<Response> {
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

  private async bootstrapVerify(request: Request): Promise<Response> {
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
      this.audit("human_registered", undefined, info.credential.id);
    });
    return this.createHumanSessionResponse(info.credential.id, null);
  }

  private async humanSessionOptions(request: Request): Promise<Response> {
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

  private async humanSessionVerify(request: Request): Promise<Response> {
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

  private async humanEvents(request: Request): Promise<Response> {
    this.requireExpectedOrigin(request);
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      throw new GatewayHttpError("websocket_upgrade_required", 426);
    }
    const session = await this.requireHumanSession(request);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    const attachment: EventSocketAttachment = {
      credentialId: session.credential_id,
      deviceId: session.device_id!,
      expiresAt: session.expires_at,
      sessionHash: session.token_hash,
    };
    server.serializeAttachment(attachment);
    this.ctx.acceptWebSocket(server, [HUMAN_EVENT_SOCKET_TAG]);
    server.send(
      JSON.stringify({
        at: iso(Date.now()),
        event_id: crypto.randomUUID(),
        type: "ready",
      }),
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  private async humanManagement(request: Request): Promise<Response> {
    const session = await this.requireHumanSession(request);
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
    const lockGeneration = this.gatewayRuntimeState().lock_generation;
    const sshAuthorizations = this.rows<SshAuthorizationGrantRow>(
      `SELECT id, requester_device_id, agent_instance_public_key, scope_id,
              scope_kind, item_id, item_title, item_version, fingerprint, duration,
              lock_generation, created_at, expires_at, revoked_at,
              authorized_by_credential_id,
              COALESCE(
                (SELECT client_application FROM requests
                 WHERE ssh_grant_id = ssh_authorization_grants.id
                 ORDER BY created_at ASC LIMIT 1),
                'Unknown local client'
              ) AS client_application
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
      duration: grant.duration,
      expires_at: grant.expires_at ? iso(grant.expires_at) : undefined,
      fingerprint: grant.fingerprint,
      id: grant.id,
      item_id: grant.item_id,
      item_title: grant.item_title,
      item_version: grant.item_version,
      requester_device_id: grant.requester_device_id,
      scope_kind: grant.scope_kind,
    }));
    return json({
      credentials,
      devices,
      requesters,
      ssh_authorizations: sshAuthorizations,
      storage: {
        database_size_bytes: this.sql.databaseSize,
        pressure: storagePressure(this.sql.databaseSize),
      },
    });
  }

  private async revokeSshAuthorization(
    request: Request,
    grantIdValue: string,
  ): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    assertExactKeys(await readJsonObject(request), []);
    const grantId = safeIdentifier(grantIdValue, "grant_id");
    const now = Date.now();
    const updated = this.rows<{ id: string }>(
      `UPDATE ssh_authorization_grants SET revoked_at = ?
       WHERE id = ? AND revoked_at IS NULL RETURNING id`,
      now,
      grantId,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("ssh_authorization_not_found", 404);
    }
    this.audit("ssh_authorization_revoked", undefined, session.credential_id);
    this.broadcastHumanEvent("management.changed", grantId);
    return json({ ok: true, status: "revoked" });
  }

  private async pushConfig(request: Request): Promise<Response> {
    const session = await this.requireHumanSession(request);
    const enabled = Boolean(
      this.first<{ device_id: string }>(
        `SELECT device_id FROM push_subscriptions WHERE device_id = ?`,
        session.device_id,
      ),
    );
    return json({
      configured: Boolean(
        this.env.VAPID_PUBLIC_KEY && this.env.VAPID_PRIVATE_KEY && this.env.VAPID_SUBJECT,
      ),
      enabled,
      public_key: this.env.VAPID_PUBLIC_KEY ?? undefined,
    });
  }

  private async putPushSubscription(request: Request): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    let subscription: StoredPushSubscription;
    try {
      subscription = validatePushSubscription(await readJsonObject(request));
    } catch (error) {
      throw new GatewayHttpError(
        error instanceof Error ? error.message : "push_subscription_invalid",
        400,
      );
    }
    if (!this.env.VAPID_PUBLIC_KEY || !this.env.VAPID_PRIVATE_KEY || !this.env.VAPID_SUBJECT) {
      throw new GatewayHttpError("push_not_configured", 503);
    }
    const now = Date.now();
    this.sql.exec(
      `INSERT INTO push_subscriptions
        (device_id, endpoint, p256dh, auth, expiration_time, created_at,
         updated_at, last_success_at, failure_count)
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 0)
       ON CONFLICT(device_id) DO UPDATE SET
         endpoint = excluded.endpoint,
         p256dh = excluded.p256dh,
         auth = excluded.auth,
         expiration_time = excluded.expiration_time,
         updated_at = excluded.updated_at,
         failure_count = 0`,
      session.device_id,
      subscription.endpoint,
      subscription.p256dh,
      subscription.auth,
      subscription.expirationTime,
      now,
      now,
    );
    this.audit("push_subscription_enabled", undefined, session.device_id!);
    this.broadcastHumanEvent("management.changed", session.device_id!);
    return json({ enabled: true, ok: true });
  }

  private async deletePushSubscription(request: Request): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    await readJsonObject(request);
    this.sql.exec(`DELETE FROM push_subscriptions WHERE device_id = ?`, session.device_id);
    this.audit("push_subscription_disabled", undefined, session.device_id!);
    this.broadcastHumanEvent("management.changed", session.device_id!);
    return json({ enabled: false, ok: true });
  }

  private async deviceRegistrationOptions(request: Request): Promise<Response> {
    const session = await this.requireHumanBaseMutation(request);
    this.assertStorageGrowthAllowed();
    const input = safeHumanDeviceInput(await readJsonObject(request));
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
      kind: "device_registration",
      payload: JSON.stringify({ ...input, session_hash: session.token_hash }),
      targetId: input.device_id,
    });
    return json({ challenge_id: challengeId, device_challenge: options.challenge, options });
  }

  private async deviceRegistrationVerify(request: Request): Promise<Response> {
    const session = await this.requireHumanBaseMutation(request);
    const body = await readJsonObject<{
      challenge_id?: unknown;
      device_signature?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.getChallenge(
      challengeId,
      "device_registration",
      undefined,
      undefined,
    );
    const payload = safeHumanDeviceInput(parseJsonObject(challenge.payload));
    if (parseJsonObject(challenge.payload).session_hash !== session.token_hash) {
      throw new GatewayHttpError("device_registration_session_mismatch", 403);
    }
    const credentialId = await this.verifyHumanAuthentication(
      record(body.response),
      challenge.challenge,
    );
    await this.verifyDeviceProof(
      payload.public_key,
      deviceProofMessage(
        "device_registration",
        challengeId,
        challenge.challenge,
        payload.device_id,
      ),
      body.device_signature,
    );
    this.assertStorageGrowthAllowed();
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
      this.markChallengeUsed(challengeId);
      this.audit("human_device_registered", undefined, payload.device_id);
      this.audit("human_device_registration_authorized", undefined, credentialId);
    });
    this.broadcastHumanEvent("management.changed", payload.device_id);
    return json({ device_id: payload.device_id, device_trusted: true, ok: true });
  }

  private async deviceRevokeOptions(request: Request, deviceId: string): Promise<Response> {
    await this.requireHumanMutation(request);
    if (!this.activeHumanDevice(deviceId)) {
      throw new GatewayHttpError("device_not_found", 404);
    }
    if (this.activeHumanDeviceCount() <= 1) {
      throw new GatewayHttpError("last_device_cannot_be_revoked", 409);
    }
    return this.freshAuthenticationOptions("device_revoke", deviceId);
  }

  private async deviceRevokeVerify(request: Request, deviceId: string): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "device_revoke",
      deviceId,
      undefined,
    );
    const credentialId = await this.verifyHumanAuthentication(body.response, challenge.challenge);
    if (this.activeHumanDeviceCount() <= 1) {
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
      this.markChallengeUsed(body.challenge_id);
      this.audit("human_device_revoked", undefined, deviceId);
      this.audit("human_device_revoke_authorized", undefined, credentialId);
    });
    this.broadcastHumanEvent("management.changed", deviceId);
    this.closeDeviceSockets(deviceId);
    return json({ ok: true, status: "revoked" });
  }

  private async credentialRegistrationAuthorizationOptions(
    request: Request,
  ): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    this.assertStorageGrowthAllowed();
    const body = await readJsonObject<{ label?: unknown }>(request);
    const label = safeText(body.label, 80);
    return this.freshAuthenticationOptions(
      "credential_authorization",
      session.token_hash,
      { label, session_hash: session.token_hash },
    );
  }

  private async credentialRegistrationAuthorizationVerify(
    request: Request,
  ): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "credential_authorization",
      session.token_hash,
      undefined,
    );
    const payload = parseJsonObject(challenge.payload);
    if (payload.session_hash !== session.token_hash) {
      throw new GatewayHttpError("credential_session_mismatch", 403);
    }
    const authorizedBy = await this.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const label = safeText(payload.label, 80);
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
    const registrationChallengeId = this.storeChallenge({
      challenge: options.challenge,
      kind: "credential_registration",
      payload: JSON.stringify({
        authorized_by: authorizedBy,
        label,
        session_hash: session.token_hash,
      }),
      targetId: session.token_hash,
    });
    this.markChallengeUsed(body.challenge_id);
    return json({ challenge_id: registrationChallengeId, options });
  }

  private async credentialRegistrationVerify(request: Request): Promise<Response> {
    const session = await this.requireHumanMutation(request);
    const body = await readJsonObject<{
      challenge_id?: unknown;
      response?: unknown;
    }>(request);
    const challengeId = safeIdentifier(body.challenge_id, "challenge_id");
    const challenge = this.getChallenge(
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
    this.assertStorageGrowthAllowed();
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
      this.markChallengeUsed(challengeId);
      this.audit("human_credential_registered", undefined, info.credential.id);
    });
    this.broadcastHumanEvent("management.changed", info.credential.id);
    return json({ credential_id: info.credential.id, ok: true });
  }

  private async credentialRevokeOptions(
    request: Request,
    credentialId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    this.humanCredential(credentialId);
    if (this.listHumanCredentials().length <= 1) {
      throw new GatewayHttpError("last_credential_cannot_be_revoked", 409);
    }
    return this.freshAuthenticationOptions("credential_revoke", credentialId);
  }

  private async credentialRevokeVerify(
    request: Request,
    credentialId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "credential_revoke",
      credentialId,
      undefined,
    );
    const authorizedBy = await this.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    if (this.listHumanCredentials().length <= 1) {
      throw new GatewayHttpError("last_credential_cannot_be_revoked", 409);
    }
    const now = Date.now();
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
      this.markChallengeUsed(body.challenge_id);
      this.audit("human_credential_revoked", undefined, credentialId);
      this.audit("human_credential_revoke_authorized", undefined, authorizedBy);
    });
    this.broadcastHumanEvent("management.changed", credentialId);
    this.closeCredentialSockets(credentialId);
    return json({ ok: true, status: "revoked" });
  }

  private async createRequesterEnrollment(
    request: Request,
  ): Promise<Response> {
    if (!this.hasHumanCredential()) {
      throw new GatewayHttpError("not_initialized", 409);
    }
    const body = await readJsonObject<RequesterEnrollmentRequest>(request);
    const deviceId = safeDeviceId(body.device_id);
    const displayName = safeText(body.display_name, 80);
    const publicKey = safeBase64Url(body.public_key, 32, "public_key");
    const publicKeyFingerprint =
      await requesterPublicKeyFingerprint(publicKey);
    this.assertGatewayUnlocked();
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
    this.assertStorageGrowthAllowed();
    this.assertRequesterEnrollmentRate();
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
    this.audit("requester_enrollment_created", undefined, deviceId);
    this.broadcastHumanEvent("requester-enrollment.changed", id);
    this.queueApprovalPush({
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

  private requesterEnrollmentStatus(id: string): Response {
    const enrollment = this.enrollment(id);
    return json(projectEnrollment(enrollment));
  }

  private async humanRequesterEnrollments(
    request: Request,
  ): Promise<Response> {
    await this.requireHumanSession(request);
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

  private async requesterEnrollmentDecisionOptions(
    request: Request,
    enrollmentId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readDecisionBody(request);
    const enrollment = this.enrollment(enrollmentId);
    if (enrollment.status !== "pending" || enrollment.expires_at <= Date.now()) {
      throw new GatewayHttpError("enrollment_not_pending", 409);
    }
    return this.decisionOptions(
      "requester_enrollment",
      enrollmentId,
      body.decision,
    );
  }

  private async requesterEnrollmentDecisionVerify(
    request: Request,
    enrollmentId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readDecisionVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "requester_enrollment",
      enrollmentId,
      body.decision,
    );
    const credentialId = await this.verifyHumanAuthentication(
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
      this.markChallengeUsed(body.challenge_id);
      this.audit(
        status === "approved"
          ? "requester_enrollment_approved"
          : "requester_enrollment_rejected",
        undefined,
        credentialId,
      );
    });
    this.broadcastHumanEvent("requester-enrollment.changed", enrollmentId);
    return json({ ok: true, status });
  }

  private async requesterRenameOptions(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
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
    return this.freshAuthenticationOptions(
      "requester_rename",
      deviceId,
      { display_name: displayName },
    );
  }

  private async requesterRenameVerify(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "requester_rename",
      deviceId,
      undefined,
    );
    const displayName = safeText(
      parseJsonObject(challenge.payload).display_name,
      80,
    );
    const authorizedBy = await this.verifyHumanAuthentication(
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
      this.markChallengeUsed(body.challenge_id);
      this.audit("requester_renamed", undefined, deviceId);
      this.audit("requester_rename_authorized", undefined, authorizedBy);
    });
    this.broadcastHumanEvent("management.changed", deviceId);
    return json({ display_name: displayName, ok: true });
  }

  private async requesterRevokeOptions(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const requester = this.first<{ device_id: string }>(
      `SELECT device_id FROM requesters
       WHERE device_id = ? AND revoked_at IS NULL`,
      deviceId,
    );
    if (!requester) {
      throw new GatewayHttpError("requester_not_found", 404);
    }
    return this.freshAuthenticationOptions("requester_revoke", deviceId);
  }

  private async requesterRevokeVerify(
    request: Request,
    requesterDeviceId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const deviceId = safeDeviceId(requesterDeviceId);
    const body = await readChallengeVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "requester_revoke",
      deviceId,
      undefined,
    );
    const authorizedBy = await this.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
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
      this.markChallengeUsed(body.challenge_id);
      this.audit("requester_revoked", undefined, deviceId);
      this.audit("requester_revoke_authorized", undefined, authorizedBy);
    });
    this.broadcastHumanEvent("management.changed", deviceId);
    return json({ ok: true, status: "revoked" });
  }

  private async catalogSearch(
    request: Request,
    path: string,
  ): Promise<Response> {
    const body = await readJsonObject<CatalogSearchRequest>(request);
    await this.authenticateSignedRequest(request, path, body);
    if (this.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
    const query =
      body.query === ""
        ? ""
        : safeText(body.query, 128);
    const items = await this.executeCatalog(query);
    this.assertGatewayUnlocked();
    return json({ items });
  }

  private async createApprovalRequest(
    request: Request,
    path: string,
  ): Promise<Response> {
    const body = await readJsonObject<
      SecretReadCreateRequest | ItemMutationRequest | SshSignCreateRequest
    >(request);
    let rateReservation: RequestCreationReservation | undefined;
    try {
      const requester = await this.authenticateSignedRequest(
        request,
        path,
        body,
        (identity) => {
          // Storage pressure is independent of requester identity, but running
          // this hook after signature verification avoids exposing diagnostics
          // to unauthenticated callers while still rejecting before nonce growth.
          this.assertStorageGrowthAllowed();
          rateReservation = this.reserveRequestCreationRate(identity.deviceId, body);
        },
      );
      if (this.gatewayRuntimeState().locked === 1) {
        this.audit("locked_request_rejected", undefined, requester.deviceId);
        throw new GatewayHttpError("gateway_locked", 423);
      }
      if (
        body.action === "item.create" ||
        body.action === "item.patch" ||
        body.action === "item.archive"
      ) {
        return await this.createItemMutationRequest(body, requester);
      }
      if (body.action === "ssh.sign") {
        return await this.createSshSignRequest(body, requester);
      }
      if (body.action !== "secret.read") {
        throw new GatewayHttpError("unsupported_action", 400);
      }
    assertExactKeys(body, [
      "action",
      "client",
      "expected_version",
      "field_id",
      "idempotency_key",
      "item_id",
    ]);
    const context = safeClientObservation(body.client);
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
        poll_token: await this.requestPollingToken(
          existing.id,
          requester.deviceId,
        ),
        request_id: existing.id,
        status: publicRequestState(existing.status),
      });
    }
      const releaseApproval = this.reserveNewApproval(requester.deviceId, false);
      try {
        const metadata =
          this.cachedSecretMetadata(itemId, fieldId, expectedVersion) ??
          (await this.executeSecretMetadata(itemId, fieldId));
        if (metadata.version !== expectedVersion) {
          throw new GatewayHttpError("item_stale", 409);
        }
        const now = Date.now();
        const expiresAt = now + APPROVAL_TTL_MS;
        const requestId = crypto.randomUUID();
        const requestValues: SqlStorageValue[] = [
      requestId,
      requester.deviceId,
      requester.displayName,
      "secret.read",
      itemId,
      fieldId,
      expectedVersion,
      context.application,
      context.source,
      null,
      null,
      null,
      null,
      metadata.item_title,
      metadata.field_label,
      metadata.field_type,
      idempotencyKey,
      bodyHash,
      "pending",
      now,
      expiresAt,
      null,
      null,
      null,
      null,
      null,
        ];
        try {
          if (requestValues.length !== REQUEST_INSERT_COLUMNS.length) {
            throw new Error("request_insert_binding_count_mismatch");
          }
          this.assertStorageGrowthAllowed();
          this.assertGatewayUnlocked();
          this.sql.exec(REQUEST_INSERT_SQL, ...requestValues);
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
          this.audit("request_created", requestId, requester.deviceId);
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
        this.broadcastHumanEvent("request.changed", requestId);
        this.queueApprovalPush({
          body: "Open the approval queue to approve or deny this request.",
          requestId,
          tag: `request-${requestId}`,
          title: "New 1Password approval request",
          url: `/requests#request-${requestId}`,
        });
        return json(
          {
            expires_at: iso(expiresAt),
            poll_token: await this.requestPollingToken(requestId, requester.deviceId),
            request_id: requestId,
            status: "pending",
          },
          201,
        );
      } finally {
        releaseApproval();
      }
    } finally {
      if (rateReservation) this.releaseRequestCreationRate(rateReservation);
    }
  }

  private async createItemMutationRequest(
    rawBody: ItemMutationRequest,
    requester: RequesterIdentity,
  ): Promise<Response> {
    let body: ItemMutationRequest;
    try {
      body = parseItemMutationRequest(rawBody);
    } catch {
      throw new GatewayHttpError("item_operation_invalid", 400);
    }
    const context = safeClientObservation(body.client);
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
        poll_token: await this.requestPollingToken(
          existing.id,
          requester.deviceId,
        ),
        request_id: existing.id,
        status: publicRequestState(existing.status),
      });
    }

    const releaseApproval = this.reserveNewApproval(requester.deviceId, true);
    try {
      const requestId = crypto.randomUUID();
      const now = Date.now();
      const expiresAt = now + APPROVAL_TTL_MS;
      let metadata: CatalogExecutorItem | undefined;
      if (body.action !== "item.create") {
        metadata = await this.executeItemMetadata(body.item_id);
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
      const requestValues: SqlStorageValue[] = [
      requestId,
      requester.deviceId,
      requester.displayName,
      body.action,
      description.itemId,
      "",
      description.expectedVersion,
      context.application,
      context.source,
      null,
      null,
      null,
      null,
      description.itemTitle,
      description.fieldLabel,
      description.fieldType,
      body.idempotency_key,
      bodyHash,
      "pending",
      now,
      expiresAt,
      null,
      null,
      null,
      null,
      null,
      ];
      if (requestValues.length !== REQUEST_INSERT_COLUMNS.length) {
        throw new Error("request_insert_binding_count_mismatch");
      }
      this.ctx.storage.transactionSync(() => {
        this.assertStorageGrowthAllowed();
        this.assertGatewayUnlocked();
        this.sql.exec(REQUEST_INSERT_SQL, ...requestValues);
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
        this.audit("request_created", requestId, requester.deviceId);
      });
      this.broadcastHumanEvent("request.changed", requestId);
      this.queueApprovalPush({
        body: "Open the approval queue to approve or deny this request.",
        requestId,
        tag: `request-${requestId}`,
        title: "New 1Password approval request",
        url: `/requests#request-${requestId}`,
      });
      return json(
        {
          expires_at: iso(expiresAt),
          poll_token: await this.requestPollingToken(requestId, requester.deviceId),
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
  ): Promise<Response> {
    let body: SshSignCreateRequest;
    try {
      body = parseSshSignRequest(rawBody);
    } catch {
      throw new GatewayHttpError("ssh_sign_request_invalid", 400);
    }
    const authorizationSession = await this.verifySshAuthorizationSession(body);
    const context = safeClientObservation(body.client);
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
        poll_token: await this.requestPollingToken(
          existing.id,
          requester.deviceId,
        ),
        request_id: existing.id,
        status: publicRequestState(existing.status),
      });
    }
    const releaseApproval = this.reserveNewApproval(requester.deviceId, false);
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
        this.assertRememberedSshSignRate(requester.deviceId, grant.id);
      }
      const metadata = grant
        ? undefined
        : await this.executeItemMetadata(body.item_id);
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
      const requestValues: SqlStorageValue[] = [
      requestId,
      requester.deviceId,
      requester.displayName,
      "ssh.sign",
      description.itemId,
      "",
      description.expectedVersion,
      context.application,
      context.source,
      authorizationSession?.agent_instance_public_key ?? null,
      authorizationSession?.scope_id ?? null,
      authorizationSession?.scope_kind ?? null,
      grant?.id ?? null,
      description.itemTitle,
      description.fingerprint,
      description.signatureAlgorithm,
      body.idempotency_key,
      bodyHash,
      initialStatus,
      now,
      expiresAt,
      grant ? now : null,
      authorizedUntil,
      null,
      null,
      null,
      ];
      if (requestValues.length !== REQUEST_INSERT_COLUMNS.length) {
        throw new Error("request_insert_binding_count_mismatch");
      }
      this.ctx.storage.transactionSync(() => {
        this.assertStorageGrowthAllowed();
        this.assertGatewayUnlocked();
        this.sql.exec(REQUEST_INSERT_SQL, ...requestValues);
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
        this.audit(
          grant ? "request_auto_approved" : "request_created",
          requestId,
          grant?.id ?? requester.deviceId,
        );
      });
      this.broadcastHumanEvent("request.changed", requestId);
      if (!grant) {
        this.queueApprovalPush({
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
          poll_token: await this.requestPollingToken(requestId, requester.deviceId),
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
    const runtime = this.gatewayRuntimeState();
    if (runtime.locked === 1) return undefined;
    return this.first<SshAuthorizationGrantRow>(
      `SELECT id, requester_device_id, agent_instance_public_key, scope_id,
              scope_kind, item_id, item_title, item_version, fingerprint, duration,
              lock_generation, created_at, expires_at, revoked_at,
              authorized_by_credential_id
       FROM ssh_authorization_grants
       WHERE requester_device_id = ?
         AND agent_instance_public_key = ?
         AND scope_id = ?
         AND scope_kind = ?
         AND item_id = ?
         AND item_version = ?
         AND fingerprint = ?
         AND revoked_at IS NULL
         AND (expires_at IS NULL OR expires_at > ?)
         AND (duration != 'until-lock' OR lock_generation = ?)
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

  private async requesterRequestStatus(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    const row = this.findRequestRow(requestId);
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
    const expected = await this.requestPollingToken(
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
          : this.requestOperation(projected.id),
      ),
    );
  }

  private async consumeApprovalRequest(
    request: Request,
    path: string,
    requestId: string,
  ): Promise<Response> {
    const body = await readJsonObject(request);
    const requester = await this.authenticateSignedRequest(
      request,
      path,
      body,
    );
    if (this.gatewayRuntimeState().locked === 1) {
      throw new GatewayHttpError("gateway_locked", 423);
    }
    const row = this.requestRow(requestId);
    if (row.requester_device_id !== requester.deviceId) {
      throw new GatewayHttpError("request_not_found", 404);
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
       RETURNING id`,
      now,
      requestId,
      requester.deviceId,
      now,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("authorization_not_consumable", 409);
    }
    this.audit("request_execution_started", requestId, requester.deviceId);
    this.broadcastHumanEvent("request.changed", requestId);

    let result: SecretReadExecutorResult;
    try {
      result = await this.executeSecretRead(row);
    } catch (error) {
      const code =
        error instanceof GatewayHttpError ? error.code : "executor_unavailable";
      this.sql.exec(
        `UPDATE requests SET status = 'error', error_code = ?
         WHERE id = ? AND status = 'executing'`,
        code,
        requestId,
      );
      this.recordTerminalActivity(requestId);
      this.audit("request_execution_failed", requestId, code);
      this.broadcastHumanEvent("request.changed", requestId);
      throw error;
    }

    const consumedAt = Date.now();
    this.sql.exec(
      `UPDATE requests
       SET status = 'consumed', consumed_at = ?, error_code = NULL
       WHERE id = ? AND status = 'executing'`,
      consumedAt,
      requestId,
    );
    this.recordTerminalActivity(requestId);
    this.audit("request_consumed", requestId, requester.deviceId);
    this.broadcastHumanEvent("request.changed", requestId);
    return json({
      ok: true,
      request_id: requestId,
      status: "consumed",
      value: result.value,
    });
  }

  private async consumeItemMutation(
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
    this.audit("request_execution_started", row.id, requester.deviceId);
    this.broadcastHumanEvent("request.changed", row.id);

    const operation = this.requestOperation(row.id);
    let executorBody: Record<string, unknown>;
    try {
      executorBody = await this.readMutationExecutorBody(row, operation);
    } catch {
      this.failMutation(row.id, "pending_payload_unavailable");
      throw new GatewayHttpError("pending_payload_unavailable", 500);
    }

    try {
      const result = await this.executeItemMutation(row, executorBody);
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
      this.audit("request_execution_unknown", row.id, code);
      this.broadcastHumanEvent("request.changed", row.id);
    }

    if (!RECONCILIATION_IMMEDIATE_ENABLED) {
      this.ctx.waitUntil(this.scheduleNextAlarm());
      return json(
        { ok: true, request_id: row.id, status: "unknown" },
        202,
      );
    }

    let reconciliation: ItemReconciliationExecutorResult;
    try {
      this.recordReconciliationAttempt(row.id);
      reconciliation = await this.reconcileItemMutation(row, executorBody);
    } catch (error) {
      this.audit(
        "request_reconcile_deferred",
        row.id,
        error instanceof GatewayHttpError ? error.code : "executor_unavailable",
      );
      this.ctx.waitUntil(this.scheduleNextAlarm());
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
    this.audit("request_reconcile_ambiguous", row.id, requester.deviceId);
    this.broadcastHumanEvent("request.changed", row.id);
    this.ctx.waitUntil(this.scheduleNextAlarm());
    return json({ ok: true, request_id: row.id, status: "unknown" }, 202);
  }

  private async consumeSshSign(
    row: RequestRow,
    requester: RequesterIdentity,
  ): Promise<Response> {
    const now = Date.now();
    const updated = this.rows<{ id: string }>(
      `UPDATE requests SET status = 'executing', execution_started_at = ?
       WHERE id = ? AND requester_device_id = ? AND status = 'approved'
         AND authorized_until > ? AND action = 'ssh.sign'
       RETURNING id`,
      now,
      row.id,
      requester.deviceId,
      now,
    );
    if (updated.length !== 1) {
      throw new GatewayHttpError("authorization_not_consumable", 409);
    }
    this.audit("request_execution_started", row.id, requester.deviceId);
    this.broadcastHumanEvent("request.changed", row.id);

    let executorBody: Record<string, unknown>;
    try {
      executorBody = await this.readSshSignExecutorBody(
        row,
        this.requestOperation(row.id),
      );
    } catch {
      this.failMutation(row.id, "pending_payload_unavailable");
      throw new GatewayHttpError("pending_payload_unavailable", 500);
    }

    let result: SshSignExecutorResult;
    try {
      result = await this.executeSshSign(row, executorBody);
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
      this.clearPendingPayload(row.id);
      this.audit("request_consumed", row.id, requester.deviceId);
    });
    this.recordTerminalActivity(row.id);
    this.broadcastHumanEvent("request.changed", row.id);
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

  private async tryReconcileUnknownMutation(
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
    const operation = this.requestOperation(row.id);
    if (
      operation.reconcile_attempt_count >=
      MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS
    ) {
      this.audit("request_reconcile_limit_reached", row.id, actorId);
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
      this.audit("request_reconcile_deferred", row.id, "pending_payload_unavailable");
      return;
    }
    let reconciliation: ItemReconciliationExecutorResult;
    try {
      reconciliation = await this.reconcileItemMutation(row, executorBody);
    } catch (error) {
      this.audit(
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
    this.audit("request_reconcile_ambiguous", row.id, actorId);
    this.broadcastHumanEvent("request.changed", row.id);
  }

  private recordReconciliationAttempt(requestId: string): void {
    this.sql.exec(
      `UPDATE request_operations
       SET reconcile_attempt_count = reconcile_attempt_count + 1,
           reconcile_attempted_at = ?
       WHERE request_id = ?`,
      Date.now(),
      requestId,
    );
  }

  private async scheduleNextAlarm(): Promise<void> {
    const now = Date.now();
    const deadlines: number[] = [];
    const maintenance = this.first<{ next_retention_at: number }>(
      `SELECT next_retention_at FROM gateway_maintenance_state WHERE singleton = 1`,
    );
    deadlines.push(maintenance?.next_retention_at ?? now + RETENTION_SWEEP_INTERVAL_MS);

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
      RECONCILIATION_RETRY_DELAY_MS,
      MAX_AUTOMATIC_RECONCILIATION_ATTEMPTS,
    )?.deadline;
    if (reconciliationDeadline !== null && reconciliationDeadline !== undefined) {
      deadlines.push(reconciliationDeadline);
    }

    const target = Math.max(now + 1_000, Math.min(...deadlines));
    const current = await this.ctx.storage.getAlarm();
    if (current === null || Math.abs(current - target) > 1_000) {
      await this.ctx.storage.setAlarm(target);
    }
  }

  private async readMutationExecutorBody(
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

  private async readSshSignExecutorBody(
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

  private completeMutation(
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
      this.audit("request_consumed", row.id, actorId);
    });
    this.invalidateCatalogMetadata(row.item_id, result.item_id);
    this.recordTerminalActivity(row.id);
    this.broadcastHumanEvent("request.changed", row.id);
    return json({
      item_id: result.item_id,
      ok: true,
      request_id: row.id,
      status: "consumed",
      ...(result.version === undefined ? {} : { version: result.version }),
    });
  }

  private failMutation(requestId: string, code: string): void {
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
      this.audit("request_execution_failed", requestId, code);
    });
    this.recordTerminalActivity(requestId);
    this.broadcastHumanEvent("request.changed", requestId);
  }

  private clearPendingPayload(requestId: string): void {
    this.sql.exec(
      `UPDATE request_operations
       SET payload_aad = NULL, payload_ciphertext = NULL, payload_digest = NULL,
           payload_iv = NULL
       WHERE request_id = ?`,
      requestId,
    );
  }

  private async humanRequests(request: Request): Promise<Response> {
    await this.requireHumanSession(request);
    const searchParams = new URL(request.url).searchParams;
    if (searchParams.get("pending") === "true") {
      const pending = this.rows<RequestRow>(
        `SELECT id, requester_device_id, requester_name, action,
                client_application, client_source,
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
              client_application, client_source,
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
              client_source, error_code
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

  private async humanRequestDetail(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.requireHumanSession(request);
    const operational = this.findRequestRow(requestId);
    if (operational) return json(projectHumanRequestDetail(operational));
    const activity = this.requestActivityRow(requestId);
    if (!activity) throw new GatewayHttpError("request_not_found", 404);
    return json(projectHumanActivityDetail(activity));
  }

  private async approvalOptions(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readDecisionBody(request);
    const row = this.requestRow(requestId);
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

  private async approvalVerify(
    request: Request,
    requestId: string,
  ): Promise<Response> {
    await this.requireHumanMutation(request);
    const body = await readDecisionVerifyBody(request);
    const challenge = this.getChallenge(
      body.challenge_id,
      "approval",
      requestId,
      body.decision,
    );
    const challengePayload = challenge.payload
      ? parseJsonObject(challenge.payload)
      : {};
    const authorizationDuration = this.approvalAuthorizationDuration(
      this.requestRow(requestId),
      body.decision,
      challengePayload.authorization_duration,
    );
    if (body.authorization_duration !== authorizationDuration) {
      throw new GatewayHttpError("authorization_duration_mismatch", 400);
    }
    const credentialId = await this.verifyHumanAuthentication(
      body.response,
      challenge.challenge,
    );
    const now = Date.now();
    const status = body.decision === "approve" ? "approved" : "rejected";
    const authorizedUntil =
      status === "approved" ? now + AUTHORIZATION_TTL_MS : null;
    const row = this.requestRow(requestId);
    const grantId =
      status === "approved" && authorizationDuration
        ? crypto.randomUUID()
        : undefined;
    this.ctx.storage.transactionSync(() => {
      const updated = this.rows<{ id: string }>(
        `UPDATE requests
         SET status = ?, decided_at = ?, authorized_until = ?,
             ssh_grant_id = COALESCE(?, ssh_grant_id)
         WHERE id = ? AND status = 'pending' AND expires_at > ?
         RETURNING id`,
        status,
        now,
        authorizedUntil,
        grantId ?? null,
        requestId,
        now,
      );
      if (updated.length !== 1) {
        throw new GatewayHttpError("request_not_pending", 409);
      }
      if (status === "rejected") this.clearPendingPayload(requestId);
      if (grantId && authorizationDuration) {
        const runtime = this.gatewayRuntimeState();
        const durationMs = SSH_GRANT_DURATION_MS[authorizationDuration];
        this.sql.exec(
          `INSERT INTO ssh_authorization_grants
            (id, requester_device_id, agent_instance_public_key, scope_id,
             scope_kind, item_id, item_title, item_version, fingerprint, duration,
             lock_generation, created_at, expires_at, revoked_at,
             authorized_by_credential_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
          grantId,
          row.requester_device_id,
          row.ssh_agent_instance_public_key!,
          row.ssh_scope_id!,
          row.ssh_scope_kind!,
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
        this.audit("ssh_authorization_created", requestId, grantId);
      }
      this.markChallengeUsed(body.challenge_id);
      this.audit(
        status === "approved" ? "request_approved" : "request_rejected",
        requestId,
        credentialId,
      );
    });
    if (status === "rejected") this.recordTerminalActivity(requestId);
    this.broadcastHumanEvent("request.changed", requestId);
    if (grantId) {
      this.broadcastHumanEvent("management.changed", grantId);
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
    if (
      decision !== "approve" ||
      row.action !== "ssh.sign" ||
      !row.ssh_agent_instance_public_key ||
      !row.ssh_scope_id ||
      (row.ssh_scope_kind !== "application" &&
        row.ssh_scope_kind !== "terminal-session")
    ) {
      throw new GatewayHttpError("ssh_authorization_unavailable", 409);
    }
    return value;
  }

  private async decisionOptions(
    kind: "requester_enrollment" | "approval",
    targetId: string,
    decision: ApprovalDecision,
    authorizationDuration?: SshAuthorizationDuration,
  ): Promise<Response> {
    const credentials = this.listHumanCredentials();
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
    const challengeId = this.storeChallenge({
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

  private async freshAuthenticationOptions(
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

  private async verifyHumanAuthentication(
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
    this.sql.exec(
      `UPDATE human_credentials
       SET counter = ?, device_type = ?, backed_up = ?, last_used_at = ?
       WHERE id = ? AND revoked_at IS NULL`,
      verification.authenticationInfo.newCounter,
      verification.authenticationInfo.credentialDeviceType,
      verification.authenticationInfo.credentialBackedUp ? 1 : 0,
      Date.now(),
      credentialId,
    );
    return credentialId;
  }

  private async authenticateSignedRequest(
    request: Request,
    path: string,
    body: unknown,
    beforeUseNonce?: (identity: RequesterIdentity) => void,
  ): Promise<RequesterIdentity> {
    return authenticateRequester({
      audience: new URL(this.env.ORIGIN).host,
      beforeUseNonce: (identity) => {
        this.assertRequesterAuthenticatedRate(identity.deviceId);
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
          this.sql.exec(
            `INSERT INTO requester_nonces (device_id, nonce, expires_at)
             VALUES (?, ?, ?)`,
            deviceId,
            nonce,
            expiresAt,
          );
          return true;
        } catch {
          return false;
        }
      },
    });
  }

  private async executeCatalog(query: string): Promise<CatalogExecutorItem[]> {
    const trusted = await this.callExecutor("/internal/1password/catalog", {
      query,
    });
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const items = sanitizeExecutorEnvelope(() =>
      sanitizeCatalogEnvelope(trusted.body, trusted.status),
    );
    this.cacheCatalogMetadata(items);
    return items;
  }

  private async executeSecretMetadata(
    itemId: string,
    fieldId: string,
  ): Promise<SecretMetadataExecutorResult> {
    const trusted = await this.callExecutor(
      "/internal/1password/secret/metadata",
      { field_id: fieldId, item_id: itemId },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const metadata = sanitizeExecutorEnvelope(() =>
      sanitizeSecretMetadataEnvelope(trusted.body, trusted.status, {
        field_id: fieldId,
        item_id: itemId,
      }),
    );
    this.cacheSecretMetadata(metadata);
    return metadata;
  }

  private cachedSecretMetadata(
    itemId: string,
    fieldId: string,
    expectedVersion: number,
  ): SecretMetadataExecutorResult | undefined {
    const key = catalogMetadataCacheKey(itemId, fieldId, expectedVersion);
    const row = this.catalogMetadataCache.get(key);
    if (!row || row.cached_at < Date.now() - CATALOG_METADATA_CACHE_TTL_MS) {
      if (row) this.catalogMetadataCache.delete(key);
      return undefined;
    }
    return {
      field_id: row.field_id,
      field_label: row.field_label,
      field_type: row.field_type,
      item_id: row.item_id,
      item_title: row.item_title,
      version: row.version,
    };
  }

  private cacheCatalogMetadata(items: CatalogExecutorItem[]): void {
    const cachedAt = Date.now();
    for (const item of items) {
      for (const field of item.fields) {
        this.cacheSecretMetadata(
          {
            field_id: field.field_id,
            field_label: field.label,
            field_type: field.field_type,
            item_id: item.item_id,
            item_title: item.title,
            version: item.version,
          },
          cachedAt,
        );
      }
    }
  }

  private cacheSecretMetadata(
    metadata: SecretMetadataExecutorResult,
    cachedAt = Date.now(),
  ): void {
    const key = catalogMetadataCacheKey(
      metadata.item_id,
      metadata.field_id,
      metadata.version,
    );
    this.catalogMetadataCache.delete(key);
    this.catalogMetadataCache.set(key, { ...metadata, cached_at: cachedAt });
    while (this.catalogMetadataCache.size > CATALOG_METADATA_CACHE_MAX_ENTRIES) {
      const oldest = this.catalogMetadataCache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.catalogMetadataCache.delete(oldest);
    }
  }

  private invalidateCatalogMetadata(...itemIds: string[]): void {
    const targets = new Set(itemIds);
    for (const [key, metadata] of this.catalogMetadataCache) {
      if (targets.has(metadata.item_id)) this.catalogMetadataCache.delete(key);
    }
  }

  private async executeSecretRead(
    row: RequestRow,
  ): Promise<SecretReadExecutorResult> {
    const trusted = await this.callExecutor(
      "/internal/1password/secret/read",
      {
        expected_version: row.expected_version,
        field_id: row.field_id,
        item_id: row.item_id,
      },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeSecretReadEnvelope(trusted.body, trusted.status, {
        field_id: row.field_id,
        field_label: row.field_label,
        field_type: row.field_type,
        item_id: row.item_id,
        item_title: row.item_title,
        version: row.expected_version,
      }),
    );
  }

  private async executeItemMetadata(itemId: string): Promise<CatalogExecutorItem> {
    const trusted = await this.callExecutor(
      "/internal/1password/item/metadata",
      { item_id: itemId },
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemMetadataEnvelope(trusted.body, trusted.status, itemId),
    );
  }

  private async executeItemMutation(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ItemMutationExecutorResult> {
    const execution = await this.executorExecutionIdentity(row, body);
    const trusted = await this.callExecutor(
      "/internal/1password/item/mutate",
      body,
      execution,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemMutationEnvelope(
        trusted.body,
        trusted.status,
        row.action === "item.create" ? undefined : row.item_id,
      ),
    );
  }

  private async reconcileItemMutation(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ItemReconciliationExecutorResult> {
    const execution = await this.executorExecutionIdentity(row, body);
    const trusted = await this.callExecutor(
      "/internal/1password/item/reconcile",
      body,
      execution,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    return sanitizeExecutorEnvelope(() =>
      sanitizeItemReconciliationEnvelope(
        trusted.body,
        trusted.status,
        row.action === "item.create" ? undefined : row.item_id,
      ),
    );
  }

  private async executeSshSign(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<SshSignExecutorResult> {
    const algorithm = safeSshSignatureAlgorithm(row.field_type);
    const trusted = await this.callExecutor(
      "/internal/1password/ssh/sign",
      body,
    );
    if (trusted.status !== 200) {
      const failure = sanitizeExecutorEnvelope(() =>
        sanitizeGatewayError(trusted.body, trusted.status),
      );
      throw new GatewayHttpError(failure.code, failure.status);
    }
    const result = sanitizeExecutorEnvelope(() =>
      sanitizeSshSignEnvelope(trusted.body, trusted.status, {
        algorithm,
        fingerprint: row.field_label,
        item_id: row.item_id,
        version: row.expected_version,
      }),
    );
    const digest = await sha256Base64Url(decodeBase64Url(result.public_key_blob));
    const fingerprint = `SHA256:${digest.replace(/-/gu, "+").replace(/_/gu, "/")}`;
    if (fingerprint !== result.fingerprint) {
      throw new GatewayHttpError("executor_response_invalid", 502);
    }
    return result;
  }

  private async callExecutor(
    path: string,
    body: Record<string, unknown>,
    execution?: ExecutorExecutionIdentity,
  ): Promise<{ body: Record<string, unknown>; status: number }> {
    if (!this.env.EXECUTOR_AUTH_TOKEN) {
      throw new GatewayHttpError("executor_not_configured", 503);
    }
    if (!this.env.EXECUTOR_SERVICE) {
      throw new GatewayHttpError("executor_not_configured", 503);
    }
    if (this.executorInFlight >= MAX_EXECUTOR_CONCURRENCY) {
      throw new GatewayHttpError("executor_busy", 429);
    }
    this.executorInFlight += 1;
    try {
      return await callExecutorService({
        authToken: this.env.EXECUTOR_AUTH_TOKEN,
        body,
        ...(execution === undefined ? {} : { execution }),
        path,
        service: this.env.EXECUTOR_SERVICE,
        timeoutMs: EXECUTOR_FETCH_TIMEOUT_MS,
      });
    } catch (error) {
      throw new GatewayHttpError(
        error instanceof ExecutorTransportError && error.failure === "timeout"
          ? "executor_timeout"
          : "executor_unavailable",
        error instanceof ExecutorTransportError && error.failure === "timeout"
          ? 504
          : 502,
      );
    } finally {
      this.executorInFlight -= 1;
    }
  }

  private async executorExecutionIdentity(
    row: RequestRow,
    body: Record<string, unknown>,
  ): Promise<ExecutorExecutionIdentity> {
    if (
      row.action !== "item.create" &&
      row.action !== "item.patch" &&
      row.action !== "item.archive"
    ) {
      throw new GatewayHttpError("item_operation_invalid", 400);
    }
    return {
      bodyDigest: await canonicalJsonSha256Base64Url(body),
      requestId: row.id,
    };
  }

  private async requestPollingToken(
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

  private async requireHumanSession(
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

  private async requireHumanBaseSession(request: Request): Promise<SessionRow> {
    const session = await this.readSession(request);
    if (!session) throw new GatewayHttpError("session_expired", 401);
    return session;
  }

  private async requireHumanMutation(
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

  private async requireHumanBaseMutation(request: Request): Promise<SessionRow> {
    this.requireExpectedOrigin(request);
    const session = await this.requireHumanBaseSession(request);
    const csrf = request.headers.get("x-csrf-token");
    if (!csrf || !constantTimeStringEquals(csrf, session.csrf_token)) {
      throw new GatewayHttpError("csrf_invalid", 403);
    }
    return session;
  }

  private requireExpectedOrigin(request: Request): void {
    if (request.headers.get("origin") !== this.env.ORIGIN) {
      throw new GatewayHttpError("origin_invalid", 403);
    }
  }

  private async readSession(
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

  private async ensureBootstrapSession(request: Request): Promise<{
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

  private async readBootstrapSession(
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

  private async createHumanSessionResponse(
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

  private storeChallenge(input: {
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

  private getChallenge(
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

  private markChallengeUsed(id: string): void {
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

  private requestRow(id: string): RequestRow {
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

  private findRequestRow(id: string): RequestRow | undefined {
    return this.first<RequestRow>(
      `SELECT id, requester_device_id, requester_name, action,
              client_application, client_source,
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

  private requestActivityRow(requestId: string): RequestActivityRow | undefined {
    return this.first<RequestActivityRow>(
      `SELECT request_id, action, status, created_at, terminal_at, expires_at,
              decided_at, consumed_at, item_title, field_label,
              expected_version, requester_name, client_application,
              client_source, error_code
       FROM request_activity WHERE request_id = ?`,
      requestId,
    );
  }

  private recordTerminalActivity(requestId: string): boolean {
    try {
      this.sql.exec(
        `INSERT INTO request_activity
          (request_id, action, status, created_at, terminal_at, expires_at,
           decided_at, consumed_at, item_title, field_label, expected_version,
           requester_name, client_application, client_source, error_code)
         SELECT id, action, status, created_at, ?, expires_at, decided_at,
                consumed_at, item_title, field_label, expected_version,
                requester_name, client_application, client_source, error_code
         FROM requests
         WHERE id = ? AND status IN ('rejected', 'expired', 'consumed', 'error')
         ON CONFLICT(request_id) DO UPDATE SET
           status = excluded.status,
           terminal_at = excluded.terminal_at,
           decided_at = excluded.decided_at,
           consumed_at = excluded.consumed_at,
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

  private requestOperation(requestId: string): RequestOperationRow {
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

  private activeHumanDevice(id: string): HumanDeviceRow | undefined {
    return this.first<HumanDeviceRow>(
      `SELECT id, label, platform, public_key, created_at, last_seen_at, revoked_at
       FROM human_devices WHERE id = ? AND revoked_at IS NULL`,
      id,
    );
  }

  private activeHumanDeviceCount(): number {
    return (
      this.first<{ count: number }>(
        `SELECT COUNT(*) AS count FROM human_devices WHERE revoked_at IS NULL`,
      )?.count ?? 0
    );
  }

  private async verifyDeviceProof(
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

  private isActiveEventSession(attachment: EventSocketAttachment): boolean {
    return Boolean(
      this.first<{ token_hash: string }>(
        `SELECT s.token_hash FROM human_sessions s
         JOIN human_devices d ON d.id = s.device_id AND d.revoked_at IS NULL
         JOIN human_credentials c ON c.id = s.credential_id AND c.revoked_at IS NULL
         WHERE s.token_hash = ? AND s.device_id = ? AND s.expires_at > ?`,
        attachment.sessionHash,
        attachment.deviceId,
        Date.now(),
      ),
    );
  }

  private broadcastHumanEvent(type: string, entityId?: string): void {
    const message = JSON.stringify({
      at: iso(Date.now()),
      ...(entityId ? { entity_id: entityId } : {}),
      event_id: crypto.randomUUID(),
      type,
    });
    try {
      for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
        try {
          const attachment = socket.deserializeAttachment() as EventSocketAttachment | null;
          if (!attachment || !this.isActiveEventSession(attachment)) {
            this.safeCloseSocket(socket, 4401, "session_expired");
            continue;
          }
          socket.send(message);
        } catch {
          this.safeCloseSocket(socket, 1011, "send_failed");
        }
      }
    } catch {
      console.error(JSON.stringify({ event: "human_event_broadcast_failed" }));
    }
  }

  private closeDeviceSockets(deviceId: string): void {
    for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
      const attachment = socket.deserializeAttachment() as EventSocketAttachment | null;
      if (attachment?.deviceId === deviceId) {
        this.safeCloseSocket(socket, 4403, "device_revoked");
      }
    }
  }

  private closeCredentialSockets(credentialId: string): void {
    for (const socket of this.ctx.getWebSockets(HUMAN_EVENT_SOCKET_TAG)) {
      const attachment = socket.deserializeAttachment() as EventSocketAttachment | null;
      if (attachment?.credentialId === credentialId) {
        this.safeCloseSocket(socket, 4403, "credential_revoked");
      }
    }
  }

  private queueApprovalPush(message: ApprovalPushMessage): void {
    if (!this.env.VAPID_PUBLIC_KEY || !this.env.VAPID_PRIVATE_KEY || !this.env.VAPID_SUBJECT) {
      console.warn(
        JSON.stringify({ event: "approval_push_skipped", reason: "configuration_missing" }),
      );
      return;
    }
    try {
      const subscriptions = this.rows<PushSubscriptionRow>(
        `SELECT p.device_id, p.endpoint, p.p256dh, p.auth, p.expiration_time,
                p.failure_count
         FROM push_subscriptions p
         JOIN human_devices d ON d.id = p.device_id AND d.revoked_at IS NULL
         ORDER BY p.updated_at DESC, p.device_id
         LIMIT ?`,
        MAX_PUSH_FANOUT,
      );
      if (subscriptions.length === 0) {
        console.warn(
          JSON.stringify({ event: "approval_push_skipped", reason: "no_subscription" }),
        );
        return;
      }
      console.log(
        JSON.stringify({
          event: "approval_push_queued",
          subscriptionCount: subscriptions.length,
        }),
      );
      this.ctx.waitUntil(
        this.deliverPushFanout(subscriptions, message)
          .then(() => undefined)
          .catch(() => {
            console.error(JSON.stringify({ event: "approval_push_fanout_failed" }));
          }),
      );
    } catch {
      // Delivery is best effort. A push setup failure must never change the
      // authoritative request or enrollment mutation that already succeeded.
      console.error(JSON.stringify({ event: "approval_push_queue_failed" }));
    }
  }

  private async deliverPushFanout(
    subscriptions: PushSubscriptionRow[],
    message: ApprovalPushMessage,
  ): Promise<void> {
    let nextIndex = 0;
    const deliverNext = async (): Promise<void> => {
      while (nextIndex < subscriptions.length) {
        const subscription = subscriptions[nextIndex];
        nextIndex += 1;
        if (subscription) await this.deliverPushToDevice(subscription, message);
      }
    };
    await Promise.all(
      Array.from(
        { length: Math.min(MAX_PUSH_CONCURRENCY, subscriptions.length) },
        deliverNext,
      ),
    );
  }

  private safeCloseSocket(socket: WebSocket, code: number, reason: string): void {
    try {
      socket.close(code, reason);
    } catch {
      // The peer may have completed the closing handshake between enumeration
      // and this call. There is no remaining connection to clean up in that case.
    }
  }

  private async deliverPushToDevice(
    row: PushSubscriptionRow,
    message: ApprovalPushMessage,
  ): Promise<void> {
    if (
      this.gatewayRuntimeState().locked === 1 &&
      (message.requestId || message.tag.startsWith("requester-"))
    ) {
      console.log(
        JSON.stringify({
          event: "approval_push_skipped",
          reason: "gateway_locked",
        }),
      );
      return;
    }
    if (message.requestId) {
      const current = this.first<{ status: string }>(
        `SELECT status FROM requests WHERE id = ?`,
        message.requestId,
      );
      if (current?.status !== "pending") {
        console.log(
          JSON.stringify({
            event: "approval_push_skipped",
            reason: "request_no_longer_pending",
          }),
        );
        return;
      }
    }
    let result: PushDeliveryResult;
    try {
      result = await deliverWebPush(
        {
          auth: row.auth,
          endpoint: row.endpoint,
          expirationTime: row.expiration_time,
          p256dh: row.p256dh,
        },
        message,
        {
          privateKey: this.env.VAPID_PRIVATE_KEY!,
          publicKey: this.env.VAPID_PUBLIC_KEY!,
          subject: this.env.VAPID_SUBJECT!,
        },
      );
    } catch {
      result = { failureStage: "unknown", outcome: "retry" };
    }
    console.log(
      JSON.stringify({
        event: "approval_push_delivery_completed",
        failureName: result.failureName ?? "none",
        failureStage: result.failureStage ?? "none",
        outcome: result.outcome,
        providerStatus: result.status ?? "no_response",
      }),
    );
    if (result.outcome === "delivered") {
      this.sql.exec(
        `UPDATE push_subscriptions
         SET last_success_at = ?, failure_count = 0 WHERE device_id = ?`,
        Date.now(),
        row.device_id,
      );
      return;
    }
    if (result.outcome === "gone") {
      this.sql.exec(`DELETE FROM push_subscriptions WHERE device_id = ?`, row.device_id);
      this.broadcastHumanEvent("management.changed", row.device_id);
      return;
    }
    const failure = this.first<{ failure_count: number }>(
      `UPDATE push_subscriptions SET failure_count = failure_count + 1
       WHERE device_id = ? RETURNING failure_count`,
      row.device_id,
    );
    if ((failure?.failure_count ?? 0) >= PUSH_FAILURE_DELETE_THRESHOLD) {
      this.sql.exec(`DELETE FROM push_subscriptions WHERE device_id = ?`, row.device_id);
      this.broadcastHumanEvent("management.changed", row.device_id);
    }
  }

  private humanCredential(id: string): HumanCredentialRow {
    const row = this.first<HumanCredentialRow>(
      `SELECT id, public_key, counter, transports, device_type, backed_up, label,
              created_at, last_used_at, revoked_at
       FROM human_credentials WHERE id = ? AND revoked_at IS NULL`,
      id,
    );
    if (!row) throw new GatewayHttpError("credential_not_found", 401);
    return row;
  }

  private listHumanCredentials(): HumanCredentialRow[] {
    return this.rows<HumanCredentialRow>(
        `SELECT id, public_key, counter, transports, device_type, backed_up, label,
                created_at, last_used_at, revoked_at
         FROM human_credentials WHERE revoked_at IS NULL ORDER BY created_at ASC`,
      );
  }

  private hasHumanCredential(): boolean {
    return Boolean(
      this.first<{ id: string }>(
        `SELECT id FROM human_credentials
         WHERE revoked_at IS NULL LIMIT 1`,
      ),
    );
  }

  private bootstrapWasUsed(): boolean {
    return Boolean(
      this.first<{ singleton: number }>(
        `SELECT singleton FROM gateway_bootstrap_state WHERE singleton = 1`,
      ),
    );
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

  private assertIngressRate(request: Request): void {
    const now = Date.now();
    this.ingressGlobalWindow = advanceRateWindow(
      this.ingressGlobalWindow,
      now,
      INGRESS_RATE_WINDOW_MS,
      INGRESS_RATE_GLOBAL_MAX,
      "gateway_rate_limited",
    );

    const rawClient = request.headers.get("cf-connecting-ip") ?? "unknown";
    const client =
      rawClient.length <= 64 && /^[0-9A-Fa-f:.]+$/u.test(rawClient)
        ? rawClient
        : "unknown";
    const current = this.ingressClientWindows.get(client) ?? {
      count: 0,
      startedAt: now,
    };
    this.ingressClientWindows.delete(client);
    this.ingressClientWindows.set(
      client,
      advanceRateWindow(
        current,
        now,
        INGRESS_RATE_WINDOW_MS,
        INGRESS_RATE_CLIENT_MAX,
        "gateway_rate_limited",
      ),
    );
    while (this.ingressClientWindows.size > INGRESS_RATE_CLIENT_MAX_ENTRIES) {
      const oldest = this.ingressClientWindows.keys().next().value as string | undefined;
      if (!oldest) break;
      this.ingressClientWindows.delete(oldest);
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

  private assertRequesterAuthenticatedRate(requesterDeviceId: string): void {
    const now = Date.now();
    const current = this.requesterAuthWindows.get(requesterDeviceId) ?? {
      count: 0,
      startedAt: now,
    };
    this.requesterAuthWindows.delete(requesterDeviceId);
    this.requesterAuthWindows.set(
      requesterDeviceId,
      advanceRateWindow(
        current,
        now,
        INGRESS_RATE_WINDOW_MS,
        REQUESTER_AUTH_RATE_MAX,
        "requester_rate_limited",
      ),
    );
    while (this.requesterAuthWindows.size > REQUESTER_AUTH_RATE_MAX_ENTRIES) {
      const oldest = this.requesterAuthWindows.keys().next().value as
        | string
        | undefined;
      if (!oldest) break;
      this.requesterAuthWindows.delete(oldest);
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
    if (rememberedSsh) {
      incrementCount(this.rememberedSshCreationReservations, requesterDeviceId);
    }
    return { rememberedSsh, requesterDeviceId };
  }

  private releaseRequestCreationRate(
    reservation: RequestCreationReservation,
  ): void {
    decrementCount(this.requestCreationReservations, reservation.requesterDeviceId);
    if (reservation.rememberedSsh) {
      decrementCount(
        this.rememberedSshCreationReservations,
        reservation.requesterDeviceId,
      );
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
    this.assertStorageGrowthAllowed();
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

  private countRows(table: string): number {
    const allowed = new Set([
      "bootstrap_sessions",
      "gateway_bootstrap_state",
      "human_credentials",
      "human_device_enrollments",
      "human_devices",
      "human_sessions",
      "push_subscriptions",
      "webauthn_challenges",
    ]);
    if (!allowed.has(table)) {
      throw new TypeError("Unsupported reset table");
    }
    return this.first<{ count: number }>(
      `SELECT COUNT(*) AS count FROM ${table}`,
    )?.count ?? 0;
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

  private expireDueState(now: number): void {
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
    this.ctx.storage.transactionSync(() => {
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
          if (!uncertainMutation) this.clearPendingPayload(row.id);
        } else {
          this.sql.exec(
            `UPDATE requests SET status = 'expired'
             WHERE id = ? AND status = ?`,
            row.id,
            row.status,
          );
          this.clearPendingPayload(row.id);
        }
      }
    });
    for (const row of dueRequests) {
      if (row.status !== "executing" || row.action === "secret.read" || row.action === "ssh.sign") {
        this.recordTerminalActivity(row.id);
      }
      this.broadcastHumanEvent("request.changed", row.id);
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
      this.broadcastHumanEvent("requester-enrollment.changed", row.id);
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
      now - SSH_GRANT_MAX_STORAGE_MS,
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

  private retentionSweepDue(now: number): boolean {
    const state = this.first<{ next_retention_at: number }>(
      `SELECT next_retention_at FROM gateway_maintenance_state WHERE singleton = 1`,
    );
    return !state || state.next_retention_at <= now;
  }

  private runRetentionSweep(now: number): void {
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
      if (!this.recordTerminalActivity(row.id)) {
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
    this.ctx.storage.transactionSync(() => {
      for (const row of purgeRequests) {
        this.sql.exec(`DELETE FROM request_operations WHERE request_id = ?`, row.id);
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

  private initializeSchema(): void {
    for (const statement of [
      `CREATE TABLE IF NOT EXISTS human_credentials (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL,
        transports TEXT NOT NULL,
        device_type TEXT NOT NULL,
        backed_up INTEGER NOT NULL,
        label TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        challenge TEXT NOT NULL,
        target_id TEXT,
        decision TEXT,
        payload TEXT,
        expires_at INTEGER NOT NULL,
        used_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS human_sessions (
        token_hash TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL,
        device_id TEXT,
        csrf_token TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        expires_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS human_devices (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        platform TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS human_device_enrollments (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        label TEXT NOT NULL,
        platform TEXT NOT NULL,
        public_key TEXT NOT NULL,
        public_key_fingerprint TEXT NOT NULL,
        requested_by_credential_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        terminal_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS push_subscriptions (
        device_id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL UNIQUE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        expiration_time INTEGER,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_success_at INTEGER,
        failure_count INTEGER NOT NULL DEFAULT 0
      )`,
      `CREATE TABLE IF NOT EXISTS bootstrap_sessions (
        id TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        armed_until INTEGER,
        consumed_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_bootstrap_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        used_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS requester_enrollments (
        id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        display_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        public_key_fingerprint TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        terminal_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS requesters (
        device_id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        public_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        revoked_at INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS requester_nonces (
        device_id TEXT NOT NULL,
        nonce TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        PRIMARY KEY (device_id, nonce)
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_runtime_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        locked INTEGER NOT NULL,
        lock_generation INTEGER NOT NULL,
        changed_at INTEGER NOT NULL,
        changed_by TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS ssh_authorization_grants (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        agent_instance_public_key TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL,
        item_id TEXT NOT NULL,
        item_title TEXT NOT NULL,
        item_version INTEGER NOT NULL,
        fingerprint TEXT NOT NULL,
        duration TEXT NOT NULL,
        lock_generation INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER,
        revoked_at INTEGER,
        authorized_by_credential_id TEXT NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS requests (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        requester_name TEXT NOT NULL,
        action TEXT NOT NULL,
        item_id TEXT NOT NULL,
        field_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        ssh_agent_instance_public_key TEXT,
        ssh_scope_id TEXT,
        ssh_scope_kind TEXT,
        ssh_grant_id TEXT,
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        body_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        authorized_until INTEGER,
        execution_started_at INTEGER,
        consumed_at INTEGER,
        error_code TEXT,
        UNIQUE (requester_device_id, idempotency_key)
      )`,
      `CREATE TABLE IF NOT EXISTS request_operations (
        request_id TEXT PRIMARY KEY,
        operation_summary TEXT NOT NULL,
        payload_aad TEXT,
        payload_ciphertext TEXT,
        payload_digest TEXT,
        payload_iv TEXT,
        reconcile_state TEXT,
        reconcile_attempt_count INTEGER NOT NULL DEFAULT 0,
        reconcile_attempted_at INTEGER,
        result_item_id TEXT,
        result_version INTEGER
      )`,
      `CREATE TABLE IF NOT EXISTS request_activity (
        request_id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        terminal_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        consumed_at INTEGER,
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        requester_name TEXT NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        error_code TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_crypto_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        master_key_fingerprint TEXT NOT NULL,
        initialized_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT NOT NULL,
        request_id TEXT,
        actor_id TEXT,
        created_at INTEGER NOT NULL
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_maintenance_state (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        next_retention_at INTEGER NOT NULL,
        retention_active INTEGER NOT NULL DEFAULT 0,
        retention_started_at INTEGER,
        activity_backfill_done INTEGER NOT NULL DEFAULT 0,
        activity_backfill_cursor_created_at INTEGER,
        activity_backfill_cursor_id TEXT,
        request_trim_done INTEGER NOT NULL DEFAULT 0,
        audit_trim_done INTEGER NOT NULL DEFAULT 0,
        activity_trim_done INTEGER NOT NULL DEFAULT 0,
        request_cutoff_created_at INTEGER,
        request_cutoff_id TEXT,
        audit_cutoff_created_at INTEGER,
        audit_cutoff_id INTEGER,
        activity_cutoff_created_at INTEGER,
        activity_cutoff_id TEXT
      )`,
      `CREATE TABLE IF NOT EXISTS gateway_schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      )`,
      `CREATE INDEX IF NOT EXISTS idx_requests_created_at
       ON requests(created_at DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_requests_transition_deadline
       ON requests(status, expires_at, authorized_until, execution_started_at)`,
      `CREATE INDEX IF NOT EXISTS idx_request_activity_cursor
       ON request_activity(created_at DESC, request_id DESC)`,
      `CREATE INDEX IF NOT EXISTS idx_request_activity_terminal
       ON request_activity(terminal_at, request_id)`,
      `CREATE INDEX IF NOT EXISTS idx_enrollments_status
       ON requester_enrollments(status, created_at)`,
      `CREATE INDEX IF NOT EXISTS idx_human_device_enrollments_status
       ON human_device_enrollments(status, created_at)`,
      `CREATE INDEX IF NOT EXISTS idx_gateway_audit_retention
       ON gateway_audit(created_at, id)`,
      `CREATE INDEX IF NOT EXISTS idx_human_devices_revoked
       ON human_devices(revoked_at, id)`,
      `CREATE INDEX IF NOT EXISTS idx_requester_nonces_expiry
       ON requester_nonces(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_human_sessions_expiry
       ON human_sessions(expires_at)`,
      `CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expiry
       ON webauthn_challenges(expires_at, used_at)`,
      `CREATE INDEX IF NOT EXISTS idx_ssh_authorization_grants_lookup
       ON ssh_authorization_grants(
         requester_device_id, agent_instance_public_key, scope_id, item_id,
         item_version, fingerprint, revoked_at
       )`,
    ]) {
      this.sql.exec(statement);
    }
    this.ensureColumn("human_credentials", "last_used_at", "INTEGER");
    this.ensureColumn("human_sessions", "device_id", "TEXT");
    this.ensureColumn("human_sessions", "last_seen_at", "INTEGER");
    this.ensureColumn(
      "request_operations",
      "reconcile_attempt_count",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn("request_operations", "reconcile_attempted_at", "INTEGER");
    this.ensureColumn("requests", "ssh_agent_instance_public_key", "TEXT");
    this.ensureColumn("requests", "ssh_scope_id", "TEXT");
    this.ensureColumn("requests", "ssh_scope_kind", "TEXT");
    this.ensureColumn("requests", "ssh_grant_id", "TEXT");
    this.ensureColumn(
      "ssh_authorization_grants",
      "item_title",
      "TEXT NOT NULL DEFAULT 'SSH key'",
    );
    this.migrateRequestClientObservation();
    this.ensureColumn("requester_enrollments", "terminal_at", "INTEGER");
    this.ensureColumn("human_device_enrollments", "terminal_at", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "retention_active",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn("gateway_maintenance_state", "retention_started_at", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_cursor_created_at",
      "INTEGER",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_backfill_cursor_id",
      "TEXT",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "request_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "audit_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_trim_done",
      "INTEGER NOT NULL DEFAULT 0",
    );
    this.ensureColumn(
      "gateway_maintenance_state",
      "request_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "request_cutoff_id", "TEXT");
    this.ensureColumn(
      "gateway_maintenance_state",
      "audit_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "audit_cutoff_id", "INTEGER");
    this.ensureColumn(
      "gateway_maintenance_state",
      "activity_cutoff_created_at",
      "INTEGER",
    );
    this.ensureColumn("gateway_maintenance_state", "activity_cutoff_id", "TEXT");
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_requester_enrollment_retention
       ON requester_enrollments(status, expires_at, terminal_at)`,
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_human_device_enrollment_retention
       ON human_device_enrollments(status, expires_at, terminal_at)`,
    );
    this.sql.exec(
      `CREATE INDEX IF NOT EXISTS idx_requests_transition_deadline
       ON requests(status, expires_at, authorized_until, execution_started_at)`,
    );
    this.sql.exec(
      `UPDATE requester_enrollments SET terminal_at = created_at
       WHERE status != 'pending' AND terminal_at IS NULL`,
    );
    this.sql.exec(
      `UPDATE human_device_enrollments SET terminal_at = created_at
       WHERE status != 'pending' AND terminal_at IS NULL`,
    );
    // Retire the former second-device approval ceremony. A fresh registered
    // Passkey now authorizes device registration directly; old pending rows
    // are migration-only receipts and become eligible for bounded cleanup.
    this.sql.exec(
      `UPDATE human_device_enrollments
       SET status = 'rejected', terminal_at = COALESCE(terminal_at, ?)
       WHERE status = 'pending'`,
      Date.now(),
    );
    // Migrate away from the old correctness-independent persistent cache.
    this.sql.exec(`DROP TABLE IF EXISTS catalog_metadata_cache`);
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_runtime_state
        (singleton, locked, lock_generation, changed_at, changed_by)
       VALUES (1, 0, 0, ?, 'system')`,
      Date.now(),
    );
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_maintenance_state
        (singleton, next_retention_at) VALUES (1, ?)`,
      Date.now() + RETENTION_SWEEP_INTERVAL_MS,
    );
    this.sql.exec(
      `INSERT OR IGNORE INTO gateway_schema_migrations (version, applied_at)
       VALUES (1, ?)`,
      Date.now(),
    );
    this.migrateLegacyDefaultPasskeyLabel();
  }

  private migrateLegacyDefaultPasskeyLabel(): void {
    const migrated = this.first<{ version: number }>(
      `SELECT version FROM gateway_schema_migrations WHERE version = 2`,
    );
    if (migrated) return;

    this.ctx.storage.transactionSync(() => {
      this.sql.exec(
        `UPDATE human_credentials SET label = ?
         WHERE id = (
           SELECT id FROM human_credentials
           WHERE label = ? AND revoked_at IS NULL
           ORDER BY created_at ASC LIMIT 1
         )`,
        DEFAULT_PASSKEY_LABEL,
        LEGACY_DEFAULT_PASSKEY_LABEL,
      );
      this.sql.exec(
        `INSERT INTO gateway_schema_migrations (version, applied_at)
         VALUES (2, ?)`,
        Date.now(),
      );
    });
  }

  private migrateRequestClientObservation(): void {
    const columns = this.rows<{ name: string }>("PRAGMA table_info(requests)");
    if (columns.some((column) => column.name === "client_application")) return;
    const now = Date.now();
    const active = this.first<{ id: string }>(
      `SELECT id FROM requests
       WHERE status IN ('executing', 'unknown')
          OR (status = 'pending' AND expires_at > ?)
          OR (status = 'approved' AND COALESCE(authorized_until, expires_at) > ?)
       LIMIT 1`,
      now,
      now,
    );
    if (active) {
      throw new Error("request_schema_migration_blocked_by_active_request");
    }

    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM request_operations");
      this.sql.exec("DROP TABLE IF EXISTS requests_client_observation");
      this.sql.exec(`CREATE TABLE requests_client_observation (
        id TEXT PRIMARY KEY,
        requester_device_id TEXT NOT NULL,
        requester_name TEXT NOT NULL,
        action TEXT NOT NULL,
        item_id TEXT NOT NULL,
        field_id TEXT NOT NULL,
        expected_version INTEGER NOT NULL,
        client_application TEXT NOT NULL,
        client_source TEXT NOT NULL,
        ssh_agent_instance_public_key TEXT,
        ssh_scope_id TEXT,
        ssh_scope_kind TEXT,
        ssh_grant_id TEXT,
        item_title TEXT NOT NULL,
        field_label TEXT NOT NULL,
        field_type TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        body_hash TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        decided_at INTEGER,
        authorized_until INTEGER,
        execution_started_at INTEGER,
        consumed_at INTEGER,
        error_code TEXT,
        UNIQUE (requester_device_id, idempotency_key)
      )`);
      this.sql.exec("DROP TABLE requests");
      this.sql.exec("ALTER TABLE requests_client_observation RENAME TO requests");
      this.sql.exec(
        "CREATE INDEX IF NOT EXISTS idx_requests_created_at ON requests(created_at DESC)",
      );
      this.sql.exec(
        `INSERT INTO gateway_audit (event, request_id, actor_id, created_at)
         VALUES ('request_schema_replaced', NULL, 'system', ?)`,
        Date.now(),
      );
    });
  }

  private ensureColumn(table: string, column: string, declaration: string): void {
    const existing = this.rows<{ name: string }>(`PRAGMA table_info(${table})`);
    if (existing.some((entry) => entry.name === column)) return;
    this.sql.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${declaration}`);
  }
}

function projectEnrollment(row: EnrollmentRow) {
  return {
    created_at: iso(row.created_at),
    device_id: row.device_id,
    display_name: row.display_name,
    expires_at: iso(row.expires_at),
    id: row.id,
    public_key_fingerprint: row.public_key_fingerprint,
    status: row.status,
  };
}

function projectRequesterStatus(
  row: RequestRow,
  operation?: RequestOperationRow,
) {
  return {
    ...(row.authorized_until
      ? { authorized_until: iso(row.authorized_until) }
      : {}),
    ...(row.error_code ? { error: row.error_code } : {}),
    expires_at: iso(row.expires_at),
    ...(row.status === "consumed" && operation?.result_item_id
      ? { item_id: operation.result_item_id }
      : {}),
    request_id: row.id,
    status: publicRequestState(row.status),
    ...(row.status === "consumed" && operation && operation.result_version !== null
      ? { version: operation.result_version }
      : {}),
  };
}

function readOnlyRequestState(row: RequestRow, now: number): RequestRow {
  if (
    (row.status === "pending" && row.expires_at <= now) ||
    (row.status === "approved" && (row.authorized_until ?? 0) <= now)
  ) {
    return { ...row, status: "expired" };
  }
  return row;
}

function projectHumanRequestSummary(row: RequestRow) {
  return {
    action: projectApprovalAction(row.action),
    ...(row.action === "ssh.sign" &&
    row.ssh_agent_instance_public_key &&
    row.ssh_scope_id &&
    (row.ssh_scope_kind === "application" ||
      row.ssh_scope_kind === "terminal-session")
      ? {
          authorization_session: {
            scope_kind: row.ssh_scope_kind,
          },
        }
      : {}),
    client: {
      application: row.client_application,
      source:
        row.client_source === "process-ancestry"
          ? "process-ancestry"
          : "unavailable",
    },
    created_at: iso(row.created_at),
    expires_at: iso(row.expires_at),
    request_id: row.id,
    requester_name: row.requester_name,
    status: uiRequestState(row.status),
    target_label: mutationTargetLabel(row),
    verified_version: row.expected_version,
  };
}

function projectHumanActivitySummary(row: RequestActivityRow) {
  return {
    action: projectApprovalAction(row.action),
    client: {
      application: row.client_application,
      source:
        row.client_source === "process-ancestry"
          ? "process-ancestry"
          : "unavailable",
    },
    created_at: iso(row.created_at),
    expires_at: iso(row.expires_at),
    request_id: row.request_id,
    requester_name: row.requester_name,
    status: uiRequestState(row.status),
    target_label:
      row.action === "secret.read"
        ? `${row.item_title} · ${row.field_label}`
        : row.item_title,
    verified_version: row.expected_version,
  };
}

function projectHumanActivityDetail(row: RequestActivityRow) {
  return {
    ...projectHumanActivitySummary(row),
    error: row.error_code ?? undefined,
    verified_facts: [
      { label: "Requester", value: row.requester_name },
      { label: "Completed", value: iso(row.terminal_at) },
    ],
  };
}

function projectHumanRequestDetail(row: RequestRow) {
  const mutationFacts = parseOperationSummary(row.operation_summary);
  return {
    ...projectHumanRequestSummary(row),
    authorized_until: row.authorized_until
      ? iso(row.authorized_until)
      : undefined,
    error: row.error_code ?? undefined,
    expected_version: row.expected_version,
    field_id: row.field_id,
    item_id: row.item_id,
    verified_facts:
      row.action === "secret.read"
        ? [
            { label: "Item", value: row.item_title },
            { label: "Field", value: row.field_label },
            { label: "Version", value: String(row.expected_version) },
            { label: "Requester", value: row.requester_name },
          ]
        : [
            ...mutationFacts,
            { label: "Requester", value: row.requester_name },
          ],
  };
}

function projectApprovalAction(value: string) {
  if (
    value === "secret.read" ||
    value === "item.create" ||
    value === "item.patch" ||
    value === "item.archive" ||
    value === "ssh.sign"
  ) {
    return value;
  }
  return "secret.read";
}

function mutationTargetLabel(row: RequestRow): string {
  if (
    row.action === "item.create" ||
    row.action === "item.patch" ||
    row.action === "item.archive" ||
    row.action === "ssh.sign"
  ) {
    return row.item_title;
  }
  return `${row.item_title} · ${row.field_label}`;
}

function catalogMetadataCacheKey(
  itemId: string,
  fieldId: string,
  version: number,
): string {
  return `${itemId}\u0000${fieldId}\u0000${String(version)}`;
}

function parseOperationSummary(
  value: string | null,
): Array<{ label: string; value: string }> {
  if (!value) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed) || parsed.length > 40) return [];
  const facts: Array<{ label: string; value: string }> = [];
  for (const candidate of parsed) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      return [];
    }
    const fact = candidate as Record<string, unknown>;
    if (
      typeof fact.label !== "string" ||
      typeof fact.value !== "string" ||
      fact.label.length === 0 ||
      fact.label.length > 160 ||
      fact.value.length === 0 ||
      fact.value.length > 512 ||
      hasForbiddenControl(fact.label, true) ||
      hasForbiddenControl(fact.value, true)
    ) {
      return [];
    }
    facts.push({ label: fact.label, value: fact.value });
  }
  return facts;
}

function publicRequestState(value: string): RequestState {
  if (
    value === "pending" ||
    value === "approved" ||
    value === "rejected" ||
    value === "expired" ||
    value === "executing" ||
    value === "consumed" ||
    value === "error" ||
    value === "unknown"
  ) {
    return value;
  }
  return "error";
}

function uiRequestState(value: string) {
  switch (publicRequestState(value)) {
    case "pending":
      return "pending";
    case "approved":
      return "approved";
    case "consumed":
      return "consumed";
    case "rejected":
      return "denied";
    case "expired":
      return "expired";
    case "executing":
      return "submitting";
    case "error":
    case "unknown":
      return "error";
  }
}

async function readDecisionBody(
  request: Request,
): Promise<{
  authorization_duration?: SshAuthorizationDuration;
  decision: ApprovalDecision;
}> {
  const body = await readJsonObject<{
    authorization_duration?: unknown;
    decision?: unknown;
  }>(request);
  assertExactKeys(
    body,
    body.authorization_duration === undefined
      ? ["decision"]
      : ["authorization_duration", "decision"],
  );
  return {
    ...(body.authorization_duration === undefined
      ? {}
      : {
          authorization_duration:
            safeSshAuthorizationDuration(body.authorization_duration),
        }),
    decision: safeDecision(body.decision),
  };
}

async function readDecisionVerifyBody(request: Request): Promise<{
  authorization_duration?: SshAuthorizationDuration;
  challenge_id: string;
  decision: ApprovalDecision;
  response: Record<string, unknown>;
}> {
  const body = await readJsonObject<{
    authorization_duration?: unknown;
    challenge_id?: unknown;
    decision?: unknown;
    response?: unknown;
  }>(request);
  assertExactKeys(
    body,
    body.authorization_duration === undefined
      ? ["challenge_id", "decision", "response"]
      : ["authorization_duration", "challenge_id", "decision", "response"],
  );
  return {
    ...(body.authorization_duration === undefined
      ? {}
      : {
          authorization_duration:
            safeSshAuthorizationDuration(body.authorization_duration),
        }),
    challenge_id: safeIdentifier(body.challenge_id, "challenge_id"),
    decision: safeDecision(body.decision),
    response: record(body.response),
  };
}

async function readChallengeVerifyBody(request: Request): Promise<{
  challenge_id: string;
  response: Record<string, unknown>;
}> {
  const body = await readJsonObject<{
    challenge_id?: unknown;
    response?: unknown;
  }>(request);
  return {
    challenge_id: safeIdentifier(body.challenge_id, "challenge_id"),
    response: record(body.response),
  };
}

async function readJsonObject<T extends object = Record<string, unknown>>(
  request: Request,
): Promise<T> {
  const declared = Number(request.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_JSON_BYTES) {
    throw new GatewayHttpError("request_too_large", 413);
  }
  if (!request.body) throw new GatewayHttpError("invalid_json", 400);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_JSON_BYTES) {
      await reader.cancel();
      throw new GatewayHttpError("request_too_large", 413);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new GatewayHttpError("invalid_json", 400);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new GatewayHttpError("invalid_json", 400);
  }
  return parsed as T;
}

function safeDecision(value: unknown): ApprovalDecision {
  if (value !== "approve" && value !== "reject") {
    throw new GatewayHttpError("decision_invalid", 400);
  }
  return value;
}

function safeSshAuthorizationDuration(
  value: unknown,
): SshAuthorizationDuration {
  if (
    value !== "until-lock" &&
    value !== "until-agent-quits" &&
    value !== "4-hours" &&
    value !== "12-hours" &&
    value !== "24-hours"
  ) {
    throw new GatewayHttpError("authorization_duration_invalid", 400);
  }
  return value;
}

function safeClientObservation(value: unknown): ClientObservationRequest {
  const input = record(value);
  assertExactKeys(input, ["application", "source"]);
  if (
    input.source !== "process-ancestry" &&
    input.source !== "unavailable"
  ) {
    throw new GatewayHttpError("client_observation_invalid", 400);
  }
  return {
    application: safeObservationText(input.application, 64),
    source: input.source,
  };
}

function safeObservationText(value: unknown, maximumLength: number): string {
  const text = safeText(value, maximumLength).trim();
  if (!text) throw new GatewayHttpError("text_invalid", 400);
  return text;
}

function assertExactKeys(
  value: object,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new GatewayHttpError("request_schema_invalid", 400);
  }
}

function safeDeviceId(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length < 8 ||
    value.length > 128 ||
    !/^[A-Za-z0-9._-]+$/u.test(value)
  ) {
    throw new GatewayHttpError("device_id_invalid", 400);
  }
  return value;
}

function safeHumanDeviceInput(value: unknown): {
  device_id: string;
  label: string;
  platform: string;
  public_key: string;
} {
  const input = record(value);
  return {
    device_id: safeDeviceId(input.device_id),
    label: safeText(input.label, 80),
    platform: safePlatform(input.platform),
    public_key: safeDevicePublicKey(input.public_key),
  };
}

function safePlatform(value: unknown): string {
  if (
    value !== "iphone" &&
    value !== "ipad" &&
    value !== "mac" &&
    value !== "other"
  ) {
    throw new GatewayHttpError("device_platform_invalid", 400);
  }
  return value;
}

function safeDevicePublicKey(value: unknown): string {
  let key: Record<string, unknown>;
  try {
    key = typeof value === "string" ? record(JSON.parse(value)) : record(value);
  } catch {
    throw new GatewayHttpError("device_public_key_invalid", 400);
  }
  if (
    key.kty !== "EC" ||
    key.crv !== "P-256" ||
    !isBase64UrlBytes(key.x, 32) ||
    !isBase64UrlBytes(key.y, 32)
  ) {
    throw new GatewayHttpError("device_public_key_invalid", 400);
  }
  return JSON.stringify({ crv: "P-256", kty: "EC", x: key.x, y: key.y });
}

function isBase64UrlBytes(value: unknown, expectedBytes: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    return decodeBase64Url(value).byteLength === expectedBytes;
  } catch {
    return false;
  }
}

function deviceProofMessage(
  purpose: string,
  challengeId: string,
  challenge: string,
  deviceId: string,
): string {
  return ["1p-human-device-v1", purpose, challengeId, challenge, deviceId].join("\n");
}

function safeIdentifier(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    value.includes("/") ||
    hasForbiddenControl(value, false)
  ) {
    throw new GatewayHttpError(`${name}_invalid`, 400);
  }
  return value;
}

function safePositiveInteger(value: unknown, name: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new GatewayHttpError(`${name}_invalid`, 400);
  }
  return value as number;
}

function safeText(
  value: unknown,
  maximumLength: number,
  fallback?: string,
): string {
  if (value === undefined && fallback !== undefined) return fallback;
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    [...value].length > maximumLength ||
    hasForbiddenControl(value, true)
  ) {
    throw new GatewayHttpError("text_invalid", 400);
  }
  return value.normalize("NFC");
}

function safeBase64Url(
  value: unknown,
  expectedBytes: number,
  name: string,
): string {
  if (typeof value !== "string") {
    throw new GatewayHttpError(`${name}_invalid`, 400);
  }
  try {
    if (decodeBase64Url(value).byteLength !== expectedBytes) {
      throw new Error("length");
    }
  } catch {
    throw new GatewayHttpError(`${name}_invalid`, 400);
  }
  return value;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GatewayHttpError("object_invalid", 400);
  }
  return value as Record<string, unknown>;
}

function parseJsonObject(value: string | null): Record<string, unknown> {
  if (!value) return {};
  try {
    return record(JSON.parse(value));
  } catch {
    throw new GatewayHttpError("stored_state_invalid", 500);
  }
}

function parseTransports(value: string): AuthenticatorTransportFuture[] {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (transport): transport is AuthenticatorTransportFuture =>
        typeof transport === "string" &&
        [
          "ble",
          "cable",
          "hybrid",
          "internal",
          "nfc",
          "smart-card",
          "usb",
        ].includes(transport),
    );
  } catch {
    return [];
  }
}

function randomToken(bytes: number): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

async function bootstrapRequestIdForToken(token: string): Promise<string> {
  return (await sha256Base64Url(token)).slice(0, 22);
}

function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const segment of header.split(";")) {
    const [rawName, ...rawValue] = segment.trim().split("=");
    if (rawName === name) return rawValue.join("=");
  }
  return undefined;
}

function constantTimeStringEquals(
  actual: string | undefined,
  expected: string | undefined,
): boolean {
  if (!actual || !expected) return false;
  const left = new TextEncoder().encode(actual);
  const right = new TextEncoder().encode(expected);
  let difference = left.length ^ right.length;
  for (let index = 0; index < Math.min(left.length, right.length); index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

function advanceRateWindow(
  current: RateWindow,
  now: number,
  windowMs: number,
  maximum: number,
  errorCode: string,
): RateWindow {
  if (current.startedAt <= 0 || now - current.startedAt >= windowMs) {
    return { count: 1, startedAt: now };
  }
  if (current.count >= maximum) {
    throw new GatewayHttpError(errorCode, 429);
  }
  return { count: current.count + 1, startedAt: current.startedAt };
}

function incrementCount(counts: Map<string, number>, key: string): void {
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

function decrementCount(counts: Map<string, number>, key: string): void {
  const remaining = (counts.get(key) ?? 0) - 1;
  if (remaining <= 0) {
    counts.delete(key);
    return;
  }
  counts.set(key, remaining);
}

function json(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  let serialized = JSON.stringify(body);
  if (new TextEncoder().encode(serialized).byteLength > MAX_JSON_RESPONSE_BYTES) {
    console.error(JSON.stringify({ event: "gateway_response_too_large" }));
    serialized = JSON.stringify({
      code: "response_too_large",
      error: "response_too_large",
      ok: false,
    });
    status = 500;
    headers = {};
  }
  return new Response(serialized, {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      ...headers,
    },
    status,
  });
}

function errorResponse(code: string, status: number): Response {
  return json(
    { code, error: code, ok: false },
    status,
    { "x-onenod-error-code": code },
  );
}

function safeErrorName(error: unknown): string {
  return error instanceof Error &&
    /^[A-Za-z][A-Za-z0-9]{0,39}$/u.test(error.name)
    ? error.name
    : "UnknownError";
}

function isUncertainWriteFailure(code: string): boolean {
  return (
    code === "onepassword_write_outcome_unknown" ||
    code === "executor_timeout" ||
    code === "executor_unavailable" ||
    code === "executor_destroy_failed"
  );
}

function safeSshSignatureAlgorithm(value: string) {
  if (
    value === "ssh-ed25519" ||
    value === "rsa-sha2-256" ||
    value === "rsa-sha2-512"
  ) {
    return value;
  }
  throw new GatewayHttpError("ssh_sign_request_invalid", 400);
}

function classifyStorageError(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  if (/SQLITE_FULL|database or disk is full|storage quota/iu.test(message)) {
    return "full";
  }
  if (/no column|has no column|unknown column/iu.test(message)) {
    return "column_missing";
  }
  if (/not null/iu.test(message)) return "not_null_constraint";
  if (/unique|primary key/iu.test(message)) return "unique_constraint";
  if (/foreign key/iu.test(message)) return "foreign_key_constraint";
  if (/values?.*columns?|columns?.*values?/iu.test(message)) {
    return "column_value_count";
  }
  if (/bind|parameter|variable/iu.test(message)) return "binding_invalid";
  if (/datatype|type mismatch/iu.test(message)) return "datatype_invalid";
  return "unclassified";
}

function sanitizeExecutorEnvelope<T>(sanitize: () => T): T {
  try {
    return sanitize();
  } catch (error) {
    if (error instanceof ExecutorTransportError) {
      throw new GatewayHttpError("executor_response_invalid", 502);
    }
    throw error;
  }
}

function hasForbiddenControl(
  value: string,
  allowTabAndLineBreak: boolean,
): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint === 0x7f) return true;
    if (codePoint >= 0x20) continue;
    if (
      allowTabAndLineBreak &&
      (codePoint === 0x09 || codePoint === 0x0a || codePoint === 0x0d)
    ) {
      continue;
    }
    return true;
  }
  return false;
}
