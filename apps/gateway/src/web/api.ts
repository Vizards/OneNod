import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import type {
  ApprovalAction,
  ApprovalStatus,
  RequestDetail,
  RequestListResponse,
  RequestSummary,
  SshAuthorizationDuration,
  SystemHealthResponse,
} from "@onenod/protocol";

const CSRF_STORAGE_KEY = "onepassword-remote.csrf";

export type ApprovalDecision = "approve" | "reject";

export interface HumanState {
  authenticated: boolean;
  bootstrapRequestId?: string;
  currentDeviceId?: string;
  deviceTrusted: boolean;
  initialized: boolean;
  locked: boolean;
}

export interface HumanCredentialSummary {
  backedUp: boolean;
  createdAt: string;
  current: boolean;
  deviceType: string;
  id: string;
  label: string;
  lastUsedAt?: string;
}

export interface HumanDeviceSummary {
  createdAt: string;
  current: boolean;
  id: string;
  label: string;
  lastSeenAt: string;
  platform: string;
  pushEnabled: boolean;
}

export interface HumanManagement {
  credentials: HumanCredentialSummary[];
  devices: HumanDeviceSummary[];
  requesters: RequesterSummary[];
  sshAuthorizations: SshAuthorizationSummary[];
}

export interface SshAuthorizationSummary {
  application: string;
  createdAt: string;
  duration: SshAuthorizationDuration;
  expiresAt?: string;
  fingerprint: string;
  id: string;
  itemId: string;
  itemTitle: string;
  itemVersion: number;
  requesterDeviceId: string;
  scopeKind: "application" | "terminal-session";
}

export interface DeviceRegistrationInput {
  device_id: string;
  label: string;
  platform: string;
  public_key: JsonWebKey;
}

export interface RequesterEnrollment {
  createdAt: string;
  deviceId: string;
  displayName: string;
  expiresAt: string;
  id: string;
  publicKeyFingerprint: string;
  status: string;
}

export interface RequesterSummary {
  createdAt: string;
  deviceId: string;
  displayName: string;
  publicKeyFingerprint: string;
}

export interface VerifyDecisionResponse {
  ok: true;
  status: string;
}

export interface PaginatedRequestListResponse extends RequestListResponse {
  nextCursor?: string;
}

interface WebAuthnOptionsEnvelope<TOptions> {
  challenge_id: string;
  options: TOptions;
}

export class ApiError extends Error {
  readonly code: string | undefined;
  readonly requestId: string | undefined;
  readonly status: number;

  constructor(message: string, status: number, code?: string, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.requestId = requestId;
    this.status = status;
  }
}

export async function getHumanState(): Promise<HumanState> {
  const response = await fetchJson<unknown>("/v1/human/state");
  const record = asRecord(response);
  const session = isRecord(record.session) ? record.session : undefined;
  const bootstrapRequestId = readString(
    record,
    "bootstrap_request_id",
    "bootstrapRequestId",
  );

  return {
    authenticated:
      readBoolean(record, "authenticated") ??
      readBoolean(session, "authenticated") ??
      false,
    ...(bootstrapRequestId ? { bootstrapRequestId } : {}),
    initialized:
      readBoolean(record, "initialized", "has_human_credential") ??
      false,
    ...(readString(record, "current_device_id", "currentDeviceId")
      ? {
          currentDeviceId: readString(
            record,
            "current_device_id",
            "currentDeviceId",
          )!,
        }
      : {}),
    deviceTrusted: readBoolean(record, "device_trusted", "deviceTrusted") ?? false,
    locked: readBoolean(record, "locked") ?? false,
  };
}

export function beginBootstrapRegistration(
  label = "Mac passkey",
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialCreationOptionsJSON>> {
  return postJson("/v1/bootstrap/registration/options", { label });
}

export function authorizeBootstrapToken(
  token: string,
): Promise<{ armed_until: string; ok: true }> {
  return postJson("/v1/bootstrap/authorize", { token }, false);
}

export function verifyBootstrapRegistration(
  challengeId: string,
  response: RegistrationResponseJSON,
): Promise<{ ok: true; csrf_token: string }> {
  return postJson(
    "/v1/bootstrap/registration/verify",
    { challenge_id: challengeId, response },
    false,
  );
}

export function beginHumanSession(deviceId: string): Promise<
  WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON> & {
    device_challenge: string;
    device_trusted: boolean;
  }
> {
  return postJson("/v1/human/session/options", { device_id: deviceId });
}

export function verifyHumanSession(
  challengeId: string,
  response: AuthenticationResponseJSON,
  deviceSignature?: string,
): Promise<{ ok: true; csrf_token: string; device_trusted: boolean }> {
  return postJson(
    "/v1/human/session/verify",
    {
      challenge_id: challengeId,
      ...(deviceSignature ? { device_signature: deviceSignature } : {}),
      response,
    },
    false,
  );
}

export function beginDeviceRegistration(
  input: DeviceRegistrationInput,
): Promise<
  WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON> & {
    device_challenge: string;
  }
> {
  return postJson("/v1/human/devices/registration/options", input);
}

export function verifyDeviceRegistration(
  challengeId: string,
  deviceSignature: string,
  response: AuthenticationResponseJSON,
): Promise<{ device_id: string; device_trusted: true; ok: true }> {
  return postJson("/v1/human/devices/registration/verify", {
    challenge_id: challengeId,
    device_signature: deviceSignature,
    response,
  });
}

export async function getHumanManagement(): Promise<HumanManagement> {
  const value = asRecord(await fetchJson("/v1/human/management"));
  const credentials = Array.isArray(value.credentials) ? value.credentials : [];
  const devices = Array.isArray(value.devices) ? value.devices : [];
  const requesters = Array.isArray(value.requesters) ? value.requesters : [];
  const sshAuthorizations = Array.isArray(value.ssh_authorizations)
    ? value.ssh_authorizations
    : [];
  return {
    credentials: credentials.map((entry) => {
      const item = asRecord(entry);
      const lastUsedAt = readString(item, "last_used_at");
      return {
        backedUp: readBoolean(item, "backed_up") ?? false,
        createdAt: readRequiredString(item, "created_at"),
        current: readBoolean(item, "current") ?? false,
        deviceType: readRequiredString(item, "device_type"),
        id: readRequiredString(item, "id"),
        label: readRequiredString(item, "label"),
        ...(lastUsedAt ? { lastUsedAt } : {}),
      };
    }),
    devices: devices.map((entry) => {
      const item = asRecord(entry);
      return {
        createdAt: readRequiredString(item, "created_at"),
        current: readBoolean(item, "current") ?? false,
        id: readRequiredString(item, "id"),
        label: readRequiredString(item, "label"),
        lastSeenAt: readRequiredString(item, "last_seen_at"),
        platform: readRequiredString(item, "platform"),
        pushEnabled: readBoolean(item, "push_enabled") ?? false,
      };
    }),
    requesters: requesters.map((entry) => {
      const item = asRecord(entry);
      return {
        createdAt: readRequiredString(item, "created_at"),
        deviceId: readRequiredString(item, "device_id"),
        displayName: readRequiredString(item, "display_name"),
        publicKeyFingerprint: readRequiredString(
          item,
          "public_key_fingerprint",
        ),
      };
    }),
    sshAuthorizations: sshAuthorizations.map((entry) => {
      const item = asRecord(entry);
      const scopeKind = readRequiredString(item, "scope_kind");
      if (scopeKind !== "application" && scopeKind !== "terminal-session") {
        throw new Error("The server returned an unknown SSH authorization scope.");
      }
      const duration = readRequiredString(item, "duration");
      if (
        duration !== "until-lock" &&
        duration !== "until-agent-quits" &&
        duration !== "4-hours" &&
        duration !== "12-hours" &&
        duration !== "24-hours"
      ) {
        throw new Error("The server returned an unknown SSH authorization duration.");
      }
      const expiresAt = readString(item, "expires_at");
      return {
        application: readRequiredString(item, "client_application"),
        createdAt: readRequiredString(item, "created_at"),
        duration,
        ...(expiresAt ? { expiresAt } : {}),
        fingerprint: readRequiredString(item, "fingerprint"),
        id: readRequiredString(item, "id"),
        itemId: readRequiredString(item, "item_id"),
        itemTitle: readRequiredString(item, "item_title"),
        itemVersion: readRequiredNumber(item, "item_version"),
        requesterDeviceId: readRequiredString(item, "requester_device_id"),
        scopeKind,
      };
    }),
  };
}

export function getPushConfig(): Promise<{
  configured: boolean;
  enabled: boolean;
  public_key?: string;
}> {
  return fetchJson("/v1/human/push/config");
}

export function putPushSubscription(subscription: PushSubscriptionJSON): Promise<{ ok: true }> {
  return fetchJson("/v1/human/push/subscription", {
    body: JSON.stringify(subscription),
    headers: { "content-type": "application/json", "x-csrf-token": readCsrfToken() },
    method: "PUT",
  });
}

export function deletePushSubscription(): Promise<{ ok: true }> {
  return fetchJson("/v1/human/push/subscription", {
    body: "{}",
    headers: { "content-type": "application/json", "x-csrf-token": readCsrfToken() },
    method: "DELETE",
  });
}

export async function getRequesterEnrollments(): Promise<{
  enrollments: RequesterEnrollment[];
}> {
  const response = await fetchJson<{
    enrollments: Array<{
      created_at: string;
      device_id: string;
      display_name: string;
      expires_at: string;
      id: string;
      public_key_fingerprint: string;
      status: string;
    }>;
  }>("/v1/human/requester-enrollments");

  return {
    enrollments: response.enrollments.map((enrollment) => ({
      createdAt: enrollment.created_at,
      deviceId: enrollment.device_id,
      displayName: enrollment.display_name,
      expiresAt: enrollment.expires_at,
      id: enrollment.id,
      publicKeyFingerprint: enrollment.public_key_fingerprint,
      status: enrollment.status,
    })),
  };
}

export function beginRequesterEnrollmentDecision(
  enrollmentId: string,
  decision: ApprovalDecision,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(
    `/v1/human/requester-enrollments/${encodeURIComponent(enrollmentId)}/options`,
    { decision },
  );
}

export function verifyRequesterEnrollmentDecision(
  enrollmentId: string,
  challengeId: string,
  decision: ApprovalDecision,
  response: AuthenticationResponseJSON,
): Promise<VerifyDecisionResponse> {
  return postJson(
    `/v1/human/requester-enrollments/${encodeURIComponent(enrollmentId)}/verify`,
    { challenge_id: challengeId, decision, response },
  );
}

export function beginRequesterRevoke(
  deviceId: string,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(
    `/v1/human/requesters/${encodeURIComponent(deviceId)}/revoke/options`,
    {},
  );
}

export function beginRequesterRename(
  deviceId: string,
  displayName: string,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(
    `/v1/human/requesters/${encodeURIComponent(deviceId)}/rename/options`,
    { display_name: displayName },
  );
}

export function verifyRequesterRename(
  deviceId: string,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<{ display_name: string; ok: true }> {
  return postJson(
    `/v1/human/requesters/${encodeURIComponent(deviceId)}/rename/verify`,
    { challenge_id: challengeId, response },
  );
}

export function verifyRequesterRevoke(
  deviceId: string,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<{ ok: true; status: "revoked" }> {
  return postJson(
    `/v1/human/requesters/${encodeURIComponent(deviceId)}/revoke/verify`,
    { challenge_id: challengeId, response },
  );
}

export async function getRequests(
  cursor?: string,
  pendingOnly = false,
): Promise<PaginatedRequestListResponse> {
  const search = new URLSearchParams();
  if (cursor) search.set("cursor", cursor);
  if (pendingOnly) search.set("pending", "true");
  const response = await fetchJson<{ next_cursor?: unknown; requests: unknown[] }>(
    `/v1/human/requests${search.size > 0 ? `?${search.toString()}` : ""}`,
  );
  return {
    ...(typeof response.next_cursor === "string"
      ? { nextCursor: response.next_cursor }
      : {}),
    requests: response.requests.map(normalizeRequestSummary),
  };
}

export async function getRequest(requestId: string): Promise<RequestDetail> {
  const response = await fetchJson<unknown>(
    `/v1/human/requests/${encodeURIComponent(requestId)}`,
  );
  return normalizeRequestDetail(response);
}

export function beginApprovalDecision(
  requestId: string,
  decision: ApprovalDecision,
  authorizationDuration?: SshAuthorizationDuration,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(`/v1/human/approvals/${encodeURIComponent(requestId)}/options`, {
    ...(authorizationDuration
      ? { authorization_duration: authorizationDuration }
      : {}),
    decision,
  });
}

export function verifyApprovalDecision(
  requestId: string,
  challengeId: string,
  decision: ApprovalDecision,
  response: AuthenticationResponseJSON,
  authorizationDuration?: SshAuthorizationDuration,
): Promise<VerifyDecisionResponse> {
  return postJson(`/v1/human/approvals/${encodeURIComponent(requestId)}/verify`, {
    ...(authorizationDuration
      ? { authorization_duration: authorizationDuration }
      : {}),
    challenge_id: challengeId,
    decision,
    response,
  });
}

export function lockGateway(): Promise<{ locked: true; ok: true }> {
  return postJson("/v1/human/lock", {});
}

export function beginGatewayUnlock(): Promise<
  WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>
> {
  return postJson("/v1/human/unlock/options", {});
}

export function verifyGatewayUnlock(
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<{ locked: false; ok: true }> {
  return postJson("/v1/human/unlock/verify", {
    challenge_id: challengeId,
    response,
  });
}

export function revokeSshAuthorization(
  grantId: string,
): Promise<{ ok: true; status: "revoked" }> {
  return fetchJson(
    `/v1/human/ssh-authorizations/${encodeURIComponent(grantId)}`,
    {
      body: "{}",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": readCsrfToken(),
      },
      method: "DELETE",
    },
  );
}

export function beginDeviceRevoke(
  deviceId: string,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(`/v1/human/devices/${encodeURIComponent(deviceId)}/revoke/options`, {});
}

export function verifyDeviceRevoke(
  deviceId: string,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<{ ok: true; status: "revoked" }> {
  return postJson(`/v1/human/devices/${encodeURIComponent(deviceId)}/revoke/verify`, {
    challenge_id: challengeId,
    response,
  });
}

export function beginCredentialRegistration(
  label: string,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson("/v1/human/credentials/registration/options", { label });
}

export function authorizeCredentialRegistration(
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialCreationOptionsJSON>> {
  return postJson("/v1/human/credentials/registration/authorize", {
    challenge_id: challengeId,
    response,
  });
}

export function verifyCredentialRegistration(
  challengeId: string,
  response: RegistrationResponseJSON,
): Promise<{ credential_id: string; ok: true }> {
  return postJson("/v1/human/credentials/registration/verify", {
    challenge_id: challengeId,
    response,
  });
}

export function beginCredentialRevoke(
  credentialId: string,
): Promise<WebAuthnOptionsEnvelope<PublicKeyCredentialRequestOptionsJSON>> {
  return postJson(
    `/v1/human/credentials/${encodeURIComponent(credentialId)}/revoke/options`,
    {},
  );
}

export function verifyCredentialRevoke(
  credentialId: string,
  challengeId: string,
  response: AuthenticationResponseJSON,
): Promise<{ ok: true; status: "revoked" }> {
  return postJson(
    `/v1/human/credentials/${encodeURIComponent(credentialId)}/revoke/verify`,
    { challenge_id: challengeId, response },
  );
}

export function getSystemHealth(): Promise<SystemHealthResponse> {
  return fetchJson("/api/health");
}

async function postJson<TResponse>(
  path: string,
  body: object,
  includeCsrf = true,
): Promise<TResponse> {
  return fetchJson(path, {
    body: JSON.stringify(body),
    headers: {
      "content-type": "application/json",
      ...(includeCsrf ? { "x-csrf-token": readCsrfToken() } : {}),
    },
    method: "POST",
  });
}

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    cache: "no-store",
    credentials: "same-origin",
    headers: {
      accept: "application/json",
      ...init?.headers,
    },
  });

  const body = (await response.json().catch(() => undefined)) as unknown;
  persistCsrfToken(response, body);

  if (!response.ok) {
    const errorBody = isRecord(body) ? body : undefined;
    const code = readString(errorBody, "code", "error_code");
    const requestId = readString(errorBody, "request_id", "requestId");
    const message =
      readString(errorBody, "message") ??
      defaultErrorMessage(response.status, code);

    if (response.status === 401 || code === "session_expired" || code === "csrf_invalid") {
      clearCsrfToken();
    }

    throw new ApiError(message, response.status, code, requestId);
  }

  return body as T;
}

function persistCsrfToken(response: Response, body: unknown): void {
  const bodyRecord = isRecord(body) ? body : undefined;
  const session = bodyRecord && isRecord(bodyRecord.session) ? bodyRecord.session : undefined;
  const token =
    response.headers.get("x-csrf-token") ??
    readString(bodyRecord, "csrf_token", "csrfToken") ??
    readString(session, "csrf_token", "csrfToken");

  if (!token) return;

  try {
    sessionStorage.setItem(CSRF_STORAGE_KEY, token);
  } catch {
    // A blocked sessionStorage should make the next mutation fail closed server-side.
  }
}

function readCsrfToken(): string {
  try {
    return sessionStorage.getItem(CSRF_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

function clearCsrfToken(): void {
  try {
    sessionStorage.removeItem(CSRF_STORAGE_KEY);
  } catch {
    // Nothing else to clear.
  }
}

function normalizeRequestSummary(value: unknown): RequestSummary {
  const record = asRecord(value);
  const client = asRecord(record.client);
  const source = readRequiredString(client, "source");
  if (
    source !== "process-ancestry" &&
    source !== "unavailable"
  ) {
    throw new Error("The server returned an unknown client observation source.");
  }
  return {
    action: readRequiredString(record, "action") as ApprovalAction,
    ...(isRecord(record.authorization_session)
      ? {
          authorizationSession: {
            scopeKind: readAuthorizationScopeKind(
              record.authorization_session,
            ),
          },
        }
      : {}),
    client: {
      application: readRequiredString(client, "application"),
      source,
    },
    createdAt: readRequiredString(record, "created_at", "createdAt"),
    expiresAt: readRequiredString(record, "expires_at", "expiresAt"),
    requestId: readRequiredString(record, "request_id", "requestId"),
    requesterName: readRequiredString(record, "requester_name", "requesterName"),
    status: readRequiredString(record, "status") as ApprovalStatus,
    targetLabel: readRequiredString(record, "target_label", "targetLabel"),
    verifiedVersion: readRequiredNumber(record, "verified_version", "verifiedVersion"),
  };
}

function readAuthorizationScopeKind(
  value: Record<string, unknown>,
): "application" | "terminal-session" {
  const kind = readRequiredString(value, "scope_kind", "scopeKind");
  if (kind !== "application" && kind !== "terminal-session") {
    throw new Error("The server returned an unknown SSH authorization scope.");
  }
  return kind;
}

function normalizeRequestDetail(value: unknown): RequestDetail {
  const record = asRecord(value);
  const factsValue = record.verified_facts ?? record.verifiedFacts;
  const facts = Array.isArray(factsValue) ? factsValue : [];

  return {
    ...normalizeRequestSummary(record),
    verifiedFacts: facts.map((fact) => {
      const factRecord = asRecord(fact);
      return {
        label: readRequiredString(factRecord, "label"),
        value: readRequiredString(factRecord, "value"),
      };
    }),
  };
}

function defaultErrorMessage(status: number, code?: string): string {
  if (code === "bootstrap_unavailable") {
    return "The one-time setup code is invalid, unavailable, or already used.";
  }
  if (code === "requester_revoked") {
    return "This requester was previously revoked. Delete its local may credential and enroll a new requester identity.";
  }
  if (code === "gateway_locked") {
    return "The gateway is in Lock mode. This request was rejected without notifying an approver.";
  }
  if (status === 401) return "Your session has expired. Sign in again with a passkey.";
  if (status === 403) return "This action failed its security check. Reload the page and try again.";
  if (status === 404) return "The request does not exist or has already been removed.";
  if (status === 409 || status === 410) return "The request has expired or was handled on another device.";
  if (status === 429) return "Too many actions. Try again shortly.";
  return code ? `Request failed (${code})` : `Request failed (HTTP ${status})`;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new Error("The server returned unrecognized data.");
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readRequiredString(
  record: Record<string, unknown>,
  ...keys: string[]
): string {
  const value = readString(record, ...keys);
  if (value === undefined) throw new Error(`Server response is missing field: ${keys[0]}`);
  return value;
}

function readRequiredNumber(
  record: Record<string, unknown>,
  ...keys: string[]
): number {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
  }
  throw new Error(`Server response is missing numeric field: ${keys[0]}`);
}

function readString(
  record: Record<string, unknown> | undefined,
  ...keys: string[]
): string | undefined {
  if (!record) return undefined;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string") return value;
  }
  return undefined;
}

function readBoolean(
  record: Record<string, unknown> | undefined,
  ...keys: string[]
): boolean | undefined {
  if (!record) return undefined;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "boolean") return value;
  }
  return undefined;
}
