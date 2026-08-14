import type {
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/browser";
import type {
  RequestDetail,
  SshAuthorizationDuration,
} from "@onenod/protocol";

import { DEFAULT_PASSKEY_LABEL } from "../passkey-identity";

const CSRF_STORAGE_KEY = "onepassword-remote.csrf";

export type {
  ApprovalDecision, AuthorizationSummary, DeviceRegistrationInput, GatewaySystemHealthResponse,
  HumanCredentialSummary, HumanDeviceSummary, HumanManagement, HumanState,
  PaginatedRequestListResponse, RequesterEnrollment, RequesterSummary,
  SecretAuthorizationSummary, SshAuthorizationSummary, VerifyDecisionResponse,
} from "./api-types";
import type {
  ApprovalDecision,
  AuthorizationSummary,
  DeviceRegistrationInput,
  GatewaySystemHealthResponse,
  HumanManagement,
  HumanState,
  PaginatedRequestListResponse,
  RequesterEnrollment,
  VerifyDecisionResponse,
  WebAuthnOptionsEnvelope,
} from "./api-types";
import {
  normalizeHumanManagement,
  normalizeHumanState,
  normalizeRequestDetail,
  normalizeRequestSummary,
} from "./api-normalizers";

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
  return normalizeHumanState(await fetchJson<unknown>("/v1/human/state"));
}

export function beginBootstrapRegistration(
  label = DEFAULT_PASSKEY_LABEL,
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
  return normalizeHumanManagement(await fetchJson("/v1/human/management"));
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
  serverTime: string;
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
    server_time: string;
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
    serverTime: response.server_time,
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
  const response = await fetchJson<{
    next_cursor?: unknown;
    requests: unknown[];
    server_time: string;
  }>(
    `/v1/human/requests${search.size > 0 ? `?${search.toString()}` : ""}`,
  );
  return {
    ...(typeof response.next_cursor === "string"
      ? { nextCursor: response.next_cursor }
      : {}),
    requests: response.requests.map(normalizeRequestSummary),
    serverTime: response.server_time,
  };
}

export async function getAuthorizationSummary(): Promise<AuthorizationSummary> {
  const response = await fetchJson<{
    active_count: number;
    next_expiry_at?: string;
    server_time: string;
  }>("/v1/human/authorizations/summary");
  return {
    activeCount: response.active_count,
    ...(response.next_expiry_at
      ? { nextExpiryAt: response.next_expiry_at }
      : {}),
    serverTime: response.server_time,
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
): Promise<VerifyDecisionResponse> {
  return postJson(`/v1/human/approvals/${encodeURIComponent(requestId)}/verify`, {
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

export function revokeSecretAuthorization(
  grantId: string,
): Promise<{ ok: true; status: "revoked" }> {
  return fetchJson(
    `/v1/human/secret-authorizations/${encodeURIComponent(grantId)}`,
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

export function getSystemHealth(): Promise<GatewaySystemHealthResponse> {
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
    const code = readString(errorBody, "code");
    const requestId = readString(errorBody, "request_id");
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
  const token =
    response.headers.get("x-csrf-token") ??
    readString(bodyRecord, "csrf_token");

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
  if (code === "onepassword_rate_limited") {
    return "The 1Password Service Account rate limit has been reached. Try again after its quota resets.";
  }
  if (status === 401) return "Your session has expired. Sign in again with a passkey.";
  if (status === 403) return "This action failed its security check. Reload the page and try again.";
  if (status === 404) return "The request does not exist or has already been removed.";
  if (status === 409 || status === 410) return "The request has expired or was handled on another device.";
  if (status === 429) return "Too many actions. Try again shortly.";
  return code ? `Request failed (${code})` : `Request failed (HTTP ${status})`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(
  record: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  if (!record) return undefined;
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}
