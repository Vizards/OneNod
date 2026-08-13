import type { AuthenticatorTransportFuture } from "@simplewebauthn/server";
import {
  APPLICATION_ATTESTATION_HEADER,
  decodeBase64Url,
  encodeBase64Url,
  sha256Base64Url,
  type ApplicationAuthorizationScopeRequest,
  type ApplicationIdentityRequest,
  type ApprovalDecision,
  type ClientObservationRequest,
  type SshAuthorizationDuration,
} from "@onenod/protocol";

import type {
  ApplicationIdentityColumns,
  RateWindow,
  ValidatedClientObservation,
} from "./approval-types.js";
import { ExecutorTransportError } from "./executor-transport.js";
import {
  type RequesterIdentity,
  verifyApplicationAttestation,
} from "./requester-auth.js";

const MAX_JSON_BYTES = 64 * 1024;
const MAX_JSON_RESPONSE_BYTES = 256 * 1024;

export class GatewayHttpError extends Error {
  override readonly name = "GatewayHttpError";

  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(code);
  }
}

export async function readDecisionBody(
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
            safeAuthorizationDuration(body.authorization_duration),
        }),
    decision: safeDecision(body.decision),
  };
}

export async function readDecisionVerifyBody(
  request: Request,
  options: { allowLegacyAuthorizationDuration?: boolean } = {},
): Promise<{
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
  const legacyDurationPresent = body.authorization_duration !== undefined;
  assertExactKeys(body, [
    ...(legacyDurationPresent && options?.allowLegacyAuthorizationDuration
      ? ["authorization_duration"]
      : []),
    "challenge_id",
    "decision",
    "response",
  ]);
  return {
    ...(legacyDurationPresent
      ? {
          authorization_duration:
            safeAuthorizationDuration(body.authorization_duration),
        }
      : {}),
    challenge_id: safeIdentifier(body.challenge_id, "challenge_id"),
    decision: safeDecision(body.decision),
    response: record(body.response),
  };
}

export function assertLegacyAuthorizationDurationMatches(
  provided: SshAuthorizationDuration | undefined,
  stored: SshAuthorizationDuration | undefined,
): void {
  if (provided !== undefined && provided !== stored) {
    throw new GatewayHttpError("authorization_duration_mismatch", 400);
  }
}

export async function readChallengeVerifyBody(request: Request): Promise<{
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

export async function readJsonObject<T extends object = Record<string, unknown>>(
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

export function safeDecision(value: unknown): ApprovalDecision {
  if (value !== "approve" && value !== "reject") {
    throw new GatewayHttpError("decision_invalid", 400);
  }
  return value;
}

export function safeAuthorizationDuration(
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

export function safeClientObservation(value: unknown): ClientObservationRequest {
  const input = record(value);
  assertExactKeys(input, [
    "application",
    ...(input.identity === undefined ? [] : ["identity"]),
    "source",
  ]);
  if (
    input.source !== "process-ancestry" &&
    input.source !== "unavailable"
  ) {
    throw new GatewayHttpError("client_observation_invalid", 400);
  }
  return {
    application: safeObservationText(input.application, 512),
    identity:
      input.identity === undefined
        ? { assurance: "unverified", platform: "unsupported" }
        : safeApplicationIdentity(input.identity),
    source: input.source,
  };
}

export function safeApplicationIdentity(value: unknown): ApplicationIdentityRequest {
  const input = record(value);
  if (input.assurance === "unverified") {
    assertExactKeys(input, ["assurance", "platform"]);
    if (input.platform !== "macos" && input.platform !== "unsupported") {
      throw new GatewayHttpError("application_identity_invalid", 400);
    }
    return { assurance: "unverified", platform: input.platform };
  }
  if (input.assurance !== "verified-code-signature") {
    throw new GatewayHttpError("application_identity_invalid", 400);
  }
  assertExactKeys(input, [
    "assurance",
    "platform",
    "principal_id",
    "principal_scheme",
    ...(input.signer_name === undefined ? [] : ["signer_name"]),
    "signing_identifier",
    ...(input.team_identifier === undefined ? [] : ["team_identifier"]),
  ]);
  if (
    input.platform !== "macos" ||
    input.principal_scheme !== "macos-designated-requirement-v1"
  ) {
    throw new GatewayHttpError("application_identity_invalid", 400);
  }
  const principalId = safeBase64Url(input.principal_id, 32, "principal_id");
  if (decodeBase64Url(principalId).byteLength !== 32) {
    throw new GatewayHttpError("application_identity_invalid", 400);
  }
  return {
    assurance: "verified-code-signature",
    platform: "macos",
    principal_id: principalId,
    principal_scheme: "macos-designated-requirement-v1",
    ...(input.signer_name === undefined
      ? {}
      : { signer_name: safeObservationText(input.signer_name, 512) }),
    signing_identifier: safeObservationText(input.signing_identifier, 1024),
    ...(input.team_identifier === undefined
      ? {}
      : { team_identifier: safeObservationText(input.team_identifier, 128) }),
  };
}

export async function verifiedClientObservation(
  value: unknown,
  request: Request,
  requester: RequesterIdentity,
): Promise<ValidatedClientObservation> {
  const client = safeClientObservation(value) as ValidatedClientObservation;
  const attestation = request.headers.get(APPLICATION_ATTESTATION_HEADER);
  if (client.identity.assurance === "unverified") {
    if (attestation !== null) {
      throw new GatewayHttpError("application_attestation_invalid", 401);
    }
    return client;
  }
  if (
    client.source !== "process-ancestry" ||
    !(await verifyApplicationAttestation({
      identity: client.identity,
      request,
      requester,
    }))
  ) {
    throw new GatewayHttpError("application_attestation_invalid", 401);
  }
  return client;
}

export function applicationIdentityColumns(
  identity: ApplicationIdentityRequest,
): ApplicationIdentityColumns {
  if (identity.assurance === "unverified") {
    return {
      application_assurance: "unverified",
      application_principal_id: null,
      application_principal_scheme: null,
      application_signer_name: null,
      application_signing_identifier: null,
      application_team_identifier: null,
    };
  }
  return {
    application_assurance: identity.assurance,
    application_principal_id: identity.principal_id,
    application_principal_scheme: identity.principal_scheme,
    application_signer_name: identity.signer_name ?? null,
    application_signing_identifier: identity.signing_identifier,
    application_team_identifier: identity.team_identifier ?? null,
  };
}

export function safeApplicationAuthorizationScope(
  value: unknown,
): ApplicationAuthorizationScopeRequest {
  const input = record(value);
  assertExactKeys(input, ["scope_id", "scope_kind"]);
  if (input.scope_kind !== "application") {
    throw new GatewayHttpError("authorization_scope_invalid", 400);
  }
  const scopeId = safeBase64Url(input.scope_id, 32, "scope_id");
  if (decodeBase64Url(scopeId).byteLength !== 32) {
    throw new GatewayHttpError("authorization_scope_invalid", 400);
  }
  return { scope_id: scopeId, scope_kind: "application" };
}

export function safeObservationText(value: unknown, maximumLength: number): string {
  const text = safeText(value, maximumLength).trim();
  if (!text) throw new GatewayHttpError("text_invalid", 400);
  return text;
}

export function assertExactKeys(
  value: object,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new GatewayHttpError("request_schema_invalid", 400);
  }
}

export function safeDeviceId(value: unknown): string {
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

export function safeHumanDeviceInput(value: unknown): {
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

export function safePlatform(value: unknown): string {
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

export function safeDevicePublicKey(value: unknown): string {
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

export function isBase64UrlBytes(value: unknown, expectedBytes: number): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    return decodeBase64Url(value).byteLength === expectedBytes;
  } catch {
    return false;
  }
}

export function deviceProofMessage(
  purpose: string,
  challengeId: string,
  challenge: string,
  deviceId: string,
): string {
  return ["1p-human-device-v1", purpose, challengeId, challenge, deviceId].join("\n");
}

export function safeIdentifier(value: unknown, name: string): string {
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

export function safePositiveInteger(value: unknown, name: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new GatewayHttpError(`${name}_invalid`, 400);
  }
  return value as number;
}

export function safeText(
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

export function safeBase64Url(
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

export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new GatewayHttpError("object_invalid", 400);
  }
  return value as Record<string, unknown>;
}

export function parseJsonObject(value: string | null): Record<string, unknown> {
  if (!value) return {};
  try {
    return record(JSON.parse(value));
  } catch {
    throw new GatewayHttpError("stored_state_invalid", 500);
  }
}

export function parseTransports(value: string): AuthenticatorTransportFuture[] {
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

export function randomToken(bytes: number): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function bootstrapRequestIdForToken(token: string): Promise<string> {
  return (await sha256Base64Url(token)).slice(0, 22);
}

export function readCookie(header: string | null, name: string): string | undefined {
  if (!header) return undefined;
  for (const segment of header.split(";")) {
    const [rawName, ...rawValue] = segment.trim().split("=");
    if (rawName === name) return rawValue.join("=");
  }
  return undefined;
}

export function constantTimeStringEquals(
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

export function iso(value: number): string {
  return new Date(value).toISOString();
}

export function advanceRateWindow(
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

export function incrementCount(counts: Map<string, number>, key: string): void {
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

export function decrementCount(counts: Map<string, number>, key: string): void {
  const remaining = (counts.get(key) ?? 0) - 1;
  if (remaining <= 0) {
    counts.delete(key);
    return;
  }
  counts.set(key, remaining);
}

export function json(
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

export function errorResponse(code: string, status: number): Response {
  return json(
    { code, error: code, ok: false },
    status,
    { "x-onenod-error-code": code },
  );
}

export function safeErrorName(error: unknown): string {
  return error instanceof Error &&
    /^[A-Za-z][A-Za-z0-9]{0,39}$/u.test(error.name)
    ? error.name
    : "UnknownError";
}

export function isUncertainWriteFailure(code: string): boolean {
  return (
    code === "onepassword_write_outcome_unknown" ||
    code === "executor_timeout" ||
    code === "executor_unavailable" ||
    code === "executor_destroy_failed"
  );
}

export function safeSshSignatureAlgorithm(value: string) {
  if (
    value === "ssh-ed25519" ||
    value === "rsa-sha2-256" ||
    value === "rsa-sha2-512"
  ) {
    return value;
  }
  throw new GatewayHttpError("ssh_sign_request_invalid", 400);
}

export function classifyStorageError(error: unknown): string {
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

export function sanitizeExecutorEnvelope<T>(sanitize: () => T): T {
  try {
    return sanitize();
  } catch (error) {
    if (error instanceof ExecutorTransportError) {
      throw new GatewayHttpError("executor_response_invalid", 502);
    }
    throw error;
  }
}

export function hasForbiddenControl(
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
