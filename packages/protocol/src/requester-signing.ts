import { canonicalizeJson } from "./canonical-json.js";
import { decodeBase64Url, sha256Base64Url } from "./encoding.js";

export const REQUESTER_SIGNATURE_PROTOCOL = "onenod-request-v1";
export const APPLICATION_ATTESTATION_PROTOCOL =
  "onenod-application-attestation-v1";
export const APPLICATION_ATTESTATION_HEADER =
  "x-onenod-application-attestation";

export const REQUESTER_HEADER_NAMES = {
  deviceId: "x-onenod-device-id",
  nonce: "x-onenod-request-nonce",
  signature: "x-onenod-request-signature",
  timestamp: "x-onenod-request-timestamp",
} as const;

export interface RequesterCanonicalStringFields {
  audience: string;
  body_sha256: string;
  device_id: string;
  method: string;
  nonce: string;
  path: string;
  unix_seconds: number;
}

export interface RequesterSigningInput
  extends Omit<RequesterCanonicalStringFields, "body_sha256"> {
  body: unknown;
}

export interface RequesterSigningMaterial {
  body_canonical_json: string;
  body_sha256: string;
  canonical_string: string;
}

export interface ApplicationAttestationFields {
  principal_id: string;
  principal_scheme: string;
  requester_canonical_string: string;
}

function assertCanonicalLine(name: string, value: string): void {
  if (value.length === 0 || value.includes("\n") || value.includes("\r")) {
    throw new TypeError(`${name} must be a non-empty canonical line.`);
  }
}

export function formatRequesterCanonicalString(
  fields: RequesterCanonicalStringFields,
): string {
  assertCanonicalLine("audience", fields.audience);
  assertCanonicalLine("body_sha256", fields.body_sha256);
  assertCanonicalLine("device_id", fields.device_id);
  assertCanonicalLine("nonce", fields.nonce);

  if (!/^[A-Z]+$/.test(fields.method)) {
    throw new TypeError("method must contain only uppercase ASCII letters.");
  }

  if (
    !fields.path.startsWith("/") ||
    fields.path.includes("?") ||
    fields.path.includes("#") ||
    fields.path.includes("\n") ||
    fields.path.includes("\r")
  ) {
    throw new TypeError("path must be an absolute path without query or fragment.");
  }

  if (!Number.isSafeInteger(fields.unix_seconds) || fields.unix_seconds < 0) {
    throw new TypeError("unix_seconds must be a non-negative safe integer.");
  }

  return [
    REQUESTER_SIGNATURE_PROTOCOL,
    fields.audience,
    fields.method,
    fields.path,
    fields.body_sha256,
    fields.device_id,
    String(fields.unix_seconds),
    fields.nonce,
  ].join("\n");
}

export function formatApplicationAttestationString(
  fields: ApplicationAttestationFields,
): string {
  assertCanonicalLine("principal_id", fields.principal_id);
  assertCanonicalLine("principal_scheme", fields.principal_scheme);
  if (
    !fields.requester_canonical_string.startsWith(
      `${REQUESTER_SIGNATURE_PROTOCOL}\n`,
    ) ||
    fields.requester_canonical_string.includes("\r") ||
    fields.requester_canonical_string.includes("\0")
  ) {
    throw new TypeError("requester_canonical_string is invalid.");
  }
  return [
    APPLICATION_ATTESTATION_PROTOCOL,
    fields.requester_canonical_string,
    fields.principal_scheme,
    fields.principal_id,
  ].join("\n");
}

export async function canonicalJsonSha256Base64Url(value: unknown): Promise<string> {
  return sha256Base64Url(canonicalizeJson(value));
}

export async function requesterPublicKeyFingerprint(
  publicKey: string,
): Promise<string> {
  const bytes = decodeBase64Url(publicKey);
  if (bytes.byteLength !== 32) {
    throw new TypeError("Requester public key must contain 32 bytes.");
  }
  return sha256Base64Url(bytes);
}

export async function buildRequesterCanonicalString(
  input: RequesterSigningInput,
): Promise<RequesterSigningMaterial> {
  const bodyCanonicalJson = canonicalizeJson(input.body);
  const bodySha256 = await sha256Base64Url(bodyCanonicalJson);
  const canonicalString = formatRequesterCanonicalString({
    audience: input.audience,
    body_sha256: bodySha256,
    device_id: input.device_id,
    method: input.method,
    nonce: input.nonce,
    path: input.path,
    unix_seconds: input.unix_seconds,
  });

  return {
    body_canonical_json: bodyCanonicalJson,
    body_sha256: bodySha256,
    canonical_string: canonicalString,
  };
}
