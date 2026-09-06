import {
  canonicalizeJson,
  decodeBase64Url,
  encodeBase64Url,
  type BeholderAuthorizationRequest,
} from "@onenod/protocol";

import { ownedBytes } from "../shared/owned-bytes.js";

const AUTHORIZATION_MODE = "dogfood-v1";
const AUTHORIZATION_PROTOCOL = "onenod-beholder-authorization-v1";
const MAX_AUTHORIZATION_LIFETIME_SECONDS = 30;
const MAX_FUTURE_CLOCK_SKEW_SECONDS = 10;

interface AuthorityKey {
  keyId: string;
  publicKey: Uint8Array<ArrayBuffer>;
  requesterDeviceId: string;
}

export interface BeholderAuthorizationEvaluation {
  accepted?: {
    evidenceId: string;
    keyId: string;
    operationTargetSha256: string;
  };
  required: boolean;
}

/** Return the requester-signed semantic body and the untrusted Core envelope. */
export function separateBeholderAuthorization<T extends Record<string, unknown>>(
  body: T,
): {
  authorization: unknown;
  semanticBody: Omit<T, "beholder_authorization">;
} {
  const { beholder_authorization: authorization, ...semanticBody } = body;
  return { authorization, semanticBody };
}

/**
 * Verify a root-Core authorization without making failure an HTTP error.
 * Invalid configuration or evidence deliberately means "human required".
 */
export async function evaluateBeholderAuthorization(input: {
  authorization: unknown;
  authorityKeysJson?: string;
  authorityMode?: string;
  nowSeconds?: number;
  requesterDeviceId: string;
  semanticBody: unknown;
}): Promise<BeholderAuthorizationEvaluation> {
  const mode = input.authorityMode?.trim() ?? "";
  if (mode === "" || mode === "human-only") return { required: false };
  if (mode !== AUTHORIZATION_MODE) return { required: true };

  const keys = await parseAuthorityKeys(input.authorityKeysJson);
  if (!keys) return { required: true };
  const authority = keys.get(input.requesterDeviceId);
  if (!authority) return { required: false };

  const result: BeholderAuthorizationEvaluation = { required: true };
  const authorization = parseAuthorization(input.authorization);
  if (!authorization || authorization.requester_device_id !== input.requesterDeviceId) {
    return result;
  }
  if (authorization.key_id !== authority.keyId) return result;

  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1_000);
  if (
    authorization.issued_at > nowSeconds + MAX_FUTURE_CLOCK_SKEW_SECONDS ||
    authorization.expires_at <= nowSeconds ||
    authorization.expires_at <= authorization.issued_at ||
    authorization.expires_at - authorization.issued_at >
      MAX_AUTHORIZATION_LIFETIME_SECONDS
  ) {
    return result;
  }

  const operationTargetSha256 = await canonicalSha256Hex(input.semanticBody);
  if (authorization.operation_target_sha256 !== operationTargetSha256) {
    return result;
  }

  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = ownedBytes(decodeBase64Url(authorization.signature));
  } catch {
    return result;
  }
  if (signature.byteLength !== 64) return result;

  let verified = false;
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      authority.publicKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    verified = await crypto.subtle.verify(
      "Ed25519",
      key,
      signature,
      new TextEncoder().encode(beholderAuthorizationMaterial(authorization)),
    );
  } catch {
    verified = false;
  }
  if (!verified) return result;

  return {
    required: true,
    accepted: {
      evidenceId: authorization.evidence_id,
      keyId: authorization.key_id,
      operationTargetSha256,
    },
  };
}

export function beholderAuthorizationMaterial(
  authorization: Omit<BeholderAuthorizationRequest, "signature">,
): string {
  return [
    AUTHORIZATION_PROTOCOL,
    authorization.key_id,
    authorization.evidence_id,
    authorization.requester_device_id,
    authorization.operation_target_sha256,
    String(authorization.issued_at),
    String(authorization.expires_at),
    authorization.decision,
  ].join("\n");
}

async function parseAuthorityKeys(
  raw: string | undefined,
): Promise<Map<string, AuthorityKey> | undefined> {
  if (!raw || raw.length > 64 * 1_024) return undefined;
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!Array.isArray(decoded) || decoded.length === 0 || decoded.length > 32) {
    return undefined;
  }
  const result = new Map<string, AuthorityKey>();
  for (const candidate of decoded) {
    if (!isExactRecord(candidate, ["public_key", "requester_device_id"])) {
      return undefined;
    }
    const requesterDeviceId = candidate.requester_device_id;
    const publicKeyText = candidate.public_key;
    if (
      typeof requesterDeviceId !== "string" ||
      !safeToken(requesterDeviceId, 8, 128) ||
      typeof publicKeyText !== "string" ||
      result.has(requesterDeviceId)
    ) {
      return undefined;
    }
    let publicKey: Uint8Array<ArrayBuffer>;
    try {
      publicKey = ownedBytes(decodeBase64Url(publicKeyText));
    } catch {
      return undefined;
    }
    if (publicKey.byteLength !== 32 || encodeBase64Url(publicKey) !== publicKeyText) {
      return undefined;
    }
    const keyId = encodeBase64Url(
      new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)),
    );
    result.set(requesterDeviceId, { keyId, publicKey, requesterDeviceId });
  }
  return result;
}

function parseAuthorization(value: unknown): BeholderAuthorizationRequest | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  const issuedAt = record.issued_at;
  const expiresAt = record.expires_at;
  if (
    !isExactRecord(record, [
      "decision",
      "evidence_id",
      "expires_at",
      "issued_at",
      "key_id",
      "operation_target_sha256",
      "requester_device_id",
      "schema_version",
      "signature",
    ]) ||
    record.schema_version !== 1 ||
    record.decision !== "allow" ||
    typeof record.evidence_id !== "string" ||
    !safeToken(record.evidence_id, 8, 96) ||
    typeof record.key_id !== "string" ||
    !base64UrlShape(record.key_id, 43) ||
    typeof record.requester_device_id !== "string" ||
    !safeToken(record.requester_device_id, 8, 128) ||
    typeof record.operation_target_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(record.operation_target_sha256) ||
    typeof record.signature !== "string" ||
    !base64UrlShape(record.signature, 86) ||
    typeof issuedAt !== "number" || !Number.isSafeInteger(issuedAt) ||
    typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) ||
    issuedAt < 0 ||
    expiresAt < 0
  ) {
    return undefined;
  }
  return record as unknown as BeholderAuthorizationRequest;
}

async function canonicalSha256Hex(value: unknown): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(canonicalizeJson(value)),
    ),
  );
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isExactRecord(
  value: unknown,
  keys: readonly string[],
): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length &&
    actual.every((key, index) => key === expected[index]);
}

function base64UrlShape(value: string, length: number): boolean {
  return value.length === length && /^[A-Za-z0-9_-]+$/.test(value);
}

function safeToken(value: string, minimum: number, maximum: number): boolean {
  return value.length >= minimum && value.length <= maximum &&
    /^[A-Za-z0-9._:-]+$/.test(value);
}
