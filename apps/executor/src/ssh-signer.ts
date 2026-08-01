import { createHash } from "node:crypto";

import type { ParsedKey } from "ssh2";
import keyParser from "ssh2/lib/protocol/keyParser.js";

import type { WireItem, WireItemField } from "./onepassword-wire";

// Runtime contract: Wrangler must enable `nodejs_compat` and alias the ssh2
// optional `cpu-features` package to `./cpu-features-disabled.cjs`. The pinned
// key parser then uses Workers' node:crypto implementation without native code.

const MAX_PUBLIC_KEY_LENGTH = 8_192;
const MAX_PRIVATE_KEY_LENGTH = 64 * 1_024;
const MAX_SIGNING_DATA_LENGTH = 64 * 1_024;
const OPENSSH_PRIVATE_KEY_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_PRIVATE_KEY_FOOTER = "-----END OPENSSH PRIVATE KEY-----";
const { parseKey } = keyParser;

export type SshSignatureAlgorithm =
  | "rsa-sha2-256"
  | "rsa-sha2-512"
  | "ssh-ed25519";

export interface SshKeyMetadata {
  algorithm: ParsedKey["type"];
  field_id: string;
  fingerprint: string;
  public_key: string;
  public_key_blob: string;
}

export interface SshSignatureResult extends Omit<SshKeyMetadata, "field_id"> {
  item_id: string;
  signature_algorithm: SshSignatureAlgorithm;
  signature_blob: string;
  version: number;
}

export class SshSignerError extends Error {
  override readonly name = "SshSignerError";

  constructor(
    readonly code:
      | "item_stale"
      | "ssh_algorithm_mismatch"
      | "ssh_algorithm_unsupported"
      | "ssh_key_invalid"
      | "ssh_key_mismatch"
      | "ssh_sign_failed"
      | "ssh_sign_request_invalid",
  ) {
    super(code);
  }
}

/**
 * Projects only public metadata from a decoded 1Password wire item. The field
 * value is intentionally ignored because raw item responses must never be used
 * as the private-key source.
 */
export function projectWireSshKeyMetadata(
  item: WireItem,
): SshKeyMetadata | undefined {
  if (item.category !== "SshKey") return undefined;
  const fields = item.fields.filter((field) => field.fieldType === "SshKey");
  if (fields.length !== 1) throw new SshSignerError("ssh_key_invalid");
  const field = fields[0]!;
  const publicKey = takePublicKey(field);
  const parsed = parseSingleKey(publicKey);
  const publicBlob = parsed.getPublicSSH();
  return {
    algorithm: parsed.type,
    field_id: takeFieldId(field.id),
    fingerprint: sshFingerprint(publicBlob),
    public_key: publicKey.trim(),
    public_key_blob: encodeBase64Url(publicBlob),
  };
}

/**
 * Signs with an unencrypted OpenSSH private key returned by the raw adapter's
 * secret resolver. The private key is used only inside this call and is never
 * included in the result or an error.
 */
export function signWireSshData(input: {
  data: Uint8Array;
  expectedFingerprint: string;
  expectedVersion: number;
  item: WireItem;
  privateKey: string;
  requestedAlgorithm: SshSignatureAlgorithm;
}): SshSignatureResult {
  validateSshSigningData(input.data);
  const metadata = validateWireSshSignTarget(input);
  const privateKey = takeOpenSshPrivateKey(input.privateKey);
  const parsed = parseSingleKey(privateKey);
  if (!parsed.isPrivateKey()) throw new SshSignerError("ssh_key_invalid");
  if (!parsed.getPublicSSH().equals(decodeBase64Url(metadata.public_key_blob))) {
    throw new SshSignerError("ssh_key_mismatch");
  }
  const hashAlgorithm = signingHash(parsed.type, input.requestedAlgorithm);
  const message = Buffer.from(input.data);
  let signature: Buffer;
  try {
    signature = parsed.sign(message, hashAlgorithm);
    if (parsed.verify(message, signature, hashAlgorithm) !== true) {
      throw new SshSignerError("ssh_sign_failed");
    }
  } catch (error) {
    if (error instanceof SshSignerError) throw error;
    throw new SshSignerError("ssh_sign_failed");
  }
  return {
    algorithm: metadata.algorithm,
    fingerprint: metadata.fingerprint,
    item_id: input.item.id,
    public_key: metadata.public_key,
    public_key_blob: metadata.public_key_blob,
    signature_algorithm: input.requestedAlgorithm,
    signature_blob: encodeBase64Url(signature),
    version: input.item.version,
  };
}

/** Validate request-controlled bytes before any private-key field is resolved. */
export function validateSshSigningData(
  data: unknown,
): asserts data is Uint8Array {
  if (
    !(data instanceof Uint8Array) ||
    data.byteLength === 0 ||
    data.byteLength > MAX_SIGNING_DATA_LENGTH
  ) {
    throw new SshSignerError("ssh_sign_request_invalid");
  }
}

/** Validate all public, approved facts before resolving private key material. */
export function validateWireSshSignTarget(input: {
  expectedFingerprint: string;
  expectedVersion: number;
  item: WireItem;
  requestedAlgorithm: SshSignatureAlgorithm;
}): SshKeyMetadata {
  if (
    !Number.isSafeInteger(input.expectedVersion) ||
    input.expectedVersion < 1
  ) {
    throw new SshSignerError("ssh_sign_request_invalid");
  }
  if (input.item.version !== input.expectedVersion) {
    throw new SshSignerError("item_stale");
  }
  const metadata = projectWireSshKeyMetadata(input.item);
  if (!metadata || metadata.fingerprint !== input.expectedFingerprint) {
    throw new SshSignerError("ssh_key_mismatch");
  }
  signingHash(metadata.algorithm, input.requestedAlgorithm);
  return metadata;
}

function takePublicKey(field: WireItemField): string {
  const details = takeRecord(field.details);
  const content = takeRecord(details?.content);
  const publicKey = content?.publicKey;
  if (
    details?.type !== "SshKey" ||
    typeof publicKey !== "string" ||
    publicKey.length === 0 ||
    publicKey.length > MAX_PUBLIC_KEY_LENGTH
  ) {
    throw new SshSignerError("ssh_key_invalid");
  }
  return publicKey;
}

function takeFieldId(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    throw new SshSignerError("ssh_key_invalid");
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) {
      throw new SshSignerError("ssh_key_invalid");
    }
  }
  return value;
}

function takeRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return undefined;
  }
  return value as Record<string, unknown>;
}

function takeOpenSshPrivateKey(value: unknown): string {
  if (typeof value !== "string") throw new SshSignerError("ssh_key_invalid");
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > MAX_PRIVATE_KEY_LENGTH ||
    !normalized.startsWith(`${OPENSSH_PRIVATE_KEY_HEADER}\n`) ||
    !normalized.endsWith(`\n${OPENSSH_PRIVATE_KEY_FOOTER}`)
  ) {
    throw new SshSignerError("ssh_key_invalid");
  }
  return normalized;
}

function parseSingleKey(value: string | Buffer): ParsedKey {
  let parsed: ParsedKey | ParsedKey[] | Error;
  try {
    parsed = parseKey(value);
  } catch {
    throw new SshSignerError("ssh_key_invalid");
  }
  if (parsed instanceof Error || Array.isArray(parsed)) {
    throw new SshSignerError("ssh_key_invalid");
  }
  if (
    parsed.type !== "ssh-ed25519" &&
    parsed.type !== "ssh-rsa"
  ) {
    throw new SshSignerError("ssh_algorithm_unsupported");
  }
  return parsed;
}

function signingHash(
  keyType: ParsedKey["type"],
  requestedAlgorithm: SshSignatureAlgorithm,
): string | undefined {
  if (keyType === "ssh-ed25519" && requestedAlgorithm === "ssh-ed25519") {
    return undefined;
  }
  if (keyType === "ssh-rsa") {
    if (requestedAlgorithm === "rsa-sha2-256") return "sha256";
    if (requestedAlgorithm === "rsa-sha2-512") return "sha512";
  }
  throw new SshSignerError("ssh_algorithm_mismatch");
}

function sshFingerprint(publicBlob: Buffer): string {
  const digest = createHash("sha256").update(publicBlob).digest("base64");
  return `SHA256:${digest.replace(/=+$/u, "")}`;
}

function encodeBase64Url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decodeBase64Url(value: string): Buffer {
  try {
    return Buffer.from(value, "base64url");
  } catch {
    throw new SshSignerError("ssh_key_invalid");
  }
}
