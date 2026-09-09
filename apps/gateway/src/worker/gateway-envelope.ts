import { decodeBase64Url, type SshSignatureAlgorithm } from "@onenod/protocol";

import { ExecutorTransportError } from "./executor-transport.js";

const ERROR_STATUSES = new Map<string, ReadonlySet<number>>([
  ["catalog_query_invalid", new Set([400])],
  ["executor_internal_error", new Set([503])],
  ["executor_storage_pressure", new Set([507])],
  ["item_operation_invalid", new Set([400])],
  ["field_not_found", new Set([404])],
  ["item_stale", new Set([409])],
  ["onepassword_rate_limited", new Set([429])],
  ["onepassword_operation_failed", new Set([502])],
  ["onepassword_write_outcome_unknown", new Set([502, 504])],
  ["ssh_algorithm_mismatch", new Set([400])],
  ["ssh_algorithm_unsupported", new Set([400])],
  ["ssh_key_invalid", new Set([502])],
  ["ssh_key_mismatch", new Set([409])],
  ["ssh_sign_failed", new Set([502])],
  ["ssh_sign_request_invalid", new Set([400])],
  ["vault_scope_mismatch", new Set([502])],
  ["onepassword_timeout", new Set([504])],
]);

export interface CatalogExecutorItem {
  category: string;
  fields: Array<{
    field_id: string;
    field_type: string;
    label: string;
  }>;
  item_id: string;
  ssh?: {
    algorithm: string;
    fingerprint: string;
    public_key: string;
    public_key_blob: string;
  };
  title: string;
  updated_at: string;
  version: number;
}

export interface SecretMetadataExecutorResult {
  field_id: string;
  field_label: string;
  field_type: string;
  item_id: string;
  item_title: string;
  version: number;
}

export interface SecretReadExecutorResult
  extends SecretMetadataExecutorResult {
  value: string;
}

export interface CredentialUseExecutorResult {
  fields: SecretReadExecutorResult[];
  item_id: string;
  item_title: string;
  version: number;
}

export interface ItemMutationExecutorResult {
  item_id: string;
  version?: number;
}

export interface ItemReconciliationExecutorResult {
  item_id?: string;
  reconciliation: "AMBIGUOUS" | "APPLIED" | "NOT_APPLIED";
  version?: number;
}

export interface SshSignExecutorResult {
  algorithm: SshSignatureAlgorithm;
  fingerprint: string;
  item_id: string;
  public_key_blob: string;
  signature_blob: string;
  version: number;
}

export interface SecretTargetExpectation {
  field_id: string;
  field_label?: string;
  field_type?: string;
  item_id: string;
  item_title?: string;
  version?: number;
}

export function sanitizeCatalogEnvelope(
  body: Record<string, unknown>,
  status: number,
): CatalogExecutorItem[] {
  assertSuccessful(body, status);
  if (!Array.isArray(body.items) || body.items.length > 20) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return body.items.map((value) => sanitizeCatalogItem(value));
}

export function sanitizeSecretMetadataEnvelope(
  body: Record<string, unknown>,
  status: number,
  expected: SecretTargetExpectation,
): SecretMetadataExecutorResult {
  assertSuccessful(body, status);
  const result = sanitizeMetadata(body);
  assertExpectedTarget(result, expected);
  return result;
}

export function sanitizeSecretReadEnvelope(
  body: Record<string, unknown>,
  status: number,
  expected: SecretTargetExpectation,
): SecretReadExecutorResult {
  assertSuccessful(body, status);
  if (typeof body.value !== "string" || body.value.length > 32 * 1024) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const result = {
    ...sanitizeMetadata(body),
    value: body.value,
  };
  assertExpectedTarget(result, expected);
  return result;
}

export function sanitizeCredentialUseEnvelope(
  body: Record<string, unknown>,
  status: number,
  expected: {
    fields: Array<Required<SecretTargetExpectation>>;
    item_id: string;
    item_title: string;
    version: number;
  },
): CredentialUseExecutorResult {
  assertSuccessful(body, status);
  const itemId = safeIdentifier(body.item_id);
  const itemTitle = safeText(body.item_title, 256);
  const version = safeVersion(body.version);
  if (
    itemId !== expected.item_id ||
    itemTitle !== expected.item_title ||
    version !== expected.version ||
    !Array.isArray(body.fields) ||
    body.fields.length !== expected.fields.length
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const fields = body.fields.map((candidate, index) => {
    const field = record(candidate);
    if (typeof field.value !== "string" || field.value.length > 32 * 1024) {
      throw new ExecutorTransportError("untrusted_response");
    }
    const result = { ...sanitizeMetadata(field), value: field.value };
    assertExpectedTarget(result, expected.fields[index]!);
    return result;
  });
  return { fields, item_id: itemId, item_title: itemTitle, version };
}

export function sanitizeItemMetadataEnvelope(
  body: Record<string, unknown>,
  status: number,
  expectedItemId: string,
): CatalogExecutorItem {
  assertSuccessful(body, status);
  const item = sanitizeCatalogItem(body.item);
  if (item.item_id !== expectedItemId) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return item;
}

export function sanitizeItemMutationEnvelope(
  body: Record<string, unknown>,
  status: number,
  expectedItemId?: string,
): ItemMutationExecutorResult {
  assertSuccessful(body, status);
  const itemId = safeIdentifier(body.item_id);
  if (expectedItemId !== undefined && itemId !== expectedItemId) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return {
    item_id: itemId,
    ...(body.version === undefined ? {} : { version: safeVersion(body.version) }),
  };
}

export function sanitizeItemReconciliationEnvelope(
  body: Record<string, unknown>,
  status: number,
  expectedItemId?: string,
): ItemReconciliationExecutorResult {
  assertSuccessful(body, status);
  if (
    body.reconciliation !== "AMBIGUOUS" &&
    body.reconciliation !== "APPLIED" &&
    body.reconciliation !== "NOT_APPLIED"
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const itemId =
    body.item_id === undefined ? undefined : safeIdentifier(body.item_id);
  if (
    expectedItemId !== undefined &&
    itemId !== expectedItemId
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  if (body.reconciliation === "APPLIED" && itemId === undefined) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return {
    ...(itemId === undefined ? {} : { item_id: itemId }),
    reconciliation: body.reconciliation,
    ...(body.version === undefined ? {} : { version: safeVersion(body.version) }),
  };
}

export function sanitizeSshSignEnvelope(
  body: Record<string, unknown>,
  status: number,
  expected: {
    algorithm: SshSignatureAlgorithm;
    fingerprint: string;
    item_id: string;
    version: number;
  },
): SshSignExecutorResult {
  assertSuccessful(body, status);
  const itemId = safeIdentifier(body.item_id);
  const version = safeVersion(body.version);
  const fingerprint = safeString(body.fingerprint, 80);
  const algorithm = body.signature_algorithm;
  if (
    itemId !== expected.item_id ||
    version !== expected.version ||
    fingerprint !== expected.fingerprint ||
    algorithm !== expected.algorithm
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const publicKeyBlob = safeBase64Url(body.public_key_blob, 8 * 1_024);
  const signatureBlob = safeBase64Url(body.signature_blob, 16 * 1_024);
  return {
    algorithm: expected.algorithm,
    fingerprint,
    item_id: itemId,
    public_key_blob: publicKeyBlob,
    signature_blob: signatureBlob,
    version,
  };
}

export function sanitizeGatewayError(
  body: Record<string, unknown>,
  status: number,
): { code: string; status: number } {
  if (
    body.ok !== false ||
    typeof body.error !== "string" ||
    !ERROR_STATUSES.get(body.error)?.has(status)
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return { code: body.error, status };
}

function assertSuccessful(
  body: Record<string, unknown>,
  status: number,
): void {
  if (status !== 200 || body.ok !== true || body.error !== undefined) {
    throw new ExecutorTransportError("untrusted_response");
  }
}

function sanitizeCatalogItem(value: unknown): CatalogExecutorItem {
  const item = record(value);
  const fields = item.fields;
  if (!Array.isArray(fields) || fields.length > 64) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const ssh = item.ssh === undefined ? undefined : sanitizeSshMetadata(item.ssh);
  return {
    category: safeString(item.category, 64),
    fields: fields.map((candidate) => {
      const field = record(candidate);
      return {
        field_id: safeIdentifier(field.field_id),
        field_type: safeString(field.field_type, 64),
        label: safeText(field.label, 128),
      };
    }),
    item_id: safeIdentifier(item.item_id),
    ...(ssh ? { ssh } : {}),
    title: safeText(item.title, 256),
    updated_at: safeTimestamp(item.updated_at),
    version: safeVersion(item.version),
  };
}

function sanitizeSshMetadata(value: unknown): NonNullable<CatalogExecutorItem["ssh"]> {
  const metadata = record(value);
  const algorithm = safeString(metadata.algorithm, 32);
  if (
    algorithm !== "ssh-ed25519" &&
    algorithm !== "ssh-rsa"
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const fingerprint = safeString(metadata.fingerprint, 80);
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/u.test(fingerprint)) {
    throw new ExecutorTransportError("untrusted_response");
  }
  const publicKey = safeText(metadata.public_key, 8_192);
  const publicKeyBlob = safeBase64Url(metadata.public_key_blob, 8 * 1024);
  return {
    algorithm,
    fingerprint,
    public_key: publicKey,
    public_key_blob: publicKeyBlob,
  };
}

function sanitizeMetadata(
  body: Record<string, unknown>,
): SecretMetadataExecutorResult {
  return {
    field_id: safeIdentifier(body.field_id),
    field_label: safeText(body.field_label, 128),
    field_type: safeString(body.field_type, 64),
    item_id: safeIdentifier(body.item_id),
    item_title: safeText(body.item_title, 256),
    version: safeVersion(body.version),
  };
}

function assertExpectedTarget(
  result: SecretMetadataExecutorResult,
  expected: SecretTargetExpectation,
): void {
  if (
    result.item_id !== expected.item_id ||
    result.field_id !== expected.field_id ||
    (expected.version !== undefined && result.version !== expected.version) ||
    (expected.item_title !== undefined &&
      result.item_title !== expected.item_title) ||
    (expected.field_label !== undefined &&
      result.field_label !== expected.field_label) ||
    (expected.field_type !== undefined &&
      result.field_type !== expected.field_type)
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return value as Record<string, unknown>;
}

function safeString(value: unknown, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    hasForbiddenControl(value, false)
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return value;
}

function safeIdentifier(value: unknown): string {
  return safeString(value, 256);
}

function safeText(value: unknown, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    hasForbiddenControl(value, true)
  ) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return value.normalize("NFC");
}

function safeTimestamp(value: unknown): string {
  const timestamp = safeString(value, 64);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return timestamp;
}

function safeVersion(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return value as number;
}

function safeBase64Url(value: unknown, maximumBytes: number): string {
  const encoded = safeString(value, Math.ceil((maximumBytes * 4) / 3) + 4);
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64Url(encoded);
  } catch {
    throw new ExecutorTransportError("untrusted_response");
  }
  if (decoded.byteLength === 0 || decoded.byteLength > maximumBytes) {
    throw new ExecutorTransportError("untrusted_response");
  }
  return encoded;
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
