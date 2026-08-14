import { base64urlnopad } from "@scure/base";
import canonicalize from "canonicalize";

import {
  type ExecutionAction,
  type ExecutionIdentity,
  ExecutionJournal,
  ExecutionJournalError,
  type ExecutionJournalRecord,
} from "./execution-journal";
import {
  GatewayOperationError,
  type ItemCreateField,
  type ItemMutationResult,
  type ItemPatchOperation,
  type ItemReconciliationResult,
  type WritableItemCategory,
  type WritableItemCreateFieldType,
  type WritableItemFieldType,
} from "./onepassword-raw-gateway";
import type { SshSignatureAlgorithm } from "./ssh-signer";

export const EXECUTOR_PROTOCOL_HEADER = "x-onenod-executor-protocol";
export const EXECUTOR_PROTOCOL_VERSION = "v1";
export const EXECUTOR_REQUEST_ID_HEADER = "x-1pr-request-id";
export const EXECUTOR_BODY_DIGEST_HEADER = "x-1pr-body-digest";

export const INTERNAL_ONEPASSWORD_PATHS = new Set([
  "/internal/health",
  "/internal/1password/catalog",
  "/internal/1password/quota",
  "/internal/1password/secret/metadata",
  "/internal/1password/secret/read",
  "/internal/1password/item/metadata",
  "/internal/1password/item/mutate",
  "/internal/1password/item/reconcile",
  "/internal/1password/ssh/sign",
]);

const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BODY_DIGEST_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_SECRET_VALUE_LENGTH = 16 * 1_024;

export type ParsedMutation =
  | {
      action: "item.create";
      category: WritableItemCategory;
      fields: ItemCreateField[];
      requestId: string;
      title: string;
    }
  | {
      action: "item.patch";
      expectedVersion: number;
      itemId: string;
      operations: ItemPatchOperation[];
    }
  | {
      action: "item.archive";
      expectedVersion: number;
      itemId: string;
    };

export interface ParsedSshSignRequest {
  data: Uint8Array;
  expectedFingerprint: string;
  expectedVersion: number;
  itemId: string;
  requestedAlgorithm: SshSignatureAlgorithm;
}

export async function readJsonObject(
  request: Request,
  maximumBytes: number,
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type");
  if (contentType?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
    throw new TypeError("request_content_type_invalid");
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const length = Number(declaredLength);
    if (!Number.isInteger(length) || length < 1 || length > maximumBytes) {
      throw new TypeError("request_body_size_invalid");
    }
  }

  const reader = request.body?.getReader();
  if (!reader) throw new TypeError("request_body_required");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel();
        throw new TypeError("request_body_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (size === 0) throw new TypeError("request_body_required");

  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new TypeError("request_json_invalid");
  }
  return takeObject(parsed);
}

export function parseCatalogRequest(body: Record<string, unknown>): string {
  assertKeys(body, ["query"]);
  return takeString(body, "query", 128, true);
}

export function parseHealthRequest(body: Record<string, unknown>): void {
  assertKeys(body, []);
}

export function parseSecretMetadataRequest(body: Record<string, unknown>): {
  fieldId: string;
  itemId: string;
} {
  assertKeys(body, ["field_id", "item_id"]);
  return {
    fieldId: takeIdentifier(body, "field_id"),
    itemId: takeIdentifier(body, "item_id"),
  };
}

export function parseSecretReadRequest(body: Record<string, unknown>): {
  expectedVersion: number;
  fieldId: string;
  itemId: string;
} {
  assertKeys(body, ["expected_version", "field_id", "item_id"]);
  return {
    expectedVersion: takePositiveInteger(body, "expected_version"),
    fieldId: takeIdentifier(body, "field_id"),
    itemId: takeIdentifier(body, "item_id"),
  };
}

export function parseItemMetadataRequest(body: Record<string, unknown>): string {
  assertKeys(body, ["item_id"]);
  return takeIdentifier(body, "item_id");
}

export function parseSshSignRequest(
  body: Record<string, unknown>,
): ParsedSshSignRequest {
  assertKeys(body, [
    "algorithm",
    "data",
    "expected_fingerprint",
    "expected_version",
    "item_id",
  ]);
  return {
    data: takeBase64UrlBytes(body, "data", 64 * 1_024),
    expectedFingerprint: takeSshFingerprint(body.expected_fingerprint),
    expectedVersion: takePositiveInteger(body, "expected_version"),
    itemId: takeIdentifier(body, "item_id"),
    requestedAlgorithm: takeSshSignatureAlgorithm(body.algorithm),
  };
}

export function parseMutationRequest(body: Record<string, unknown>): ParsedMutation {
  const action = takeString(body, "action", 32);
  if (action === "item.create") {
    assertKeys(body, ["action", "category", "fields", "request_id", "title"]);
    const category = takeWritableCategory(body, "category");
    return {
      action,
      category,
      fields: takeCreateFields(body, "fields", category),
      requestId: takeIdentifier(body, "request_id"),
      title: takeText(body, "title", 256),
    };
  }
  if (action === "item.patch") {
    assertKeys(body, ["action", "expected_version", "item_id", "operations"]);
    return {
      action,
      expectedVersion: takePositiveInteger(body, "expected_version"),
      itemId: takeIdentifier(body, "item_id"),
      operations: takePatchOperations(body, "operations"),
    };
  }
  if (action === "item.archive") {
    assertKeys(body, ["action", "expected_version", "item_id"]);
    return {
      action,
      expectedVersion: takePositiveInteger(body, "expected_version"),
      itemId: takeIdentifier(body, "item_id"),
    };
  }
  throw new TypeError("mutation_action_invalid");
}

export async function readExecutionIdentity(
  request: Request,
  body: Record<string, unknown>,
  action: ExecutionAction,
): Promise<ExecutionIdentity> {
  const requestId = request.headers.get(EXECUTOR_REQUEST_ID_HEADER);
  const bodyDigest = request.headers.get(EXECUTOR_BODY_DIGEST_HEADER);
  if (
    requestId === null ||
    bodyDigest === null ||
    !REQUEST_ID_PATTERN.test(requestId) ||
    !BODY_DIGEST_PATTERN.test(bodyDigest)
  ) {
    throw new TypeError("execution_identity_invalid");
  }
  if (action === "item.create" && body.request_id !== requestId) {
    throw new TypeError("execution_identity_invalid");
  }
  if ((await canonicalJsonSha256Base64Url(body)) !== bodyDigest) {
    throw new TypeError("execution_body_digest_mismatch");
  }
  return { action, bodyDigest, requestId };
}

/**
 * Persist a no-replay fence before entering `invoke`. Existing terminal records
 * are served without invoking 1Password; unresolved records return the public
 * write-outcome-unknown error understood by the control plane.
 */
export async function executeJournaledMutation(input: {
  identity: ExecutionIdentity;
  invoke: () => Promise<ItemMutationResult>;
  journal: ExecutionJournal;
}): Promise<ItemMutationResult> {
  let prepared: ExecutionJournalRecord;
  try {
    prepared = input.journal.prepare(input.identity);
  } catch (error) {
    throw classifyJournalIdentityError(error);
  }
  if (prepared.state !== "prepared") return mutationTerminal(prepared);

  try {
    input.journal.beginWrite(input.identity);
  } catch (error) {
    return mutationTerminalAfterRace(input, error);
  }

  let result: ItemMutationResult;
  try {
    result = await input.invoke();
  } catch (error) {
    const classified = classifyMutationFailure(error);
    try {
      if (classified.code === "onepassword_write_outcome_unknown") {
        input.journal.markUnknown(input.identity, classified.code);
      } else {
        input.journal.markDefinitivelyFailed(input.identity, classified.code);
      }
    } catch {
      throw writeOutcomeUnknown();
    }
    throw classified;
  }

  try {
    input.journal.markApplied(input.identity, {
      itemId: result.item_id,
      ...(result.version === undefined ? {} : { version: result.version }),
    });
  } catch {
    throw writeOutcomeUnknown();
  }
  return result;
}

/** Reconciliation is strictly read-only; only its journal transitions persist. */
export async function executeJournaledReconciliation(input: {
  identity: ExecutionIdentity;
  invoke: () => Promise<ItemReconciliationResult>;
  itemId?: string;
  journal: ExecutionJournal;
}): Promise<ItemReconciliationResult> {
  let current: ExecutionJournalRecord;
  try {
    const loaded = input.journal.get(input.identity.requestId);
    if (
      loaded === undefined ||
      loaded.action !== input.identity.action ||
      loaded.bodyDigest !== input.identity.bodyDigest
    ) {
      throw new ExecutionJournalError("identity_conflict");
    }
    current = loaded;
  } catch (error) {
    throw classifyJournalIdentityError(error);
  }

  if (current.state === "applied") {
    return appliedReconciliation(current);
  }
  if (current.state === "definitively_failed") {
    return {
      ...(input.itemId === undefined ? {} : { item_id: input.itemId }),
      reconciliation: "NOT_APPLIED",
    };
  }
  if (current.state === "prepared") {
    try {
      input.journal.beginWrite(input.identity);
      input.journal.markDefinitivelyFailed(
        input.identity,
        "reconciled_not_applied",
      );
    } catch {
      throw writeOutcomeUnknown();
    }
    return {
      ...(input.itemId === undefined ? {} : { item_id: input.itemId }),
      reconciliation: "NOT_APPLIED",
    };
  }

  let result: ItemReconciliationResult;
  try {
    result = await input.invoke();
  } catch (error) {
    bestEffortRecordUnknownReconciliation(input.journal, input.identity, current);
    throw classifyReadFailure(error);
  }

  try {
    if (current.state === "attempting") {
      input.journal.markUnknown(input.identity, "onepassword_write_outcome_unknown");
    }
    input.journal.recordReconcile(input.identity, result.reconciliation);
    if (result.reconciliation === "APPLIED") {
      input.journal.markApplied(input.identity, {
        ...(result.item_id === undefined ? {} : { itemId: result.item_id }),
        ...(result.version === undefined ? {} : { version: result.version }),
      });
    } else if (result.reconciliation === "NOT_APPLIED") {
      input.journal.markDefinitivelyFailed(
        input.identity,
        "reconciled_not_applied",
      );
    }
  } catch {
    throw writeOutcomeUnknown();
  }
  return result;
}

export async function canonicalJsonSha256Base64Url(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalizeJson(value));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return encodeBase64Url(digest);
}

function mutationTerminal(record: ExecutionJournalRecord): ItemMutationResult {
  if (record.state === "applied" && record.resultItemId !== null) {
    return {
      item_id: record.resultItemId,
      ...(record.resultVersion === null ? {} : { version: record.resultVersion }),
    };
  }
  if (record.state === "definitively_failed") {
    throw gatewayErrorForSafeCode(record.safeCode);
  }
  throw writeOutcomeUnknown();
}

function mutationTerminalAfterRace(
  input: {
    identity: ExecutionIdentity;
    journal: ExecutionJournal;
  },
  error: unknown,
): ItemMutationResult {
  if (
    error instanceof ExecutionJournalError &&
    error.code === "journal_storage_pressure"
  ) {
    throw new GatewayOperationError("executor_storage_pressure", 507);
  }
  try {
    const current = input.journal.get(input.identity.requestId);
    if (current !== undefined) return mutationTerminal(current);
  } catch {
    // Fall through to the conservative no-replay response.
  }
  if (
    error instanceof ExecutionJournalError &&
    (error.code === "identity_conflict" ||
      error.code === "invalid_action" ||
      error.code === "invalid_body_digest" ||
      error.code === "invalid_request_id")
  ) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  throw writeOutcomeUnknown();
}

function appliedReconciliation(
  record: ExecutionJournalRecord,
): ItemReconciliationResult {
  if (record.resultItemId === null) throw writeOutcomeUnknown();
  return {
    item_id: record.resultItemId,
    reconciliation: "APPLIED",
    ...(record.resultVersion === null ? {} : { version: record.resultVersion }),
  };
}

function classifyMutationFailure(error: unknown): GatewayOperationError {
  return error instanceof GatewayOperationError ? error : writeOutcomeUnknown();
}

function classifyReadFailure(error: unknown): GatewayOperationError {
  return error instanceof GatewayOperationError
    ? error
    : new GatewayOperationError("onepassword_operation_failed", 502);
}

function classifyJournalIdentityError(error: unknown): GatewayOperationError {
  if (
    error instanceof ExecutionJournalError &&
    error.code === "journal_storage_pressure"
  ) {
    return new GatewayOperationError("executor_storage_pressure", 507);
  }
  if (
    error instanceof ExecutionJournalError &&
    (error.code === "identity_conflict" ||
      error.code === "invalid_action" ||
      error.code === "invalid_body_digest" ||
      error.code === "invalid_request_id" ||
      error.code === "journal_not_found")
  ) {
    return new GatewayOperationError("item_operation_invalid", 400);
  }
  return writeOutcomeUnknown();
}

function gatewayErrorForSafeCode(safeCode: string | null): GatewayOperationError {
  switch (safeCode) {
    case "field_not_found":
      return new GatewayOperationError(safeCode, 404);
    case "item_operation_invalid":
      return new GatewayOperationError(safeCode, 400);
    case "item_stale":
      return new GatewayOperationError(safeCode, 409);
    case "onepassword_timeout":
      return new GatewayOperationError(safeCode, 504);
    case "onepassword_operation_failed":
    case "vault_scope_mismatch":
      return new GatewayOperationError(safeCode, 502);
    default:
      return writeOutcomeUnknown();
  }
}

function bestEffortRecordUnknownReconciliation(
  journal: ExecutionJournal,
  identity: ExecutionIdentity,
  current: ExecutionJournalRecord,
): void {
  try {
    if (current.state === "attempting") {
      journal.markUnknown(identity, "onepassword_write_outcome_unknown");
    }
    journal.recordReconcile(identity, "UNKNOWN");
  } catch {
    // The durable no-replay state remains safer than retrying the write.
  }
}

function writeOutcomeUnknown(): GatewayOperationError {
  return new GatewayOperationError("onepassword_write_outcome_unknown", 502);
}

function takeCreateFields(
  body: Record<string, unknown>,
  name: string,
  category: WritableItemCategory,
): ItemCreateField[] {
  const value = body[name];
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    throw new TypeError(`invalid_${name}`);
  }
  const fields = value.map((candidate) => {
    const field = takeObject(candidate);
    assertKeys(field, ["field_id", "field_type", "label", "value"]);
    return {
      field_id: takeIdentifier(field, "field_id"),
      field_type: takeWritableCreateFieldType(field.field_type),
      label: takeText(field, "label", 128),
      value: takeSecretValue(field, "value"),
    };
  });
  if (category === "SshKey") {
    if (
      fields.length !== 1 ||
      fields[0]?.field_id !== "private_key" ||
      fields[0].field_type !== "SshKey" ||
      fields[0].label !== "private key"
    ) {
      throw new TypeError("ssh_key_create_shape_invalid");
    }
  } else if (fields.some((field) => field.field_type === "SshKey")) {
    throw new TypeError("ssh_key_category_invalid");
  }
  return fields;
}

function takePatchOperations(
  body: Record<string, unknown>,
  name: string,
): ItemPatchOperation[] {
  const value = body[name];
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    throw new TypeError(`invalid_${name}`);
  }
  return value.map((candidate) => {
    const operation = takeObject(candidate);
    if (operation.op === "add") {
      assertKeys(operation, ["field_id", "field_type", "label", "op", "value"]);
      return {
        field_id: takeIdentifier(operation, "field_id"),
        field_type: takeWritableFieldType(operation.field_type),
        label: takeText(operation, "label", 128),
        op: "add",
        value: takeSecretValue(operation, "value"),
      };
    }
    if (operation.op === "replace") {
      assertKeys(operation, ["field_id", "op", "value"]);
      return {
        field_id: takeIdentifier(operation, "field_id"),
        op: "replace",
        value: takeSecretValue(operation, "value"),
      };
    }
    if (operation.op === "remove") {
      assertKeys(operation, ["field_id", "op"]);
      return { field_id: takeIdentifier(operation, "field_id"), op: "remove" };
    }
    throw new TypeError("patch_operation_invalid");
  });
}

function takeWritableCategory(
  body: Record<string, unknown>,
  name: string,
): WritableItemCategory {
  const value = takeString(body, name, 32);
  if (
    value !== "ApiCredentials" &&
    value !== "Login" &&
    value !== "Password" &&
    value !== "SecureNote" &&
    value !== "SshKey"
  ) {
    throw new TypeError(`invalid_${name}`);
  }
  return value;
}

function takeWritableCreateFieldType(value: unknown): WritableItemCreateFieldType {
  if (value === "SshKey") return value;
  return takeWritableFieldType(value);
}

function takeSshSignatureAlgorithm(value: unknown): SshSignatureAlgorithm {
  if (
    value !== "ssh-ed25519" &&
    value !== "rsa-sha2-256" &&
    value !== "rsa-sha2-512"
  ) {
    throw new TypeError("ssh_algorithm_unsupported");
  }
  return value;
}

function takeSshFingerprint(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^SHA256:[A-Za-z0-9+/]{43}$/u.test(value)
  ) {
    throw new TypeError("ssh_fingerprint_invalid");
  }
  return value;
}

function takeBase64UrlBytes(
  body: Record<string, unknown>,
  name: string,
  maximumBytes: number,
): Uint8Array {
  const value = body[name];
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    throw new TypeError(`invalid_${name}`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64urlnopad.decode(value);
  } catch {
    throw new TypeError(`invalid_${name}`);
  }
  if (
    decoded.byteLength === 0 ||
    decoded.byteLength > maximumBytes ||
    encodeBase64Url(decoded) !== value
  ) {
    throw new TypeError(`invalid_${name}`);
  }
  return decoded;
}

function takeWritableFieldType(value: unknown): WritableItemFieldType {
  if (value !== "Concealed" && value !== "Email" && value !== "Text" && value !== "Url") {
    throw new TypeError("field_type_invalid");
  }
  return value;
}

function takeSecretValue(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value.length > MAX_SECRET_VALUE_LENGTH) {
    throw new TypeError(`invalid_${name}`);
  }
  return value;
}

function takeText(
  body: Record<string, unknown>,
  name: string,
  maximumLength: number,
): string {
  const value = takeString(body, name, maximumLength).normalize("NFC");
  if (value.length === 0 || hasControlCharacter(value)) {
    throw new TypeError(`invalid_${name}`);
  }
  return value;
}

function takeIdentifier(body: Record<string, unknown>, name: string): string {
  const value = takeString(body, name, 256);
  if (value.length === 0 || hasControlCharacter(value)) {
    throw new TypeError(`invalid_${name}`);
  }
  return value;
}

function takeString(
  body: Record<string, unknown>,
  name: string,
  maximumLength: number,
  allowEmpty = false,
): string {
  const value = body[name];
  if (
    typeof value !== "string" ||
    (!allowEmpty && value.length === 0) ||
    value.length > maximumLength
  ) {
    throw new TypeError(`invalid_${name}`);
  }
  return value;
}

function takePositiveInteger(body: Record<string, unknown>, name: string): number {
  const value = body[name];
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new TypeError(`invalid_${name}`);
  }
  return value as number;
}

function takeObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("request_object_invalid");
  }
  return value as Record<string, unknown>;
}

function assertKeys(body: Record<string, unknown>, expected: string[]): void {
  const actual = Object.keys(body).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new TypeError("request_fields_invalid");
  }
}

function hasControlCharacter(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}

function canonicalizeJson(value: unknown): string {
  const serialized = canonicalize(value);
  if (serialized === undefined) throw new TypeError("canonical_json_invalid");
  return serialized;
}

function encodeBase64Url(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}
