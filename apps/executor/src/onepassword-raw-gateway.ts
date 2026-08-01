import { CoreAdapterError, type OnePasswordCoreClient } from "./onepassword-core";
import {
  type WireDetailedItemOverview,
  type WireItem,
  type WireItemCreateParams,
  type OnePasswordOperation,
  decodeDetailedItemList,
  decodeItem,
  decodeResolvedSecret,
  decodeVaultList,
  decodeVoid,
} from "./onepassword-wire";
import {
  SshSignerError,
  projectWireSshKeyMetadata,
  signWireSshData,
  type SshSignatureAlgorithm,
  type SshSignatureResult,
  validateSshSigningData,
  validateWireSshSignTarget,
} from "./ssh-signer";

const MAX_CATALOG_RESULTS = 12;
const MAX_SSH_CATALOG_RESULTS = 64;
const MAX_SECRET_VALUE_LENGTH = 16 * 1_024;
const NOTES_FIELD_ID = "com.github.vizards.onenod.notes";
const INTERNAL_NAMESPACE = "com.github.vizards.onenod";
const INTERNAL_SECTION_ID = INTERNAL_NAMESPACE;
const MARKER_FIELD_ID = `${INTERNAL_NAMESPACE}.request-id`;
const MARKER_TAG_PREFIX = "1pr-request-";
const USER_SECTION_ID = `${INTERNAL_NAMESPACE}.fields`;
const ITEM_ID_PATTERN = /^[a-z0-9]{20,64}$/;

export type WritableItemCategory =
  | "ApiCredentials"
  | "Login"
  | "Password"
  | "SecureNote"
  | "SshKey";

export type WritableItemFieldType = "Concealed" | "Email" | "Text" | "Url";
export type WritableItemCreateFieldType = WritableItemFieldType | "SshKey";

export interface ItemCreateField {
  field_id: string;
  field_type: WritableItemCreateFieldType;
  label: string;
  value: string;
}

export type ItemPatchOperation =
  | {
      field_id: string;
      field_type: WritableItemFieldType;
      label: string;
      op: "add";
      value: string;
    }
  | { field_id: string; op: "replace"; value: string }
  | { field_id: string; op: "remove" };

export interface CatalogField {
  field_id: string;
  field_type: string;
  label: string;
}

export interface CatalogItem {
  category: string;
  fields: CatalogField[];
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

export interface SecretReadMetadata {
  field_id: string;
  field_label: string;
  field_type: string;
  item_id: string;
  item_title: string;
  version: number;
}

export interface RawGatewayOptions {
  client: OnePasswordCoreClient;
  vaultId: string;
}

export interface CatalogOptions extends RawGatewayOptions {
  query: string;
}

export interface SecretTargetOptions extends RawGatewayOptions {
  fieldId: string;
  itemId: string;
}

export interface SecretReadOptions extends SecretTargetOptions {
  expectedVersion: number;
}

export interface ItemCreateOptions extends RawGatewayOptions {
  category: WritableItemCategory;
  fields: ItemCreateField[];
  requestId: string;
  title: string;
}

export interface ItemPatchOptions extends RawGatewayOptions {
  expectedVersion: number;
  itemId: string;
  operations: ItemPatchOperation[];
}

export interface ItemArchiveOptions extends RawGatewayOptions {
  expectedVersion: number;
  itemId: string;
}

export interface SshSignOptions extends RawGatewayOptions {
  data: Uint8Array;
  expectedFingerprint: string;
  expectedVersion: number;
  itemId: string;
  requestedAlgorithm: SshSignatureAlgorithm;
}

export type ItemWriteReconciliation = "AMBIGUOUS" | "APPLIED" | "NOT_APPLIED";

export interface ItemMutationResult {
  item_id: string;
  version?: number;
}

export interface ItemReconciliationResult {
  item_id?: string;
  reconciliation: ItemWriteReconciliation;
  version?: number;
}

export class GatewayOperationError extends Error {
  override readonly name = "GatewayOperationError";

  constructor(
    readonly code:
      | "catalog_query_invalid"
      | "executor_storage_pressure"
      | "field_not_found"
      | "item_operation_invalid"
      | "item_stale"
      | "onepassword_operation_failed"
      | "onepassword_timeout"
      | "onepassword_write_outcome_unknown"
      | "ssh_algorithm_mismatch"
      | "ssh_algorithm_unsupported"
      | "ssh_key_invalid"
      | "ssh_key_mismatch"
      | "ssh_sign_failed"
      | "ssh_sign_request_invalid"
      | "vault_scope_mismatch",
    readonly status: number,
  ) {
    super(code);
  }
}

export async function executeCatalog(options: CatalogOptions): Promise<CatalogItem[]> {
  assertExactKeys(options, ["client", "query", "vaultId"]);
  if (typeof options.query !== "string" || options.query.length > 128) {
    throw new GatewayOperationError("catalog_query_invalid", 400);
  }
  const vaultId = itemIdentifier(options.vaultId);
  await assertVaultScope(options.client, vaultId);
  const overviews = await listItems(options.client, vaultId, false);
  const normalized = options.query.trim().toLocaleLowerCase("en-US");
  const matches =
    normalized.length === 0
      ? overviews
          .filter((item) => item.category === "SshKey")
          .slice(0, MAX_SSH_CATALOG_RESULTS)
      : overviews
          .filter(
            (item) =>
              item.id === options.query.trim() ||
              item.title.toLocaleLowerCase("en-US").includes(normalized),
          )
          .slice(0, MAX_CATALOG_RESULTS);

  const result: CatalogItem[] = [];
  for (const overview of matches) {
    result.push(projectCatalogItem(await getItem(options.client, vaultId, overview.id)));
  }
  return result;
}

export async function executeSecretReadMetadata(
  options: SecretTargetOptions,
): Promise<SecretReadMetadata> {
  assertExactKeys(options, ["client", "fieldId", "itemId", "vaultId"]);
  const target = validateSecretTarget(options);
  await assertVaultScope(options.client, target.vaultId);
  const item = await getItem(options.client, target.vaultId, target.itemId);
  const field = findField(item, target.fieldId);
  return projectSecretMetadata(item, target.fieldId, field);
}

export async function executeSecretRead(
  options: SecretReadOptions,
): Promise<SecretReadMetadata & { value: string }> {
  assertExactKeys(options, [
    "client",
    "expectedVersion",
    "fieldId",
    "itemId",
    "vaultId",
  ]);
  const target = validateSecretTarget(options);
  const expectedVersion = positiveVersion(options.expectedVersion);
  await assertVaultScope(options.client, target.vaultId);
  const item = await getItem(options.client, target.vaultId, target.itemId);
  if (item.version !== expectedVersion) {
    throw new GatewayOperationError("item_stale", 409);
  }
  const field = findField(item, target.fieldId);
  return {
    ...projectSecretMetadata(item, target.fieldId, field),
    value: field.value,
  };
}

export async function resolveSecret(
  options: SecretTargetOptions,
): Promise<string> {
  assertExactKeys(options, ["client", "fieldId", "itemId", "vaultId"]);
  const target = validateSecretTarget(options);
  await assertVaultScope(options.client, target.vaultId);
  const value = await invokeRead(
    options.client,
    {
      fieldId: target.fieldId,
      itemId: target.itemId,
      kind: "secret.resolve",
      vaultId: target.vaultId,
    },
    decodeResolvedSecret,
  );
  if (value.length > MAX_SECRET_VALUE_LENGTH) {
    throw new GatewayOperationError("onepassword_operation_failed", 502);
  }
  return value;
}

export async function executeSshSign(
  options: SshSignOptions,
): Promise<SshSignatureResult> {
  assertExactKeys(options, [
    "client",
    "data",
    "expectedFingerprint",
    "expectedVersion",
    "itemId",
    "requestedAlgorithm",
    "vaultId",
  ]);
  try {
    validateSshSigningData(options.data);
  } catch (error) {
    throw sshGatewayError(error);
  }
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  await assertVaultScope(options.client, vaultId);
  const item = await getItem(options.client, vaultId, itemId);
  let metadata;
  try {
    metadata = validateWireSshSignTarget({
      expectedFingerprint: options.expectedFingerprint,
      expectedVersion: options.expectedVersion,
      item,
      requestedAlgorithm: options.requestedAlgorithm,
    });
  } catch (error) {
    throw sshGatewayError(error);
  }
  const privateKey = await invokeRead(
    options.client,
    {
      fieldId: metadata.field_id,
      itemId,
      kind: "ssh.private-key.resolve",
      vaultId,
    },
    decodeResolvedSecret,
  );
  try {
    return signWireSshData({
      data: options.data,
      expectedFingerprint: options.expectedFingerprint,
      expectedVersion: options.expectedVersion,
      item,
      privateKey,
      requestedAlgorithm: options.requestedAlgorithm,
    });
  } catch (error) {
    throw sshGatewayError(error);
  }
}

export async function executeItemMetadata(
  options: Omit<SecretTargetOptions, "fieldId">,
): Promise<CatalogItem> {
  assertExactKeys(options, ["client", "itemId", "vaultId"]);
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  await assertVaultScope(options.client, vaultId);
  return projectCatalogItem(await getItem(options.client, vaultId, itemId));
}

export async function executeItemCreate(
  options: ItemCreateOptions,
): Promise<ItemMutationResult> {
  assertExactKeys(options, ["category", "client", "fields", "requestId", "title", "vaultId"]);
  const vaultId = itemIdentifier(options.vaultId);
  const category = writableCategory(options.category);
  const fields = validateWritableFields(options.fields, category);
  const requestId = identifier(options.requestId);
  const title = text(options.title, 256);
  await assertVaultScope(options.client, vaultId);

  const params: WireItemCreateParams = {
    category,
    fields: [
      ...fields.map((field) => ({
        fieldType: field.field_type,
        id: field.field_id,
        sectionId: USER_SECTION_ID,
        title: field.label,
        value: field.value,
      })),
      {
        fieldType: "Text",
        id: MARKER_FIELD_ID,
        sectionId: INTERNAL_SECTION_ID,
        title: "Gateway request ID",
        value: requestId,
      },
    ],
    notes: "",
    sections: [
      { id: USER_SECTION_ID, title: "Agent fields" },
      { id: INTERNAL_SECTION_ID, title: "OneNod" },
    ],
    tags: ["onenod", requestMarkerTag(requestId)],
    title,
    vaultId,
  };
  const created = await invokeWrite(
    options.client,
    { kind: "item.create.raw", params },
    decodeItem,
  );
  if (created.vaultId !== vaultId || created.title !== title) {
    throw unknownWriteFailure();
  }
  return { item_id: created.id, version: created.version };
}

export async function executeItemPatch(
  options: ItemPatchOptions,
): Promise<ItemMutationResult> {
  assertExactKeys(options, [
    "client",
    "expectedVersion",
    "itemId",
    "operations",
    "vaultId",
  ]);
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  const expectedVersion = positiveVersion(options.expectedVersion);
  const operations = validatePatchOperations(options.operations);
  await assertVaultScope(options.client, vaultId);
  const item = await getItem(options.client, vaultId, itemId);
  if (item.version !== expectedVersion) {
    throw new GatewayOperationError("item_stale", 409);
  }
  if (item.category === "SshKey") {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  applyPatch(item, operations);
  const updated = await invokeWrite(
    options.client,
    { item, kind: "item.put" },
    decodeItem,
  );
  if (
    updated.id !== itemId ||
    updated.vaultId !== vaultId ||
    updated.version <= expectedVersion
  ) {
    throw unknownWriteFailure();
  }
  return { item_id: updated.id, version: updated.version };
}

export async function executeItemArchive(
  options: ItemArchiveOptions,
): Promise<ItemMutationResult> {
  assertExactKeys(options, ["client", "expectedVersion", "itemId", "vaultId"]);
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  const expectedVersion = positiveVersion(options.expectedVersion);
  await assertVaultScope(options.client, vaultId);
  const item = await getItem(options.client, vaultId, itemId);
  if (item.version !== expectedVersion) {
    throw new GatewayOperationError("item_stale", 409);
  }
  await invokeWrite(
    options.client,
    { itemId, kind: "item.archive", vaultId },
    decodeVoid,
  );
  return { item_id: item.id, version: item.version };
}

export async function reconcileItemCreate(
  options: RawGatewayOptions & { requestId: string },
): Promise<ItemReconciliationResult> {
  assertExactKeys(options, ["client", "requestId", "vaultId"]);
  const vaultId = itemIdentifier(options.vaultId);
  const requestId = identifier(options.requestId);
  await assertVaultScope(options.client, vaultId);
  const overviews = await listItems(options.client, vaultId, true);
  const matches: WireItem[] = [];
  for (const overview of overviews.filter((item) =>
    item.tags.includes(requestMarkerTag(requestId)),
  )) {
    const item = await getItem(options.client, vaultId, overview.id);
    if (
      item.fields.some(
        (field) => field.id === MARKER_FIELD_ID && field.value === requestId,
      )
    ) {
      matches.push(item);
    }
  }
  if (matches.length === 0) return { reconciliation: "NOT_APPLIED" };
  if (matches.length !== 1) return { reconciliation: "AMBIGUOUS" };
  return {
    item_id: matches[0]!.id,
    reconciliation: "APPLIED",
    version: matches[0]!.version,
  };
}

export async function reconcileItemPatch(
  options: ItemPatchOptions,
): Promise<ItemReconciliationResult> {
  assertExactKeys(options, [
    "client",
    "expectedVersion",
    "itemId",
    "operations",
    "vaultId",
  ]);
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  const expectedVersion = positiveVersion(options.expectedVersion);
  const operations = validatePatchOperations(options.operations);
  await assertVaultScope(options.client, vaultId);
  const item = await getItem(options.client, vaultId, itemId);
  if (item.version === expectedVersion) {
    return { item_id: item.id, reconciliation: "NOT_APPLIED", version: item.version };
  }
  if (item.version > expectedVersion && patchMatches(item, operations)) {
    return { item_id: item.id, reconciliation: "APPLIED", version: item.version };
  }
  return { item_id: item.id, reconciliation: "AMBIGUOUS", version: item.version };
}

export async function reconcileItemArchive(
  options: ItemArchiveOptions,
): Promise<ItemReconciliationResult> {
  assertExactKeys(options, ["client", "expectedVersion", "itemId", "vaultId"]);
  const vaultId = itemIdentifier(options.vaultId);
  const itemId = itemIdentifier(options.itemId);
  const expectedVersion = positiveVersion(options.expectedVersion);
  await assertVaultScope(options.client, vaultId);
  const overviews = await listItems(options.client, vaultId, true);
  const overview = overviews.find((item) => item.id === itemId);
  if (!overview) return { item_id: itemId, reconciliation: "AMBIGUOUS" };
  if (overview.state === "archived") {
    return { item_id: itemId, reconciliation: "APPLIED" };
  }
  const item = await getItem(options.client, vaultId, itemId);
  return {
    item_id: item.id,
    reconciliation:
      item.version === expectedVersion ? "NOT_APPLIED" : "AMBIGUOUS",
    version: item.version,
  };
}

async function assertVaultScope(
  client: OnePasswordCoreClient,
  vaultId: string,
): Promise<void> {
  const vaults = await invokeRead(client, { kind: "vault.list" }, decodeVaultList);
  if (vaults.length !== 1 || vaults[0]?.id !== vaultId) {
    throw new GatewayOperationError("vault_scope_mismatch", 502);
  }
}

async function listItems(
  client: OnePasswordCoreClient,
  vaultId: string,
  includeArchived: boolean,
): Promise<WireDetailedItemOverview[]> {
  const items = await invokeRead(
    client,
    { includeArchived, kind: "item.list", vaultId },
    decodeDetailedItemList,
  );
  if (items.some((item) => item.vaultId !== vaultId)) {
    throw new GatewayOperationError("vault_scope_mismatch", 502);
  }
  return items;
}

async function getItem(
  client: OnePasswordCoreClient,
  vaultId: string,
  itemId: string,
): Promise<WireItem> {
  const item = await invokeRead(
    client,
    { itemId, kind: "item.get", vaultId },
    decodeItem,
  );
  if (item.id !== itemId || item.vaultId !== vaultId) {
    throw new GatewayOperationError("vault_scope_mismatch", 502);
  }
  return item;
}

async function invokeRead<T>(
  client: OnePasswordCoreClient,
  operation: OnePasswordOperation,
  decode: (value: Uint8Array) => T,
): Promise<T> {
  try {
    return decode(await client.invoke(operation));
  } catch (error) {
    if (error instanceof GatewayOperationError) throw error;
    if (isTimeoutError(error)) {
      throw new GatewayOperationError("onepassword_timeout", 504);
    }
    throw new GatewayOperationError("onepassword_operation_failed", 502);
  }
}

async function invokeWrite<T>(
  client: OnePasswordCoreClient,
  operation: OnePasswordOperation,
  decode: (value: Uint8Array) => T,
): Promise<T> {
  try {
    return decode(await client.invoke(operation));
  } catch (error) {
    if (
      error instanceof CoreAdapterError &&
      error.code === "invalid_operation_input"
    ) {
      throw new GatewayOperationError("item_operation_invalid", 400);
    }
    throw unknownWriteFailure(isTimeoutError(error) ? 504 : 502);
  }
}

function projectCatalogItem(item: WireItem): CatalogItem {
  const fields: CatalogField[] = item.fields.map((field) => ({
    field_id: field.id,
    field_type: field.fieldType,
    label: field.title,
  }));
  if (item.notes.length > 0) {
    fields.push({ field_id: NOTES_FIELD_ID, field_type: "Notes", label: "notes" });
  }
  let ssh;
  try {
    ssh = projectWireSshKeyMetadata(item);
  } catch (error) {
    throw sshGatewayError(error);
  }
  return {
    category: item.category,
    fields,
    item_id: item.id,
    ...(ssh
      ? {
          ssh: {
            algorithm: ssh.algorithm,
            fingerprint: ssh.fingerprint,
            public_key: ssh.public_key,
            public_key_blob: ssh.public_key_blob,
          },
        }
      : {}),
    title: item.title,
    updated_at: item.updatedAt,
    version: item.version,
  };
}

function sshGatewayError(error: unknown): GatewayOperationError {
  if (!(error instanceof SshSignerError)) {
    return new GatewayOperationError("ssh_sign_failed", 502);
  }
  switch (error.code) {
    case "item_stale":
      return new GatewayOperationError(error.code, 409);
    case "ssh_key_mismatch":
      return new GatewayOperationError(error.code, 409);
    case "ssh_algorithm_mismatch":
    case "ssh_algorithm_unsupported":
    case "ssh_sign_request_invalid":
      return new GatewayOperationError(error.code, 400);
    case "ssh_key_invalid":
    case "ssh_sign_failed":
      return new GatewayOperationError(error.code, 502);
  }
}

function findField(
  item: WireItem,
  fieldId: string,
): { label: string; type: string; value: string } {
  if (fieldId === NOTES_FIELD_ID && item.notes.length > 0) {
    return { label: "notes", type: "Notes", value: item.notes };
  }
  const field = item.fields.find((candidate) => candidate.id === fieldId);
  if (!field) throw new GatewayOperationError("field_not_found", 404);
  return { label: field.title, type: field.fieldType, value: field.value };
}

function projectSecretMetadata(
  item: WireItem,
  fieldId: string,
  field: { label: string; type: string },
): SecretReadMetadata {
  return {
    field_id: fieldId,
    field_label: field.label,
    field_type: field.type,
    item_id: item.id,
    item_title: item.title,
    version: item.version,
  };
}

function applyPatch(item: WireItem, operations: ItemPatchOperation[]): void {
  for (const operation of operations) {
    const index = item.fields.findIndex((field) => field.id === operation.field_id);
    if (operation.op === "add") {
      if (index !== -1) throw new GatewayOperationError("item_operation_invalid", 400);
      if (!item.sections.some((section) => section.id === USER_SECTION_ID)) {
        item.sections.push({ id: USER_SECTION_ID, title: "Agent fields" });
      }
      item.fields.push({
        fieldType: operation.field_type,
        id: operation.field_id,
        sectionId: USER_SECTION_ID,
        title: operation.label,
        value: operation.value,
      });
      continue;
    }
    if (index === -1) throw new GatewayOperationError("field_not_found", 404);
    if (operation.op === "remove") {
      item.fields.splice(index, 1);
      continue;
    }
    item.fields[index] = { ...item.fields[index]!, value: operation.value };
  }
}

function patchMatches(item: WireItem, operations: ItemPatchOperation[]): boolean {
  return operations.every((operation) => {
    const field = item.fields.find((candidate) => candidate.id === operation.field_id);
    if (operation.op === "remove") return field === undefined;
    if (!field || field.value !== operation.value) return false;
    if (operation.op === "replace") return true;
    return field.title === operation.label && field.fieldType === operation.field_type;
  });
}

function validateSecretTarget(options: SecretTargetOptions): {
  fieldId: string;
  itemId: string;
  vaultId: string;
} {
  return {
    fieldId: identifier(options.fieldId),
    itemId: itemIdentifier(options.itemId),
    vaultId: itemIdentifier(options.vaultId),
  };
}

function validateWritableFields(
  fields: ItemCreateField[],
  category: WritableItemCategory,
): ItemCreateField[] {
  if (!Array.isArray(fields) || fields.length === 0 || fields.length > 32) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  const ids = new Set<string>();
  const validated = fields.map((field) => {
    assertExactKeys(field, ["field_id", "field_type", "label", "value"]);
    const fieldId = userFieldIdentifier(field.field_id);
    if (ids.has(fieldId)) throw new GatewayOperationError("item_operation_invalid", 400);
    ids.add(fieldId);
    return {
      field_id: fieldId,
      field_type: writableCreateFieldType(field.field_type),
      label: text(field.label, 128),
      value: secretValue(field.value),
    };
  });
  if (category === "SshKey") {
    if (
      validated.length !== 1 ||
      validated[0]?.field_id !== "private_key" ||
      validated[0].field_type !== "SshKey" ||
      validated[0].label !== "private key"
    ) {
      throw new GatewayOperationError("item_operation_invalid", 400);
    }
  } else if (validated.some((field) => field.field_type === "SshKey")) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return validated;
}

function validatePatchOperations(
  operations: ItemPatchOperation[],
): ItemPatchOperation[] {
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > 32) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  const ids = new Set<string>();
  return operations.map((operation) => {
    const fieldId = userFieldIdentifier(operation.field_id);
    if (ids.has(fieldId)) throw new GatewayOperationError("item_operation_invalid", 400);
    ids.add(fieldId);
    if (operation.op === "add") {
      assertExactKeys(operation, ["field_id", "field_type", "label", "op", "value"]);
      return {
        field_id: fieldId,
        field_type: writableFieldType(operation.field_type),
        label: text(operation.label, 128),
        op: "add",
        value: secretValue(operation.value),
      };
    }
    if (operation.op === "replace") {
      assertExactKeys(operation, ["field_id", "op", "value"]);
      return { field_id: fieldId, op: "replace", value: secretValue(operation.value) };
    }
    if (operation.op === "remove") {
      assertExactKeys(operation, ["field_id", "op"]);
      return { field_id: fieldId, op: "remove" };
    }
    throw new GatewayOperationError("item_operation_invalid", 400);
  });
}

function writableCategory(value: unknown): WritableItemCategory {
  if (
    value !== "ApiCredentials" &&
    value !== "Login" &&
    value !== "Password" &&
    value !== "SecureNote" &&
    value !== "SshKey"
  ) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value;
}

function writableCreateFieldType(value: unknown): WritableItemCreateFieldType {
  if (value === "SshKey") return value;
  return writableFieldType(value);
}

function writableFieldType(value: unknown): WritableItemFieldType {
  if (value !== "Concealed" && value !== "Email" && value !== "Text" && value !== "Url") {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value;
}

function itemIdentifier(value: unknown): string {
  if (typeof value !== "string" || !ITEM_ID_PATTERN.test(value)) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value;
}

function userFieldIdentifier(value: unknown): string {
  const fieldId = identifier(value);
  if (fieldId.startsWith(INTERNAL_NAMESPACE)) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return fieldId;
}

function identifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    hasForbiddenControl(value)
  ) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value;
}

function text(value: unknown, maximumLength: number): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    hasForbiddenControl(value)
  ) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value.normalize("NFC");
}

function secretValue(value: unknown): string {
  if (typeof value !== "string" || value.length > MAX_SECRET_VALUE_LENGTH) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value;
}

function positiveVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
  return value as number;
}

function assertExactKeys(value: object, expected: string[]): void {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new GatewayOperationError("item_operation_invalid", 400);
  }
}

function isTimeoutError(error: unknown): boolean {
  return (
    error instanceof CoreAdapterError &&
    (error.code === "operation_aborted" || error.code === "operation_deadline_exceeded")
  );
}

function unknownWriteFailure(status = 502): GatewayOperationError {
  return new GatewayOperationError("onepassword_write_outcome_unknown", status);
}

function requestMarkerTag(requestId: string): string {
  return `${MARKER_TAG_PREFIX}${identifier(requestId)}`;
}

function hasForbiddenControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}
