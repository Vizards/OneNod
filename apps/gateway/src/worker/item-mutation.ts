import type {
  ClientObservationRequest,
  ItemArchiveRequest,
  ItemCreateFieldRequest,
  ItemCreateRequest,
  ItemMutationRequest,
  ItemPatchOperationRequest,
  ItemPatchRequest,
  WritableItemCategory,
  WritableItemCreateFieldType,
  WritableItemFieldType,
} from "@onenod/protocol";

import type { CatalogExecutorItem } from "./gateway-envelope.js";

const INTERNAL_NAMESPACE = "com.github.vizards.onenod";
const MAX_SECRET_VALUE_LENGTH = 16 * 1_024;

export interface ItemMutationDescription {
  expectedVersion: number;
  fieldLabel: string;
  fieldType: string;
  itemId: string;
  itemTitle: string;
  summary: Array<{ label: string; value: string }>;
  targetLabel: string;
}

export function parseItemMutationRequest(value: unknown): ItemMutationRequest {
  const body = record(value);
  const action = body.action;
  if (action === "item.create") return parseItemCreate(body);
  if (action === "item.patch") return parseItemPatch(body);
  if (action === "item.archive") return parseItemArchive(body);
  throw new Error("unsupported_action");
}

export function describeItemMutation(
  body: ItemMutationRequest,
  metadata: CatalogExecutorItem | undefined,
  payloadDigest?: string,
): ItemMutationDescription {
  if (body.action === "item.create") {
    if (!payloadDigest) throw new Error("payload_digest_required");
    return {
      expectedVersion: 0,
      fieldLabel: `${body.fields.length} fields`,
      fieldType: "ItemCreate",
      itemId: "",
      itemTitle: body.title,
      summary: [
        { label: "Category", value: body.category },
        { label: "Title", value: body.title },
        ...body.fields.map((field) => ({
          label: `Add field · ${field.label}`,
          value: `${field.field_type} · ${field.field_id}`,
        })),
        { label: "Encrypted payload digest", value: payloadDigest },
      ],
      targetLabel: `Create ${body.title}`,
    };
  }
  if (!metadata || metadata.item_id !== body.item_id) {
    throw new Error("item_metadata_mismatch");
  }
  if (metadata.version !== body.expected_version) {
    throw new Error("item_stale");
  }
  if (body.action === "item.archive") {
    return {
      expectedVersion: body.expected_version,
      fieldLabel: "Archive item",
      fieldType: "ItemArchive",
      itemId: body.item_id,
      itemTitle: metadata.title,
      summary: [
        { label: "Item", value: metadata.title },
        { label: "Category", value: metadata.category },
        { label: "Version", value: String(metadata.version) },
      ],
      targetLabel: `Archive ${metadata.title}`,
    };
  }
  if (!payloadDigest) throw new Error("payload_digest_required");
  if (metadata.category === "SshKey") {
    throw new Error("ssh_key_patch_forbidden");
  }
  const fields = new Map(metadata.fields.map((field) => [field.field_id, field]));
  const operationFacts = body.operations.map((operation) => {
    const existing = fields.get(operation.field_id);
    if (operation.op === "add") {
      if (existing) throw new Error("field_already_exists");
      return {
        label: `Add field · ${operation.label}`,
        value: `${operation.field_type} · ${operation.field_id}`,
      };
    }
    if (!existing) throw new Error("field_not_found");
    return {
      label: `${operation.op === "replace" ? "Replace" : "Remove"} field · ${existing.label}`,
      value: `${existing.field_type} · ${operation.field_id}`,
    };
  });
  return {
    expectedVersion: body.expected_version,
    fieldLabel: `${body.operations.length} changes`,
    fieldType: "ItemPatch",
    itemId: body.item_id,
    itemTitle: metadata.title,
    summary: [
      { label: "Item", value: metadata.title },
      { label: "Version", value: String(metadata.version) },
      ...operationFacts,
      { label: "Encrypted payload digest", value: payloadDigest },
    ],
    targetLabel: `Update ${metadata.title}`,
  };
}

export function mutationExecutorBody(
  body: ItemMutationRequest,
  requestId: string,
): Record<string, unknown> {
  if (body.action === "item.create") {
    return {
      action: body.action,
      category: body.category,
      fields: body.fields,
      request_id: requestId,
      title: body.title,
    };
  }
  if (body.action === "item.patch") {
    return {
      action: body.action,
      expected_version: body.expected_version,
      item_id: body.item_id,
      operations: body.operations,
    };
  }
  return {
    action: body.action,
    expected_version: body.expected_version,
    item_id: body.item_id,
  };
}

function parseItemCreate(body: Record<string, unknown>): ItemCreateRequest {
  assertExactKeys(body, [
    "action",
    "category",
    "client",
    "fields",
    "idempotency_key",
    "title",
  ]);
  const category = writableCategory(body.category);
  const fields = body.fields;
  if (!Array.isArray(fields) || fields.length === 0 || fields.length > 32) {
    throw new Error("fields_invalid");
  }
  const parsedFields = fields.map(parseCreateField);
  assertUniqueSortedFieldIds(parsedFields.map((field) => field.field_id));
  assertCreateShape(category, parsedFields);
  return {
    action: "item.create",
    category,
    client: body.client as ClientObservationRequest,
    fields: parsedFields,
    idempotency_key: identifier(body.idempotency_key, "idempotency_key"),
    title: safeText(body.title, 256, "title"),
  };
}

function parseItemPatch(body: Record<string, unknown>): ItemPatchRequest {
  assertExactKeys(body, [
    "action",
    "client",
    "expected_version",
    "idempotency_key",
    "item_id",
    "operations",
  ]);
  const operations = body.operations;
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > 32) {
    throw new Error("operations_invalid");
  }
  const parsedOperations = operations.map(parsePatchOperation);
  assertUniqueSortedFieldIds(parsedOperations.map((operation) => operation.field_id));
  return {
    action: "item.patch",
    client: body.client as ClientObservationRequest,
    expected_version: positiveInteger(body.expected_version, "expected_version"),
    idempotency_key: identifier(body.idempotency_key, "idempotency_key"),
    item_id: identifier(body.item_id, "item_id"),
    operations: parsedOperations,
  };
}

function parseItemArchive(body: Record<string, unknown>): ItemArchiveRequest {
  assertExactKeys(body, [
    "action",
    "client",
    "expected_version",
    "idempotency_key",
    "item_id",
  ]);
  return {
    action: "item.archive",
    client: body.client as ClientObservationRequest,
    expected_version: positiveInteger(body.expected_version, "expected_version"),
    idempotency_key: identifier(body.idempotency_key, "idempotency_key"),
    item_id: identifier(body.item_id, "item_id"),
  };
}

function parseCreateField(value: unknown): ItemCreateFieldRequest {
  const field = record(value);
  assertExactKeys(field, ["field_id", "field_type", "label", "value"]);
  const fieldId = identifier(field.field_id, "field_id");
  assertUserFieldId(fieldId);
  return {
    field_id: fieldId,
    field_type: writableCreateFieldType(field.field_type),
    label: safeText(field.label, 128, "label"),
    value: secretValue(field.value),
  };
}

function parsePatchOperation(value: unknown): ItemPatchOperationRequest {
  const operation = record(value);
  const fieldId = identifier(operation.field_id, "field_id");
  assertUserFieldId(fieldId);
  if (operation.op === "add") {
    assertExactKeys(operation, ["field_id", "field_type", "label", "op", "value"]);
    return {
      field_id: fieldId,
      field_type: writableFieldType(operation.field_type),
      label: safeText(operation.label, 128, "label"),
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
  throw new Error("operation_invalid");
}

function writableCategory(value: unknown): WritableItemCategory {
  if (
    value !== "ApiCredentials" &&
    value !== "Login" &&
    value !== "Password" &&
    value !== "SecureNote" &&
    value !== "SshKey"
  ) {
    throw new Error("category_invalid");
  }
  return value;
}

function writableCreateFieldType(value: unknown): WritableItemCreateFieldType {
  if (value === "SshKey") return value;
  return writableFieldType(value);
}

function assertCreateShape(
  category: WritableItemCategory,
  fields: ItemCreateFieldRequest[],
): void {
  if (category === "SshKey") {
    if (
      fields.length !== 1 ||
      fields[0]?.field_id !== "private_key" ||
      fields[0].field_type !== "SshKey" ||
      fields[0].label !== "private key"
    ) {
      throw new Error("ssh_key_create_shape_invalid");
    }
    return;
  }
  if (fields.some((field) => field.field_type === "SshKey")) {
    throw new Error("ssh_key_create_shape_invalid");
  }
}

function writableFieldType(value: unknown): WritableItemFieldType {
  if (value !== "Concealed" && value !== "Email" && value !== "Text" && value !== "Url") {
    throw new Error("field_type_invalid");
  }
  return value;
}

function secretValue(value: unknown): string {
  if (typeof value !== "string" || value.length > MAX_SECRET_VALUE_LENGTH) {
    throw new Error("field_value_invalid");
  }
  return value;
}

function assertUserFieldId(value: string): void {
  if (value.startsWith(INTERNAL_NAMESPACE)) {
    throw new Error("internal_namespace_reserved");
  }
}

function assertUniqueSortedFieldIds(values: string[]): void {
  if (new Set(values).size !== values.length) throw new Error("field_id_duplicate");
  const sorted = [...values].sort();
  if (values.some((value, index) => value !== sorted[index])) {
    throw new Error("field_ids_not_sorted");
  }
}

function assertExactKeys(body: Record<string, unknown>, expected: string[]): void {
  const keys = Object.keys(body).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error("request_schema_invalid");
  }
}

function identifier(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    hasForbiddenControl(value)
  ) {
    throw new Error(`${name}_invalid`);
  }
  return value;
}

function positiveInteger(value: unknown, name: string): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new Error(`${name}_invalid`);
  }
  return value as number;
}

function safeText(value: unknown, maximumLength: number, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maximumLength ||
    hasForbiddenControl(value)
  ) {
    throw new Error(`${name}_invalid`);
  }
  return value.normalize("NFC");
}

function hasForbiddenControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("request_schema_invalid");
  }
  return value as Record<string, unknown>;
}
