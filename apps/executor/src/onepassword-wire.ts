import { EXECUTOR_RELEASE } from "./release";

const MAX_WIRE_BYTES = 512 * 1024;
const MAX_COLLECTION_LENGTH = 1_000;
const MAX_ITEM_FIELDS = 256;
const MAX_ITEM_SECTIONS = 128;
const MAX_ITEM_TAGS = 128;
const ITEM_ID_PATTERN = /^[a-z0-9]{20,64}$/;
const CLIENT_ID_PATTERN = /^(0|[1-9][0-9]{0,19})$/;
const UINT64_MAX = 18_446_744_073_709_551_615n;
const SERVICE_ACCOUNT_TOKEN_PATTERN = /^ops_[A-Za-z0-9_-]{32,4092}$/;
const FATAL_DECODER = new TextDecoder("utf-8", { fatal: true });
const ENCODER = new TextEncoder();

declare const clientIdBrand: unique symbol;
export type ClientIdJson = string & { readonly [clientIdBrand]: true };

export interface WireItemField extends Record<string, unknown> {
  fieldType: string;
  id: string;
  sectionId?: string;
  title: string;
  value: string;
}

export interface WireItemSection extends Record<string, unknown> {
  id: string;
  title: string;
}

export interface WireItemCreateParams {
  category: string;
  fields: WireItemField[];
  notes?: string;
  sections: WireItemSection[];
  tags?: string[];
  title: string;
  vaultId: string;
  websites?: unknown[];
}

export type OnePasswordOperation =
  | { kind: "vault.list" }
  | { includeArchived?: boolean; kind: "item.list"; vaultId: string }
  | { kind: "item.create.raw"; params: WireItemCreateParams }
  | { kind: "item.get"; vaultId: string; itemId: string }
  | { kind: "item.put"; item: WireItem }
  | { kind: "item.archive"; vaultId: string; itemId: string }
  | {
      fieldId: string;
      kind: "ssh.private-key.resolve";
      vaultId: string;
      itemId: string;
    }
  | { fieldId: string; kind: "secret.resolve"; vaultId: string; itemId: string };

export interface WireItem extends Record<string, unknown> {
  category: string;
  createdAt: string;
  fields: WireItemField[];
  files: unknown[];
  id: string;
  notes: string;
  sections: WireItemSection[];
  tags: string[];
  title: string;
  updatedAt: string;
  vaultId: string;
  version: number;
  websites: unknown[];
}

export interface WireItemOverview {
  id: string;
  title: string;
  vaultId: string;
}

export interface WireDetailedItemOverview extends WireItemOverview {
  category: string;
  state: "active" | "archived";
  tags: string[];
  updatedAt: string;
}

export interface WireVaultOverview {
  id: string;
  title: string;
}

export class WireCodecError extends Error {
  readonly code = "invalid_core_response";

  constructor() {
    super("invalid_core_response");
    this.name = "WireCodecError";
  }
}

export function encodeClientConfig(serviceAccountToken: string): Uint8Array {
  validateServiceAccountToken(serviceAccountToken);

  return encodeJson({
    serviceAccountToken,
    programmingLanguage: "JS",
    sdkVersion: "0040101",
    integrationName: "onenod",
    integrationVersion: EXECUTOR_RELEASE.version,
    requestLibraryName: "Fetch API",
    requestLibraryVersion: "workerd",
    os: "linux",
    osVersion: "0.0.0",
    architecture: "wasm32",
    account_name: null,
  });
}

export function validateServiceAccountToken(serviceAccountToken: string): void {
  if (!SERVICE_ACCOUNT_TOKEN_PATTERN.test(serviceAccountToken)) {
    throw new WireCodecError();
  }
}

export function decodeClientId(output: Uint8Array): ClientIdJson {
  const value = decodeText(output);
  if (!CLIENT_ID_PATTERN.test(value) || BigInt(value) > UINT64_MAX) {
    throw new WireCodecError();
  }
  return value as ClientIdJson;
}

export function encodeClientId(clientId: ClientIdJson): Uint8Array {
  validateClientId(clientId);
  return ENCODER.encode(clientId);
}

export function encodeInvocation(
  clientId: ClientIdJson,
  operation: OnePasswordOperation,
): Uint8Array {
  validateClientId(clientId);
  const { name, parameters } = operationParameters(operation);
  const encodedParameters = JSON.stringify({ name, parameters });
  return encodeText(
    `{"invocation":{"clientId":${clientId},"parameters":${encodedParameters}}}`,
  );
}

export function decodeVaultList(output: Uint8Array): WireVaultOverview[] {
  return decodeCollection(output, (value) => {
    const record = requireRecord(value);
    return {
      id: requireIdentifier(record.id),
      title: requireString(record.title, 256),
    };
  });
}

export function decodeItemList(output: Uint8Array): WireItemOverview[] {
  return decodeCollection(output, (value) => {
    const record = requireRecord(value);
    return {
      id: requireIdentifier(record.id),
      title: requireString(record.title, 256),
      vaultId: requireIdentifier(record.vaultId),
    };
  });
}

export function decodeDetailedItemList(
  output: Uint8Array,
): WireDetailedItemOverview[] {
  return decodeCollection(output, (value) => {
    const record = requireRecord(value);
    const state = record.state;
    if (state !== "active" && state !== "archived") {
      throw new WireCodecError();
    }
    return {
      category: requireKnownCategory(record.category),
      id: requireIdentifier(record.id),
      state,
      tags: requireStringArray(record.tags, MAX_ITEM_TAGS, 128),
      title: requireString(record.title, 256),
      updatedAt: requireTimestamp(record.updatedAt),
      vaultId: requireIdentifier(record.vaultId),
    };
  });
}

export function decodeItem(output: Uint8Array): WireItem {
  const record = requireRecord(decodeJson(output));
  return {
    ...record,
    category: requireKnownCategory(record.category),
    createdAt: requireTimestamp(record.createdAt),
    fields: requireBoundedArray(record.fields, MAX_ITEM_FIELDS).map(decodeItemField),
    files: requireBoundedArray(record.files, MAX_ITEM_FIELDS),
    id: requireIdentifier(record.id),
    notes: requireString(record.notes, 64 * 1024),
    sections: decodeItemSections(record.sections),
    tags: requireStringArray(record.tags, MAX_ITEM_TAGS, 128),
    title: requireString(record.title, 256),
    updatedAt: requireTimestamp(record.updatedAt),
    vaultId: requireIdentifier(record.vaultId),
    version: requireVersion(record.version),
    websites: requireBoundedArray(record.websites, MAX_ITEM_FIELDS),
  };
}

export function decodeResolvedSecret(output: Uint8Array): string {
  const value = decodeJson(output);
  return requireString(value, 64 * 1024);
}

export function decodeVoid(output: Uint8Array): void {
  if (decodeJson(output) !== null) throw new WireCodecError();
}

function operationParameters(operation: OnePasswordOperation): {
  name: string;
  parameters: Record<string, unknown>;
} {
  switch (operation.kind) {
    case "vault.list":
      return { name: "VaultsList", parameters: { params: null } };
    case "item.list":
      return {
        name: "ItemsList",
        parameters: {
          vault_id: requireIdentifier(operation.vaultId),
          filters: operation.includeArchived
            ? [
                {
                  content: { active: true, archived: true },
                  type: "ByState",
                },
              ]
            : [],
        },
      };
    case "item.create.raw":
      return {
        name: "ItemsCreate",
        parameters: { params: validateCreateParams(operation.params) },
      };
    case "item.get":
      return {
        name: "ItemsGet",
        parameters: {
          vault_id: requireIdentifier(operation.vaultId),
          item_id: requireIdentifier(operation.itemId),
        },
      };
    case "item.put":
      validateWireItem(operation.item);
      return { name: "ItemsPut", parameters: { item: operation.item } };
    case "item.archive":
      return {
        name: "ItemsArchive",
        parameters: {
          vault_id: requireIdentifier(operation.vaultId),
          item_id: requireIdentifier(operation.itemId),
        },
      };
    case "secret.resolve":
      return {
        name: "SecretsResolve",
        parameters: {
          secret_reference: `op://${requireIdentifier(operation.vaultId)}/${requireIdentifier(operation.itemId)}/${encodeURIComponent(requireFieldIdentifier(operation.fieldId))}`,
        },
      };
    case "ssh.private-key.resolve":
      return {
        name: "SecretsResolve",
        parameters: {
          secret_reference: `op://${requireIdentifier(operation.vaultId)}/${requireIdentifier(operation.itemId)}/${encodeURIComponent(requireFieldIdentifier(operation.fieldId))}?ssh-format=openssh`,
        },
      };
  }
}

function validateWireItem(item: WireItem): void {
  requireKnownCategory(item.category);
  requireTimestamp(item.createdAt);
  requireBoundedArray(item.fields, MAX_ITEM_FIELDS).forEach(decodeItemField);
  requireBoundedArray(item.files, MAX_ITEM_FIELDS);
  requireIdentifier(item.id);
  requireString(item.notes, 64 * 1024);
  requireBoundedArray(item.sections, MAX_ITEM_SECTIONS).forEach(decodeItemSection);
  requireStringArray(item.tags, MAX_ITEM_TAGS, 128);
  requireIdentifier(item.vaultId);
  requireString(item.title, 256);
  requireTimestamp(item.updatedAt);
  requireVersion(item.version);
  requireBoundedArray(item.websites, MAX_ITEM_FIELDS);
}

function validateCreateParams(params: WireItemCreateParams): WireItemCreateParams {
  const category = requireKnownCategory(params.category);
  const fields = requireBoundedArray(params.fields, MAX_ITEM_FIELDS).map(decodeItemField);
  const sections = requireBoundedArray(params.sections, MAX_ITEM_SECTIONS).map(
    decodeItemSection,
  );
  return {
    category,
    fields,
    ...(params.notes === undefined
      ? {}
      : { notes: requireString(params.notes, 64 * 1024) }),
    sections,
    ...(params.tags === undefined
      ? {}
      : { tags: requireStringArray(params.tags, MAX_ITEM_TAGS, 128) }),
    title: requireString(params.title, 256),
    vaultId: requireIdentifier(params.vaultId),
    ...(params.websites === undefined
      ? {}
      : { websites: requireBoundedArray(params.websites, MAX_ITEM_FIELDS) }),
  };
}

function encodeJson(value: unknown): Uint8Array {
  return encodeText(JSON.stringify(value));
}

function decodeJson(output: Uint8Array): unknown {
  try {
    return JSON.parse(decodeText(output)) as unknown;
  } catch {
    throw new WireCodecError();
  }
}

function decodeCollection<T>(output: Uint8Array, decode: (value: unknown) => T): T[] {
  const values = requireArray(decodeJson(output));
  if (values.length > MAX_COLLECTION_LENGTH) {
    throw new WireCodecError();
  }
  return values.map(decode);
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new WireCodecError();
  }
  return value as Record<string, unknown>;
}

function requireArray(value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new WireCodecError();
  }
  return value;
}

function requireBoundedArray(value: unknown, maximumLength: number): unknown[] {
  const result = requireArray(value);
  if (result.length > maximumLength) throw new WireCodecError();
  return result;
}

function requireStringArray(
  value: unknown,
  maximumLength: number,
  maximumValueLength: number,
): string[] {
  return requireBoundedArray(value, maximumLength).map((entry) =>
    requireString(entry, maximumValueLength),
  );
}

function requireIdentifier(value: unknown): string {
  if (typeof value !== "string" || !ITEM_ID_PATTERN.test(value)) {
    throw new WireCodecError();
  }
  return value;
}

function requireFieldIdentifier(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 256 ||
    hasForbiddenControl(value)
  ) {
    throw new WireCodecError();
  }
  return value;
}

function requireString(value: unknown, maximumLength: number): string {
  if (typeof value !== "string" || value.length > maximumLength) {
    throw new WireCodecError();
  }
  return value;
}

function requireVersion(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new WireCodecError();
  }
  return value;
}

function requireTimestamp(value: unknown): string {
  const timestamp = requireString(value, 64);
  if (!Number.isFinite(Date.parse(timestamp))) throw new WireCodecError();
  return timestamp;
}

function requireKnownCategory(value: unknown): string {
  const category = requireString(value, 64);
  if (!KNOWN_ITEM_CATEGORIES.has(category)) throw new WireCodecError();
  return category;
}

function decodeItemField(value: unknown): WireItemField {
  const field = requireRecord(value);
  const { sectionId, ...fieldWithoutSectionId } = field;
  const fieldType = requireString(field.fieldType, 64);
  if (!KNOWN_FIELD_TYPES.has(fieldType)) throw new WireCodecError();
  return {
    ...fieldWithoutSectionId,
    fieldType,
    id: requireFieldIdentifier(field.id),
    ...(sectionId === undefined || sectionId === null || sectionId === ""
      ? {}
      : { sectionId: requireFieldIdentifier(sectionId) }),
    title: requireString(field.title, 256),
    value: requireString(field.value, 64 * 1024),
  };
}

function decodeItemSection(value: unknown): WireItemSection {
  const section = requireRecord(value);
  return {
    ...section,
    id: requireFieldIdentifier(section.id),
    title: requireString(section.title, 256),
  };
}

function decodeItemSections(value: unknown): WireItemSection[] {
  return requireBoundedArray(value, MAX_ITEM_SECTIONS).flatMap((entry) => {
    const section = requireRecord(entry);
    if (section.id === "" && section.title === "") return [];
    return [decodeItemSection(section)];
  });
}

function validateClientId(clientId: string): asserts clientId is ClientIdJson {
  if (!CLIENT_ID_PATTERN.test(clientId) || BigInt(clientId) > UINT64_MAX) {
    throw new WireCodecError();
  }
}

function encodeText(value: string): Uint8Array {
  const encoded = ENCODER.encode(value);
  if (encoded.byteLength > MAX_WIRE_BYTES) {
    throw new WireCodecError();
  }
  return encoded;
}

function decodeText(output: Uint8Array): string {
  if (output.byteLength === 0 || output.byteLength > MAX_WIRE_BYTES) {
    throw new WireCodecError();
  }
  try {
    return FATAL_DECODER.decode(output);
  } catch {
    throw new WireCodecError();
  }
}

function hasForbiddenControl(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint < 0x20 || codePoint === 0x7f) return true;
  }
  return false;
}

const KNOWN_ITEM_CATEGORIES = new Set([
  "ApiCredentials",
  "BankAccount",
  "CreditCard",
  "CryptoWallet",
  "Database",
  "Document",
  "DriverLicense",
  "Email",
  "Identity",
  "Login",
  "MedicalRecord",
  "Membership",
  "OutdoorLicense",
  "Passport",
  "Password",
  "Person",
  "Rewards",
  "Router",
  "SecureNote",
  "Server",
  "SocialSecurityNumber",
  "SoftwareLicense",
  "SshKey",
  "Unsupported",
]);

const KNOWN_FIELD_TYPES = new Set([
  "Address",
  "Concealed",
  "CreditCardNumber",
  "CreditCardType",
  "Date",
  "Email",
  "Menu",
  "MonthYear",
  "Phone",
  "Reference",
  "SshKey",
  "Text",
  "Totp",
  "Unsupported",
  "Url",
]);
