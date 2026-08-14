import type {
  ApplicationIdentity,
  ApprovalAction,
  ApprovalStatus,
  RequestDetail,
  RequestSummary,
} from "@onenod/protocol";

import type {
  HumanManagement,
  HumanState,
  VerifiedApplicationIdentity,
} from "./api-types";

export function normalizeHumanState(value: unknown): HumanState {
  const record = asRecord(value);
  const bootstrapRequestId = readString(record, "bootstrap_request_id");
  const currentDeviceId = readString(record, "current_device_id");
  return {
    authenticated: readBoolean(record, "authenticated") ?? false,
    ...(bootstrapRequestId ? { bootstrapRequestId } : {}),
    initialized: readBoolean(record, "initialized") ?? false,
    ...(currentDeviceId ? { currentDeviceId } : {}),
    deviceTrusted: readBoolean(record, "device_trusted") ?? false,
    locked: readBoolean(record, "locked") ?? false,
  };
}

export function normalizeHumanManagement(value: unknown): HumanManagement {
  const record = asRecord(value);
  const credentials = arrayField(record, "credentials");
  const devices = arrayField(record, "devices");
  const requesters = arrayField(record, "requesters");
  const secretAuthorizations = arrayField(record, "secret_authorizations");
  const sshAuthorizations = arrayField(record, "ssh_authorizations");
  return {
    credentials: credentials.map((entry) => {
      const item = asRecord(entry);
      const lastUsedAt = readString(item, "last_used_at");
      return {
        backedUp: readBoolean(item, "backed_up") ?? false,
        createdAt: readRequiredString(item, "created_at"),
        current: readBoolean(item, "current") ?? false,
        deviceType: readRequiredString(item, "device_type"),
        id: readRequiredString(item, "id"),
        label: readRequiredString(item, "label"),
        ...(lastUsedAt ? { lastUsedAt } : {}),
      };
    }),
    devices: devices.map((entry) => {
      const item = asRecord(entry);
      return {
        createdAt: readRequiredString(item, "created_at"),
        current: readBoolean(item, "current") ?? false,
        id: readRequiredString(item, "id"),
        label: readRequiredString(item, "label"),
        lastSeenAt: readRequiredString(item, "last_seen_at"),
        platform: readRequiredString(item, "platform"),
        pushEnabled: readBoolean(item, "push_enabled") ?? false,
      };
    }),
    requesters: requesters.map((entry) => {
      const item = asRecord(entry);
      return {
        createdAt: readRequiredString(item, "created_at"),
        deviceId: readRequiredString(item, "device_id"),
        displayName: readRequiredString(item, "display_name"),
        publicKeyFingerprint: readRequiredString(item, "public_key_fingerprint"),
      };
    }),
    serverTime: readRequiredString(record, "server_time"),
    secretAuthorizations: secretAuthorizations.map((entry) => {
      const item = asRecord(entry);
      const duration = readRequiredString(item, "duration");
      if (
        duration !== "until-lock" &&
        duration !== "4-hours" &&
        duration !== "12-hours" &&
        duration !== "24-hours"
      ) {
        throw new Error("The server returned an unknown secret authorization duration.");
      }
      const expiresAt = readString(item, "expires_at");
      return {
        application: readRequiredString(item, "client_application"),
        applicationIdentity: readVerifiedApplicationIdentity(item.application_identity),
        createdAt: readRequiredString(item, "created_at"),
        duration,
        ...(expiresAt ? { expiresAt } : {}),
        fieldId: readRequiredString(item, "field_id"),
        fieldLabel: readRequiredString(item, "field_label"),
        fieldType: readRequiredString(item, "field_type"),
        id: readRequiredString(item, "id"),
        itemId: readRequiredString(item, "item_id"),
        itemTitle: readRequiredString(item, "item_title"),
        itemVersion: readRequiredNumber(item, "item_version"),
        requesterDeviceId: readRequiredString(item, "requester_device_id"),
        useCount: readRequiredNumber(item, "use_count"),
      };
    }),
    sshAuthorizations: sshAuthorizations.map((entry) => {
      const item = asRecord(entry);
      const scopeKind = readRequiredString(item, "scope_kind");
      if (scopeKind !== "application") {
        throw new Error("The server returned an unknown SSH authorization scope.");
      }
      const duration = readRequiredString(item, "duration");
      if (
        duration !== "until-lock" &&
        duration !== "until-agent-quits" &&
        duration !== "4-hours" &&
        duration !== "12-hours" &&
        duration !== "24-hours"
      ) {
        throw new Error("The server returned an unknown SSH authorization duration.");
      }
      const expiresAt = readString(item, "expires_at");
      return {
        application: readRequiredString(item, "client_application"),
        applicationIdentity: readVerifiedApplicationIdentity(item.application_identity),
        createdAt: readRequiredString(item, "created_at"),
        duration,
        ...(expiresAt ? { expiresAt } : {}),
        fingerprint: readRequiredString(item, "fingerprint"),
        id: readRequiredString(item, "id"),
        itemId: readRequiredString(item, "item_id"),
        itemTitle: readRequiredString(item, "item_title"),
        itemVersion: readRequiredNumber(item, "item_version"),
        requesterDeviceId: readRequiredString(item, "requester_device_id"),
        scopeKind,
        useCount: readRequiredNumber(item, "use_count"),
      };
    }),
  };
}

export function normalizeRequestSummary(value: unknown): RequestSummary {
  const record = asRecord(value);
  const client = asRecord(record.client);
  const source = readRequiredString(client, "source");
  if (source !== "process-ancestry" && source !== "unavailable") {
    throw new Error("The server returned an unknown client observation source.");
  }
  return {
    action: readRequiredString(record, "action") as ApprovalAction,
    applicationRecognition: readApplicationRecognition(record),
    ...(isRecord(record.authorization_scope)
      ? {
          authorizationScope: {
            kind: readAuthorizationScopeKind(record.authorization_scope),
            resource: readAuthorizationResource(record.authorization_scope),
          },
        }
      : {}),
    client: {
      application: readRequiredString(client, "application"),
      identity: readApplicationIdentity(client.identity),
      source,
    },
    createdAt: readRequiredString(record, "created_at"),
    expiresAt: readRequiredString(record, "expires_at"),
    requestId: readRequiredString(record, "request_id"),
    requesterName: readRequiredString(record, "requester_name"),
    status: readRequiredString(record, "status") as ApprovalStatus,
    targetLabel: readRequiredString(record, "target_label"),
    verifiedVersion: readRequiredNumber(record, "verified_version"),
  };
}

function readApplicationRecognition(
  record: Record<string, unknown>,
): "approved-before" | "first-approval" | "unverified" {
  const recognition = readRequiredString(record, "application_recognition");
  if (
    recognition !== "approved-before" &&
    recognition !== "first-approval" &&
    recognition !== "unverified"
  ) {
    throw new Error("The server returned an unknown application recognition state.");
  }
  return recognition;
}

export function normalizeRequestDetail(value: unknown): RequestDetail {
  const record = asRecord(value);
  const facts = Array.isArray(record.verified_facts) ? record.verified_facts : [];
  return {
    ...normalizeRequestSummary(record),
    verifiedFacts: facts.map((fact) => {
      const factRecord = asRecord(fact);
      return {
        label: readRequiredString(factRecord, "label"),
        value: readRequiredString(factRecord, "value"),
      };
    }),
  };
}

function readApplicationIdentity(value: unknown): ApplicationIdentity {
  if (!isRecord(value)) {
    return { assurance: "unverified", platform: "unsupported" };
  }
  const assurance = readRequiredString(value, "assurance");
  const platform = readRequiredString(value, "platform");
  if (assurance === "unverified") {
    if (platform !== "macos" && platform !== "unsupported") {
      throw new Error("The server returned an unknown application platform.");
    }
    return { assurance, platform };
  }
  if (
    assurance !== "verified-code-signature" ||
    platform !== "macos" ||
    readRequiredString(value, "principal_scheme") !==
      "macos-designated-requirement-v1"
  ) {
    throw new Error("The server returned an unknown application identity.");
  }
  const signerName = readString(value, "signer_name");
  const teamIdentifier = readString(value, "team_identifier");
  return {
    assurance,
    platform,
    principalId: readRequiredString(value, "principal_id"),
    principalScheme: "macos-designated-requirement-v1",
    ...(signerName ? { signerName } : {}),
    signingIdentifier: readRequiredString(value, "signing_identifier"),
    ...(teamIdentifier ? { teamIdentifier } : {}),
  };
}

function readVerifiedApplicationIdentity(value: unknown): VerifiedApplicationIdentity {
  const identity = readApplicationIdentity(value);
  if (identity.assurance !== "verified-code-signature") {
    throw new Error("The server returned an unverified remembered authorization.");
  }
  return identity;
}

function readAuthorizationScopeKind(value: Record<string, unknown>): "application" {
  const kind = readRequiredString(value, "scope_kind");
  if (kind !== "application") {
    throw new Error("The server returned an unknown authorization scope.");
  }
  return kind;
}

function readAuthorizationResource(value: Record<string, unknown>): "secret" | "ssh" {
  const resource = readRequiredString(value, "resource");
  if (resource !== "secret" && resource !== "ssh") {
    throw new Error("The server returned an unknown authorization resource.");
  }
  return resource;
}

function arrayField(record: Record<string, unknown>, key: string): unknown[] {
  const value = record[key];
  return Array.isArray(value) ? value : [];
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) throw new Error("The server returned unrecognized data.");
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readRequiredString(record: Record<string, unknown>, key: string): string {
  const value = readString(record, key);
  if (value === undefined) throw new Error(`Server response is missing field: ${key}`);
  return value;
}

function readRequiredNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value === "number" && Number.isFinite(value)) return value;
  throw new Error(`Server response is missing numeric field: ${key}`);
}

function readString(
  record: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  if (!record) return undefined;
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function readBoolean(
  record: Record<string, unknown> | undefined,
  key: string,
): boolean | undefined {
  if (!record) return undefined;
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}
