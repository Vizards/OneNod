import { projectStoredApplicationIdentity } from "./application-identity.js";
import { projectApplicationRecognition } from "./approved-application-identities.js";
import type {
  EnrollmentRow,
  RequestActivityRow,
  RequestOperationRow,
  RequestRow,
  RequestState,
  SecretAuthorizationGrantRow,
  SshAuthorizationGrantRow,
} from "./approval-types.js";

export function projectEnrollment(row: EnrollmentRow) {
  return {
    created_at: iso(row.created_at),
    device_id: row.device_id,
    display_name: row.display_name,
    expires_at: iso(row.expires_at),
    id: row.id,
    public_key_fingerprint: row.public_key_fingerprint,
    status: row.status,
  };
}

export function projectRequesterStatus(
  row: RequestRow,
  operation?: RequestOperationRow,
) {
  return {
    ...(row.authorized_until
      ? { authorized_until: iso(row.authorized_until) }
      : {}),
    ...(row.error_code ? { error: row.error_code } : {}),
    expires_at: iso(row.expires_at),
    ...(row.status === "consumed" && operation?.result_item_id
      ? { item_id: operation.result_item_id }
      : {}),
    request_id: row.id,
    status: publicRequestState(row.status),
    ...(row.status === "consumed" && operation && operation.result_version !== null
      ? { version: operation.result_version }
      : {}),
  };
}

export function readOnlyRequestState(row: RequestRow, now: number): RequestRow {
  if (
    (row.status === "pending" && row.expires_at <= now) ||
    (row.status === "approved" && (row.authorized_until ?? 0) <= now)
  ) {
    return { ...row, status: "expired" };
  }
  return row;
}

export function projectHumanRequestSummary(row: RequestRow) {
  return {
    action: projectApprovalAction(row.action),
    application_recognition: projectApplicationRecognition(row),
    ...(row.application_assurance === "verified-code-signature" &&
    (row.action === "secret.read" || row.action === "credential.use") &&
    row.application_scope_id === row.application_principal_id
      ? {
          authorization_scope: {
            scope_kind: "application",
            resource: "secret",
          },
        }
      : row.application_assurance === "verified-code-signature" &&
          row.action === "ssh.sign" &&
          row.ssh_agent_instance_public_key &&
          row.ssh_scope_id === row.application_principal_id &&
          row.ssh_scope_kind === "application"
        ? {
            authorization_scope: {
              scope_kind: "application",
              resource: "ssh",
            },
          }
        : {}),
    client: {
      application: row.client_application,
      identity: projectStoredApplicationIdentity(row),
      source:
        row.client_source === "process-ancestry"
          ? "process-ancestry"
          : "unavailable",
    },
    created_at: iso(row.created_at),
    expires_at: iso(row.expires_at),
    request_id: row.id,
    requester_name: row.requester_name,
    status: uiRequestState(row.status),
    target_label: mutationTargetLabel(row),
    verified_version: row.expected_version,
  };
}

export function projectHumanActivitySummary(row: RequestActivityRow) {
  return {
    action: projectApprovalAction(row.action),
    application_recognition: projectApplicationRecognition(row),
    client: {
      application: row.client_application,
      identity: projectStoredApplicationIdentity(row),
      source:
        row.client_source === "process-ancestry"
          ? "process-ancestry"
          : "unavailable",
    },
    created_at: iso(row.created_at),
    expires_at: iso(row.expires_at),
    request_id: row.request_id,
    requester_name: row.requester_name,
    status: uiRequestState(row.status),
    target_label:
      row.action === "secret.read" || row.action === "credential.use"
        ? `${row.item_title} · ${row.field_label}`
        : row.item_title,
    verified_version: row.expected_version,
  };
}

export function projectGrantApplicationIdentity(
  grant: SecretAuthorizationGrantRow | SshAuthorizationGrantRow,
) {
  return {
    assurance: "verified-code-signature" as const,
    platform: "macos" as const,
    principal_id: grant.scope_id,
    principal_scheme: "macos-designated-requirement-v1" as const,
    ...(grant.application_signer_name
      ? { signer_name: grant.application_signer_name }
      : {}),
    signing_identifier: grant.application_signing_identifier,
    ...(grant.application_team_identifier
      ? { team_identifier: grant.application_team_identifier }
      : {}),
  };
}

export function projectHumanActivityDetail(row: RequestActivityRow) {
  return {
    ...projectHumanActivitySummary(row),
    error: row.error_code ?? undefined,
    verified_facts: [
      { label: "Requester", value: row.requester_name },
      { label: "Completed", value: iso(row.terminal_at) },
    ],
  };
}

export function projectHumanRequestDetail(row: RequestRow) {
  const mutationFacts = parseOperationSummary(row.operation_summary);
  return {
    ...projectHumanRequestSummary(row),
    authorized_until: row.authorized_until
      ? iso(row.authorized_until)
      : undefined,
    error: row.error_code ?? undefined,
    expected_version: row.expected_version,
    field_id: row.field_id,
    item_id: row.item_id,
    verified_facts:
      row.action === "secret.read" || row.action === "credential.use"
        ? [
            { label: "Item", value: row.item_title },
            { label: "Field", value: row.field_label },
            { label: "Version", value: String(row.expected_version) },
            { label: "Requester", value: row.requester_name },
          ]
        : [...mutationFacts, { label: "Requester", value: row.requester_name }],
  };
}

export function catalogMetadataCacheKey(
  itemId: string,
  fieldId: string,
  version: number,
): string {
  return `${itemId}\u0000${fieldId}\u0000${String(version)}`;
}

function projectApprovalAction(value: string) {
  if (
    value === "secret.read" ||
    value === "credential.use" ||
    value === "item.create" ||
    value === "item.patch" ||
    value === "item.archive" ||
    value === "ssh.sign"
  ) {
    return value;
  }
  return "secret.read";
}

function mutationTargetLabel(row: RequestRow): string {
  if (
    row.action === "item.create" ||
    row.action === "item.patch" ||
    row.action === "item.archive" ||
    row.action === "ssh.sign"
  ) {
    return row.item_title;
  }
  return `${row.item_title} · ${row.field_label}`;
}

function parseOperationSummary(
  value: string | null,
): Array<{ label: string; value: string }> {
  if (!value) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed) || parsed.length > 40) return [];
  const facts: Array<{ label: string; value: string }> = [];
  for (const candidate of parsed) {
    if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
      return [];
    }
    const fact = candidate as Record<string, unknown>;
    if (
      typeof fact.label !== "string" ||
      typeof fact.value !== "string" ||
      fact.label.length === 0 ||
      fact.label.length > 160 ||
      fact.value.length === 0 ||
      fact.value.length > 512 ||
      hasForbiddenControl(fact.label, true) ||
      hasForbiddenControl(fact.value, true)
    ) {
      return [];
    }
    facts.push({ label: fact.label, value: fact.value });
  }
  return facts;
}

export function publicRequestState(value: string): RequestState {
  if (
    value === "pending" ||
    value === "approved" ||
    value === "rejected" ||
    value === "expired" ||
    value === "executing" ||
    value === "consumed" ||
    value === "error" ||
    value === "unknown"
  ) {
    return value;
  }
  return "error";
}

function uiRequestState(value: string) {
  switch (publicRequestState(value)) {
    case "pending": return "pending";
    case "approved": return "approved";
    case "consumed": return "consumed";
    case "rejected": return "denied";
    case "expired": return "expired";
    case "executing": return "submitting";
    case "error":
    case "unknown": return "error";
  }
}

function iso(value: number): string {
  return new Date(value).toISOString();
}

function hasForbiddenControl(value: string, allowNewline: boolean): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0)!;
    if (codePoint === 0x7f) return true;
    if (codePoint < 0x20 && !(allowNewline && codePoint === 0x0a)) return true;
  }
  return false;
}
