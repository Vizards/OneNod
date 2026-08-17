import type {
  ApplicationIdentityRequest,
  ClientObservationRequest,
} from "@onenod/protocol";

export type ChallengeKind =
  | "bootstrap"
  | "human_session"
  | "requester_enrollment"
  | "approval"
  | "device_registration"
  | "device_revoke"
  | "credential_authorization"
  | "credential_registration"
  | "credential_revoke"
  | "gateway_unlock"
  | "requester_rename"
  | "requester_revoke";

export type RequestState =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | "executing"
  | "consumed"
  | "error"
  | "unknown";

export interface HumanCredentialRow {
  backed_up: number;
  counter: number;
  created_at: number;
  device_type: string;
  id: string;
  label: string;
  last_used_at: number | null;
  public_key: string;
  revoked_at: number | null;
  transports: string;
}

export interface ChallengeRow {
  challenge: string;
  decision: string | null;
  expires_at: number;
  id: string;
  kind: string;
  payload: string | null;
  target_id: string | null;
  used_at: number | null;
}

export interface SessionRow {
  credential_id: string;
  csrf_token: string;
  device_id: string | null;
  expires_at: number;
  token_hash: string;
}

export interface HumanDeviceRow {
  created_at: number;
  id: string;
  label: string;
  last_seen_at: number;
  platform: string;
  public_key: string;
  revoked_at: number | null;
}

export interface PushSubscriptionRow {
  auth: string;
  device_id: string;
  endpoint: string;
  expiration_time: number | null;
  failure_count: number;
  p256dh: string;
}

export interface CatalogMetadataCacheRow {
  cached_at: number;
  field_id: string;
  field_label: string;
  field_type: string;
  item_id: string;
  item_title: string;
  version: number;
}

export interface TrustedCatalogMetadataRow {
  field_id: string;
  field_label: string;
  field_type: string;
  item_id: string;
  item_title: string;
  item_version: number;
  observed_at: number;
}

export interface RequestSecretFieldRow {
  field_id: string;
  field_label: string;
  field_type: string;
  ordinal: number;
  request_id: string;
  secret_grant_id: string | null;
}

export interface RequestActivityRow {
  action: string;
  application_assurance: string;
  application_principal_id: string | null;
  application_principal_scheme: string | null;
  application_signer_name: string | null;
  application_signing_identifier: string | null;
  application_team_identifier: string | null;
  application_approved_before?: number;
  client_application: string;
  client_source: string;
  consumed_at: number | null;
  created_at: number;
  decided_at: number | null;
  error_code: string | null;
  expected_version: number;
  expires_at: number;
  field_label: string;
  item_title: string;
  request_id: string;
  requester_name: string;
  status: string;
  terminal_at: number;
}

export interface EventSocketAttachment {
  credentialId: string;
  deviceId: string;
  expiresAt: number;
  sessionHash: string;
}

export interface RateWindow {
  count: number;
  startedAt: number;
}

export interface RequestCreationReservation {
  rememberedSecret: boolean;
  rememberedSsh: boolean;
  requesterDeviceId: string;
}

export type ValidatedClientObservation = ClientObservationRequest & {
  identity: ApplicationIdentityRequest;
};

export interface ApplicationIdentityColumns {
  application_assurance: string;
  application_principal_id: string | null;
  application_principal_scheme: string | null;
  application_signer_name: string | null;
  application_signing_identifier: string | null;
  application_team_identifier: string | null;
}

export interface RetentionSweepStateRow {
  activity_backfill_done: number;
  activity_backfill_cursor_created_at: number | null;
  activity_backfill_cursor_id: string | null;
  activity_cutoff_created_at: number | null;
  activity_cutoff_id: string | null;
  activity_trim_done: number;
  audit_cutoff_created_at: number | null;
  audit_cutoff_id: number | null;
  audit_trim_done: number;
  request_cutoff_created_at: number | null;
  request_cutoff_id: string | null;
  request_trim_done: number;
  retention_active: number;
  retention_started_at: number | null;
}

export interface BootstrapSessionRow {
  armed_until: number | null;
  consumed_at: number | null;
  expires_at: number;
  id: string;
}

export interface EnrollmentRow {
  created_at: number;
  device_id: string;
  display_name: string;
  expires_at: number;
  id: string;
  public_key: string;
  public_key_fingerprint: string;
  status: string;
  terminal_at: number | null;
}

export interface RequesterRow {
  created_at: number;
  device_id: string;
  display_name: string;
  public_key: string;
  revoked_at: number | null;
}

export interface RequestRow {
  action: string;
  application_assurance: string;
  application_principal_id: string | null;
  application_principal_scheme: string | null;
  application_signer_name: string | null;
  application_signing_identifier: string | null;
  application_team_identifier: string | null;
  application_approved_before?: number;
  application_scope_id: string | null;
  authorized_until: number | null;
  client_application: string;
  client_source: string;
  consumed_at: number | null;
  created_at: number;
  decided_at: number | null;
  error_code: string | null;
  execution_started_at: number | null;
  expected_version: number;
  expires_at: number;
  field_id: string;
  field_label: string;
  field_type: string;
  id: string;
  item_id: string;
  item_title: string;
  legacy_ssh_signed_consume: number;
  operation_summary: string | null;
  requester_device_id: string;
  requester_name: string;
  secret_grant_id: string | null;
  ssh_agent_instance_public_key: string | null;
  ssh_grant_id: string | null;
  ssh_scope_id: string | null;
  ssh_scope_kind: string | null;
  status: string;
}

export interface SecretAuthorizationGrantRow {
  application_principal_scheme: string;
  application_signer_name: string | null;
  application_signing_identifier: string;
  application_team_identifier: string | null;
  authorized_by_credential_id: string;
  client_application: string;
  created_at: number;
  duration: string;
  expires_at: number | null;
  field_id: string;
  field_label: string;
  field_type: string;
  id: string;
  item_id: string;
  item_title: string;
  item_version: number;
  lock_generation: number;
  requester_device_id: string;
  revoked_at: number | null;
  scope_id: string;
  use_count: number;
}

export interface SshAuthorizationGrantRow {
  agent_instance_public_key: string;
  application_principal_scheme: string;
  application_signer_name: string | null;
  application_signing_identifier: string;
  application_team_identifier: string | null;
  authorized_by_credential_id: string;
  client_application: string;
  created_at: number;
  duration: string;
  expires_at: number | null;
  fingerprint: string;
  id: string;
  item_id: string;
  item_title: string;
  item_version: number;
  lock_generation: number;
  requester_device_id: string;
  revoked_at: number | null;
  scope_id: string;
  scope_kind: string;
  use_count: number;
}

export interface GatewayRuntimeStateRow {
  changed_at: number;
  changed_by: string;
  lock_generation: number;
  locked: number;
}

export interface RequestOperationRow {
  operation_summary: string;
  payload_aad: string | null;
  payload_ciphertext: string | null;
  payload_digest: string | null;
  payload_iv: string | null;
  reconcile_state: string | null;
  reconcile_attempt_count: number;
  reconcile_attempted_at: number | null;
  request_id: string;
  result_item_id: string | null;
  result_version: number | null;
}
