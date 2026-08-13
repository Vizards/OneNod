export type EmptyRequest = Record<string, never>;
export type WebAuthnJsonObject = Record<string, unknown>;

export interface HumanStateResponse {
  authenticated: boolean;
  bootstrap_request_id?: string;
  csrf_token?: string;
  initialized: boolean;
  locked?: boolean;
}

export interface WebAuthnChallengeOptionsResponse {
  challenge_id: string;
  options: WebAuthnJsonObject;
}

export interface WebAuthnChallengeVerifyRequest {
  challenge_id: string;
  response: WebAuthnJsonObject;
}

export interface HumanBootstrapRequest {
  label: string;
}

export type HumanBootstrapResponse = WebAuthnChallengeOptionsResponse;
export type HumanBootstrapVerifyRequest = WebAuthnChallengeVerifyRequest;

export interface HumanBootstrapVerifyResponse {
  csrf_token: string;
  ok: true;
}

export type HumanSessionOptionsRequest = EmptyRequest;
export type HumanSessionOptionsResponse = WebAuthnChallengeOptionsResponse;
export type HumanSessionVerifyRequest = WebAuthnChallengeVerifyRequest;

export interface HumanSessionVerifyResponse {
  csrf_token: string;
  ok: true;
}

export interface RequesterEnrollmentRequest {
  device_id: string;
  display_name: string;
  /** Unpadded base64url of the raw 32-byte Ed25519 public key. */
  public_key: string;
}

export interface RequesterEnrollmentResponse {
  enrollment_id: string;
  expires_at: string;
  public_key_fingerprint: string;
  status: "pending";
}

export type RequesterEnrollmentStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired";

export interface RequesterEnrollmentStatusResponse {
  created_at: string;
  device_id: string;
  display_name: string;
  expires_at: string;
  id: string;
  public_key_fingerprint: string;
  status: RequesterEnrollmentStatus;
}

export interface RequesterEnrollmentListResponse {
  enrollments: RequesterEnrollmentStatusResponse[];
}

export interface RequesterSelfResponse {
  device_id: string;
  public_key_fingerprint: string;
  registered: true;
}

export type Decision = "approve" | "reject";

export type SshAuthorizationDuration =
  | "until-lock"
  | "until-agent-quits"
  | "4-hours"
  | "12-hours"
  | "24-hours";

export type SecretAuthorizationDuration = Exclude<
  SshAuthorizationDuration,
  "until-agent-quits"
>;

export interface DecisionOptionsRequest {
  authorization_duration?: SshAuthorizationDuration;
  decision: Decision;
}

export type DecisionOptionsResponse = WebAuthnChallengeOptionsResponse;

export interface DecisionVerifyRequest {
  authorization_duration?: SshAuthorizationDuration;
  challenge_id: string;
  decision: Decision;
  response: WebAuthnJsonObject;
}

export interface DecisionVerifyResponse {
  grant_id?: string;
  ok: true;
  status: "approved" | "rejected";
}

export type RequesterEnrollmentOptionsRequest = DecisionOptionsRequest;
export type RequesterEnrollmentOptionsResponse = DecisionOptionsResponse;
export type RequesterEnrollmentVerifyRequest = DecisionVerifyRequest;
export type RequesterEnrollmentVerifyResponse = DecisionVerifyResponse;

export interface CatalogFieldResult {
  field_id: string;
  field_type: string;
  label: string;
}

export interface CatalogItemResult {
  category: string;
  fields: CatalogFieldResult[];
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

export interface CatalogSearchRequest {
  query: string;
}

export interface CatalogSearchResponse {
  items: CatalogItemResult[];
}

export interface ClientObservationRequest {
  application: string;
  identity?: ApplicationIdentityRequest;
  source: "process-ancestry" | "unavailable";
}

export interface VerifiedMacOSApplicationIdentityRequest {
  assurance: "verified-code-signature";
  platform: "macos";
  principal_id: string;
  principal_scheme: "macos-designated-requirement-v1";
  signer_name?: string;
  signing_identifier: string;
  team_identifier?: string;
}

export interface UnverifiedApplicationIdentityRequest {
  assurance: "unverified";
  platform: "macos" | "unsupported";
}

export type ApplicationIdentityRequest =
  | VerifiedMacOSApplicationIdentityRequest
  | UnverifiedApplicationIdentityRequest;

export interface ApplicationAuthorizationScopeRequest {
  scope_id: string;
  scope_kind: "application";
}

export interface SshAuthorizationSessionRequest {
  agent_instance_public_key: string;
  proof: string;
  scope_id: string;
  // Protocol 1 clients used terminal-session. The Gateway accepts that shape
  // only as a rolling-upgrade bridge and never turns it into reusable authority.
  scope_kind: "application" | "terminal-session";
}

export interface SshAuthenticationOperationRequest {
  authentication_method:
    | "publickey"
    | "publickey-hostbound-v00@openssh.com";
  kind: "ssh.authentication";
  remote_username: string;
  server_host_key_fingerprint?: string;
  session_binding: "verified" | "unavailable";
  service: "ssh-connection";
  session_id_fingerprint: string;
}

export interface SshOpaqueSignatureOperationRequest {
  kind: "ssh.opaque-signature";
}

export interface GitSshSignatureOperationRequest {
  kind: "git.ssh-signature";
  namespace: "git";
}

export type SshOperationRequest =
  | GitSshSignatureOperationRequest
  | SshAuthenticationOperationRequest
  | SshOpaqueSignatureOperationRequest;

export interface SecretReadCreateRequest {
  action: "secret.read";
  authorization_scope?: ApplicationAuthorizationScopeRequest;
  client: ClientObservationRequest;
  expected_version: number;
  field_id: string;
  idempotency_key: string;
  item_id: string;
}

export type WritableItemCategory =
  | "ApiCredentials"
  | "Login"
  | "Password"
  | "SecureNote"
  | "SshKey";

export type WritableItemFieldType = "Concealed" | "Email" | "Text" | "Url";
export type WritableItemCreateFieldType = WritableItemFieldType | "SshKey";

export type SshSignatureAlgorithm =
  | "rsa-sha2-256"
  | "rsa-sha2-512"
  | "ssh-ed25519";

export interface ItemCreateFieldRequest {
  field_id: string;
  field_type: WritableItemCreateFieldType;
  label: string;
  value: string;
}

export interface ItemCreateRequest {
  action: "item.create";
  category: WritableItemCategory;
  client: ClientObservationRequest;
  fields: ItemCreateFieldRequest[];
  idempotency_key: string;
  title: string;
}

export type ItemPatchOperationRequest =
  | {
      field_id: string;
      field_type: WritableItemFieldType;
      label: string;
      op: "add";
      value: string;
    }
  | {
      field_id: string;
      op: "replace";
      value: string;
    }
  | {
      field_id: string;
      op: "remove";
    };

export interface ItemPatchRequest {
  action: "item.patch";
  client: ClientObservationRequest;
  expected_version: number;
  idempotency_key: string;
  item_id: string;
  operations: ItemPatchOperationRequest[];
}

export interface ItemArchiveRequest {
  action: "item.archive";
  client: ClientObservationRequest;
  expected_version: number;
  idempotency_key: string;
  item_id: string;
}

export type ItemMutationRequest =
  | ItemCreateRequest
  | ItemPatchRequest
  | ItemArchiveRequest;

export interface SshSignCreateRequest {
  action: "ssh.sign";
  algorithm: SshSignatureAlgorithm;
  authorization_session?: SshAuthorizationSessionRequest;
  client: ClientObservationRequest;
  data: string;
  expected_fingerprint: string;
  expected_version: number;
  idempotency_key: string;
  item_id: string;
  operation: SshOperationRequest;
}

export interface SshSignConsumeResponse {
  algorithm: SshSignatureAlgorithm;
  fingerprint: string;
  item_id: string;
  ok: true;
  public_key_blob: string;
  request_id: string;
  signature_blob: string;
  status: "consumed";
  version: number;
}

export type ItemMutationConsumeResponse =
  | {
      item_id: string;
      ok: true;
      request_id: string;
      status: "consumed";
      version?: number;
    }
  | {
      ok: true;
      request_id: string;
      status: "unknown";
    };

export type SecretReadStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "expired"
  | "executing"
  | "consumed"
  | "error"
  | "unknown";

export interface SecretReadCreateResponse {
  expires_at: string;
  request_id: string;
  status: SecretReadStatus;
}

export interface SecretReadStatusResponse {
  authorized_until?: string;
  error?: string;
  expires_at: string;
  item_id?: string;
  request_id: string;
  status: SecretReadStatus;
  version?: number;
}

export interface SecretReadDetailResponse {
  action: "secret.read";
  authorized_until?: string;
  client: {
    application: string;
    source: "process-ancestry" | "unavailable";
  };
  created_at: string;
  error?: string;
  expected_version: number;
  expires_at: string;
  field_id: string;
  item_id: string;
  request_id: string;
  requester_name: string;
  status:
    | "pending"
    | "authenticating"
    | "submitting"
    | "approved"
    | "consumed"
    | "denied"
    | "expired"
    | "error";
  target_label: string;
  verified_facts: Array<{
    label: string;
    value: string;
  }>;
  verified_version: number;
}

export type ApprovalDecision = Decision;
export type ApprovalOptionsRequest = DecisionOptionsRequest;
export type ApprovalOptionsResponse = DecisionOptionsResponse;
export type ApprovalVerifyRequest = DecisionVerifyRequest;
export type ApprovalVerifyResponse = DecisionVerifyResponse;

export interface ConsumeResponse {
  ok: true;
  request_id: string;
  status: "consumed";
  value: string;
}
