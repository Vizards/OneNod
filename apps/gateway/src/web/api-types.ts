import type { ApplicationIdentity, RequestListResponse, SecretAuthorizationDuration, SshAuthorizationDuration, SystemHealthResponse } from "@onenod/protocol";

import type { GatewayReleaseChannel } from "../release";

export type ApprovalDecision = "approve" | "reject";

export interface HumanState {
  authenticated: boolean;
  bootstrapRequestId?: string;
  currentDeviceId?: string;
  deviceTrusted: boolean;
  initialized: boolean;
  locked: boolean;
}
export interface HumanCredentialSummary {
  backedUp: boolean;
  createdAt: string;
  current: boolean;
  deviceType: string;
  id: string;
  label: string;
  lastUsedAt?: string;
}

export interface HumanDeviceSummary {
  createdAt: string;
  current: boolean;
  id: string;
  label: string;
  lastSeenAt: string;
  platform: string;
  pushEnabled: boolean;
}

export interface HumanManagement {
  credentials: HumanCredentialSummary[];
  devices: HumanDeviceSummary[];
  requesters: RequesterSummary[];
  serverTime: string;
  secretAuthorizations: SecretAuthorizationSummary[];
  sshAuthorizations: SshAuthorizationSummary[];
}

export interface SecretAuthorizationSummary {
  application: string;
  applicationIdentity: VerifiedApplicationIdentity;
  createdAt: string;
  duration: SecretAuthorizationDuration;
  expiresAt?: string;
  fieldId: string;
  fieldLabel: string;
  fieldType: string;
  id: string;
  itemId: string;
  itemTitle: string;
  itemVersion: number;
  requesterDeviceId: string;
  useCount: number;
}

export interface SshAuthorizationSummary {
  application: string;
  applicationIdentity: VerifiedApplicationIdentity;
  createdAt: string;
  duration: SshAuthorizationDuration;
  expiresAt?: string;
  fingerprint: string;
  id: string;
  itemId: string;
  itemTitle: string;
  itemVersion: number;
  requesterDeviceId: string;
  scopeKind: "application";
  useCount: number;
}

export type VerifiedApplicationIdentity = Extract<
  ApplicationIdentity,
  { assurance: "verified-code-signature" }
>;

export interface DeviceRegistrationInput {
  device_id: string;
  label: string;
  platform: string;
  public_key: JsonWebKey;
}

export interface RequesterEnrollment {
  createdAt: string;
  deviceId: string;
  displayName: string;
  expiresAt: string;
  id: string;
  publicKeyFingerprint: string;
  status: string;
}

export interface RequesterSummary {
  createdAt: string;
  deviceId: string;
  displayName: string;
  publicKeyFingerprint: string;
}

export interface VerifyDecisionResponse {
  ok: true;
  status: string;
}

export interface GatewaySystemHealthResponse extends SystemHealthResponse {
  channel: GatewayReleaseChannel;
}

export interface PaginatedRequestListResponse extends RequestListResponse {
  nextCursor?: string;
  serverTime: string;
}

export interface AuthorizationSummary {
  activeCount: number;
  nextExpiryAt?: string;
  serverTime: string;
}

export interface ServiceAccountQuota {
  dailyLimit?: number;
  dailyRemaining?: number;
  exhausted: boolean;
  exhaustedAt?: string;
  lastSuccessAt?: string;
}

export interface WebAuthnOptionsEnvelope<TOptions> {
  challenge_id: string;
  options: TOptions;
}
