export const API_PATHS = {
  executorHealth: "/api/executor/health",
  requests: "/api/requests",
  systemHealth: "/api/health",
} as const;

export const EXECUTOR_PROTOCOL_HEADER = "x-onenod-executor-protocol";
export const EXECUTOR_PROTOCOL_VERSION = "v1";

export type ApprovalStatus =
  | "pending"
  | "authenticating"
  | "submitting"
  | "approved"
  | "consumed"
  | "denied"
  | "expired"
  | "error";

export type ApprovalAction =
  | "catalog.search"
  | "secret.read"
  | "process.run"
  | "item.create"
  | "item.patch"
  | "item.archive"
  | "ssh.sign";

export interface ClientObservation {
  application: string;
  identity: ApplicationIdentity;
  source: "process-ancestry" | "unavailable";
}

export type ApplicationIdentity =
  | {
      assurance: "verified-code-signature";
      platform: "macos";
      principalId: string;
      principalScheme: "macos-designated-requirement-v1";
      signerName?: string;
      signingIdentifier: string;
      teamIdentifier?: string;
    }
  | {
      assurance: "unverified";
      platform: "macos" | "unsupported";
    };

export interface RequestSummary {
  action: ApprovalAction;
  authorizationScope?: {
    kind: "application";
    resource: "secret" | "ssh";
  };
  client: ClientObservation;
  createdAt: string;
  expiresAt: string;
  requestId: string;
  requesterName: string;
  status: ApprovalStatus;
  targetLabel: string;
  verifiedVersion: number;
}

export interface RequestDetail extends RequestSummary {
  verifiedFacts: ReadonlyArray<{
    label: string;
    value: string;
  }>;
}

export interface RequestListResponse {
  requests: RequestSummary[];
}

export interface SystemHealthResponse {
  environment: "dev" | "prod";
  ok: true;
  service: "onenod-gateway";
  version: string;
}

export interface ExecutorHealthResponse {
  configured: {
    executorAuthToken: boolean;
    onePasswordServiceAccount: boolean;
    onePasswordVault: boolean;
  };
  ok: true;
  runtime: "cloudflare-worker-sqlite-do";
  version: string;
}

export * from "./canonical-json.js";
export * from "./encoding.js";
export * from "./release-version.js";
export * from "./requester-signing.js";
export * from "./v1.js";
