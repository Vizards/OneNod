import type {
  ApplicationIdentity,
  ApprovalAction,
  ApprovalStatus,
  RequestSummary,
  SecretAuthorizationDuration,
  SshAuthorizationDuration,
} from "@onenod/protocol";

import { ApiError } from "../api";

export { formatCountdown, shortIdentifier } from "./presentation-core";

export const statusCopy: Record<ApprovalStatus, string> = {
  approved: "Approved",
  consumed: "Released",
  authenticating: "Authenticating",
  denied: "Denied",
  error: "Needs attention",
  expired: "Expired",
  pending: "Pending",
  submitting: "Submitting",
};

export const statusClass: Record<ApprovalStatus, string> = {
  approved: "border-success-border bg-success-muted text-success",
  consumed: "border-success-border bg-success-muted text-success",
  authenticating: "border-focus/40 bg-focus/10 text-focus",
  denied: "border-danger-border bg-danger-muted text-danger-text",
  error: "border-danger-border bg-danger-muted text-danger-text",
  expired: "border-subtle bg-muted text-secondary",
  pending: "border-warning-border bg-warning-muted text-warning",
  submitting: "border-focus/40 bg-focus/10 text-focus",
};

export const sshAuthorizationDurationCopy: Record<SshAuthorizationDuration, string> = {
  "until-lock": "Until Lock mode",
  "until-agent-quits": "Until SSH Agent quits",
  "4-hours": "For 4 hours",
  "12-hours": "For 12 hours",
  "24-hours": "For 24 hours",
};

export const sshAuthorizationDurations = Object.keys(
  sshAuthorizationDurationCopy,
) as SshAuthorizationDuration[];

export const secretAuthorizationDurations: SecretAuthorizationDuration[] = [
  "until-lock",
  "4-hours",
  "12-hours",
  "24-hours",
];

export function approvalActionCopy(action: ApprovalAction): string {
  switch (action) {
    case "secret.read":
      return "Read secret";
    case "item.create":
      return "Create item";
    case "item.patch":
      return "Update item";
    case "item.archive":
      return "Archive item";
    case "ssh.sign":
      return "Use SSH key";
    case "catalog.search":
      return "Search catalog";
    case "process.run":
      return "Run process";
  }
}

export function applicationSignerCopy(
  identity: Extract<ApplicationIdentity, { assurance: "verified-code-signature" }>,
): string {
  return [
    identity.signerName,
    identity.teamIdentifier,
    identity.signingIdentifier,
  ].filter(Boolean).join(" · ");
}

export function approvalQuestion(request: RequestSummary): string {
  const application = request.client.application;
  switch (request.action) {
    case "secret.read":
      return `Allow ${application} to read “${request.targetLabel}”?`;
    case "item.create":
      return `Allow ${application} to create “${request.targetLabel}”?`;
    case "item.patch":
      return `Allow ${application} to update “${request.targetLabel}”?`;
    case "item.archive":
      return `Allow ${application} to archive “${request.targetLabel}”?`;
    case "ssh.sign":
      return `Allow ${application} to use “${request.targetLabel}”?`;
    case "catalog.search":
      return `Allow ${application} to search “${request.targetLabel}”?`;
    case "process.run":
      return `Allow ${application} to run “${request.targetLabel}”?`;
  }
}
export function environmentCopy(value: string): string {
  if (value === "dev") return "Development";
  if (value === "prod") return "Production";
  return `${value} environment`;
}

export function effectiveStatus(
  request: RequestSummary,
  now = Date.now(),
): ApprovalStatus {
  return request.status === "pending" && isPast(request.expiresAt, now)
    ? "expired"
    : request.status;
}

export function isRefreshableDecisionError(error: unknown): boolean {
  return error instanceof ApiError && [401, 404, 409, 410].includes(error.status);
}

export function isPast(value: string, now = Date.now()): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp <= now;
}

export function toErrorMessage(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return "Passkey verification was cancelled or timed out, or this passkey is unavailable for the current site.";
  }
  if (error instanceof Error) return error.message;
  return "An unknown error occurred. Reload the page and try again.";
}

export function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit" }).format(
    new Date(value),
  );
}

export function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}
