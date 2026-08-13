import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import type { ApprovalStatus } from "@onenod/protocol";

import {
  statusClass,
  statusCopy,
  toErrorMessage,
} from "../utils/presentation";
import { usePageTitle } from "../hooks/human";

export function HumanGateCard({
  children,
  eyebrow,
  title,
}: {
  children: ReactNode;
  eyebrow: string;
  title: string;
}) {
  return (
    <section className="mx-auto max-w-[520px] rounded-dialog border border-subtle bg-surface p-6 sm:p-8">
      <p className="font-mono text-xs uppercase tracking-[0.12em] text-secondary">{eyebrow}</p>
      <h1 className="mt-3 text-2xl font-semibold tracking-[-0.03em]">{title}</h1>
      <div className="mt-4">{children}</div>
    </section>
  );
}
export function HumanGateSkeleton() {
  return (
    <div
      aria-label="Checking approver state"
      aria-busy="true"
      className="mx-auto h-72 max-w-[520px] animate-pulse rounded-dialog border border-subtle bg-surface"
    />
  );
}

export function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid min-w-0 gap-1 px-4 py-3 sm:grid-cols-[132px_minmax(0,1fr)] sm:gap-4">
      <dt className="text-xs text-secondary">{label}</dt>
      <dd className={`min-w-0 text-sm [overflow-wrap:anywhere] ${mono ? "font-mono tabular-nums" : ""}`}>{value}</dd>
    </div>
  );
}

export function StatusBadge({ status }: { status: ApprovalStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-pill border px-2.5 py-1 text-xs font-medium ${statusClass[status]}`}
    >
      {statusCopy[status]}
    </span>
  );
}

export function EmptyQueue() {
  return (
    <div className="grid min-h-72 place-items-center rounded-card border border-dashed border-subtle bg-surface px-6 text-center">
      <div className="max-w-sm">
        <div
          aria-hidden="true"
          className="mx-auto mb-5 grid size-10 place-items-center rounded-full border border-subtle bg-muted text-secondary"
        >
          ✓
        </div>
        <h2 className="text-base font-medium">No pending requests</h2>
        <p className="mt-2 text-sm leading-6 text-secondary">
          New Agent registrations and secret-access requests appear here. Reloading the page never grants approval.
        </p>
        <Link
          to="/activity"
          className="mt-4 inline-flex rounded-control text-sm font-medium text-foreground underline decoration-subtle underline-offset-4 hover:decoration-foreground"
        >
          View recent activity
        </Link>
      </div>
    </div>
  );
}

export function InlineError({
  message,
  onRetry,
  title = "Unable to load requests",
}: {
  message: string;
  onRetry: () => void;
  title?: string;
}) {
  return (
    <div role="alert" className="rounded-card border border-danger-border bg-danger-muted p-5">
      <h2 className="text-sm font-medium text-danger-text">{title}</h2>
      <p className="mt-2 text-sm leading-5 text-secondary">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-4 h-10 rounded-control border border-danger-border bg-background px-4 text-sm font-medium hover:border-subtle-active"
      >
        Reload
      </button>
    </div>
  );
}

export function ActionError({
  compact = false,
  error,
  onDismiss,
}: {
  compact?: boolean;
  error: unknown;
  onDismiss: () => void;
}) {
  return (
    <div
      role="alert"
      className={`${compact ? "mt-4" : "mt-5"} rounded-card border border-danger-border bg-danger-muted p-4`}
    >
      <p className="text-sm leading-5 text-danger-text">{toErrorMessage(error)}</p>
      <button
        type="button"
        onClick={onDismiss}
        className="mt-2 rounded-control text-xs text-secondary underline decoration-subtle underline-offset-4 hover:text-foreground"
      >
        Dismiss
      </button>
    </div>
  );
}

export function RequestListSkeleton() {
  return (
    <div aria-label="Loading requests" aria-busy="true" className="grid gap-3">
      {[0, 1].map((item) => (
        <div
          key={item}
          className="h-32 animate-pulse rounded-card border border-subtle bg-surface"
        />
      ))}
    </div>
  );
}

export function PagePanelSkeleton() {
  return (
    <div
      aria-label="Loading page"
      aria-busy="true"
      className="mx-auto h-[560px] max-w-[640px] animate-pulse rounded-dialog border border-subtle bg-surface"
    />
  );
}

export function NotFoundPage() {
  usePageTitle("Page not found · OneNod");
  return (
    <section className="mx-auto max-w-[640px] rounded-card border border-subtle bg-surface p-6">
      <p className="font-mono text-xs uppercase tracking-[0.12em] text-secondary">404</p>
      <h1 className="mt-3 text-2xl font-semibold tracking-[-0.03em]">Page not found</h1>
      <p className="mt-3 text-sm leading-6 text-secondary">
        This link is invalid or no longer available. Return to the approval queue to view current requests.
      </p>
      <Link
        to="/requests"
        className="mt-6 inline-flex h-10 items-center rounded-control bg-foreground px-4 text-sm font-medium text-background"
      >
        Return to approval queue
      </Link>
    </section>
  );
}
