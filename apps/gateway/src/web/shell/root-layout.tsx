import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { Link, Outlet } from "@tanstack/react-router";

import {
  getAuthorizationSummary,
  getHumanState,
  getServiceAccountQuota,
  getSystemHealth,
} from "../api";
import { BootstrapPage, DeviceSetupPage, LoginPage } from "../auth/human-gate";
import { HumanGateSkeleton, InlineError } from "../components/common";
import { useApprovalAppBadge } from "../hooks/approval-app-badge";
import { useHumanRealtime } from "../hooks/human";
import { PWA_RELEASE_METADATA } from "../release-metadata";
import { toErrorMessage } from "../utils/presentation";

export function RootLayout() {
  const health = useQuery({
    queryKey: ["system-health"],
    queryFn: getSystemHealth,
    refetchInterval: 30_000,
    refetchOnWindowFocus: "always",
  });
  const humanState = useQuery({
    queryKey: ["human-state"],
    queryFn: getHumanState,
    refetchOnMount: "always",
  });
  const trusted = Boolean(
    humanState.data?.authenticated && humanState.data.deviceTrusted,
  );
  const authorizationSummary = useQuery({
    enabled: trusted,
    queryFn: getAuthorizationSummary,
    queryKey: ["authorization-summary"],
    refetchOnWindowFocus: "always",
  });
  const serviceAccountQuota = useQuery({
    enabled: trusted,
    queryFn: getServiceAccountQuota,
    queryKey: ["service-account-quota"],
    refetchInterval: 60_000,
    refetchOnWindowFocus: "always",
  });
  useHumanRealtime(trusted);
  const pendingApprovalCount = useApprovalAppBadge(trusted);

  useEffect(() => {
    const nextExpiry = authorizationSummary.data?.nextExpiryAt;
    const serverTime = authorizationSummary.data?.serverTime;
    if (!nextExpiry || !serverTime) return;
    const delay = Math.max(0, Date.parse(nextExpiry) - Date.parse(serverTime) + 250);
    const timer = window.setTimeout(
      () => void authorizationSummary.refetch(),
      Math.min(delay, 2_147_000_000),
    );
    return () => window.clearTimeout(timer);
  }, [
    authorizationSummary.data?.nextExpiryAt,
    authorizationSummary.data?.serverTime,
    authorizationSummary.refetch,
  ]);

  const releaseMismatch = Boolean(
    health.data &&
      (health.data.version !== PWA_RELEASE_METADATA.releaseVersion ||
        health.data.channel !== PWA_RELEASE_METADATA.releaseChannel),
  );

  return (
    <div className="min-h-dvh min-w-0 bg-background text-foreground">
      <a
        href="#main-content"
        className="fixed left-4 top-[calc(1rem+env(safe-area-inset-top))] z-50 -translate-y-24 whitespace-nowrap rounded-control bg-foreground px-3 py-2 text-sm font-medium text-background transition-transform focus:translate-y-0"
      >
        Skip to main content
      </a>
      <header className="fixed inset-x-0 top-0 z-40 border-b border-subtle bg-background/80 pt-[env(safe-area-inset-top)] backdrop-blur-2xl">
        <div className="mx-auto flex h-16 max-w-[960px] items-center justify-between px-4 sm:px-6">
          <Link
            to="/requests"
            aria-label="Approval queue"
            className="flex items-center gap-3 rounded-control"
          >
            <span
              className="grid size-8 place-items-center rounded-control border border-subtle bg-muted font-mono text-xs font-semibold"
              aria-hidden="true"
            >
              NOD
            </span>
            <span className="text-sm font-medium tracking-[-0.01em]">OneNod</span>
          </Link>
          <RefreshPageButton />
        </div>
      </header>

      <main
        id="main-content"
        className="mx-auto min-w-0 max-w-[960px] px-4 pb-[calc(7.5rem+env(safe-area-inset-bottom))] pt-[calc(5.25rem+env(safe-area-inset-top))] sm:px-6 sm:pt-[calc(7rem+env(safe-area-inset-top))]"
      >
        {health.isError ? (
          <button
            type="button"
            onClick={() => void health.refetch()}
            className="mb-4 w-full rounded-card border border-danger-border bg-danger-muted px-4 py-3 text-left text-sm text-danger-text"
          >
            Gateway connection failed · Tap to retry
          </button>
        ) : null}
        {releaseMismatch ? (
          <div
            role="status"
            className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-card border border-subtle bg-surface px-4 py-3 text-sm"
          >
            <span>A newer OneNod Gateway release is active.</span>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-control font-medium underline decoration-subtle underline-offset-4 hover:decoration-foreground"
            >
              Reload the approval app
            </button>
          </div>
        ) : null}
        {serviceAccountQuota.data?.exhausted ? (
          <div
            role="alert"
            className="mb-6 rounded-card border border-danger-border bg-danger-muted px-4 py-3"
          >
            <p className="text-sm font-medium text-danger-text">
              1Password Service Account quota exhausted
            </p>
            <p className="mt-1 text-xs text-secondary">
              Password reads and SSH signing remain unavailable until 1Password resets the quota.
            </p>
          </div>
        ) : null}
        {humanState.isPending ? <HumanGateSkeleton /> : null}
        {humanState.isError ? (
          <div className="mx-auto max-w-[640px]">
            <InlineError
              title="Unable to verify approver state"
              message={toErrorMessage(humanState.error)}
              onRetry={() => void humanState.refetch()}
            />
          </div>
        ) : null}
        {humanState.data && !humanState.data.initialized ? <BootstrapPage /> : null}
        {humanState.data?.initialized && !humanState.data.authenticated ? <LoginPage /> : null}
        {humanState.data?.authenticated && !humanState.data.deviceTrusted ? (
          <DeviceSetupPage />
        ) : null}
        {trusted ? <Outlet /> : null}
      </main>

      {trusted ? (
        <BottomNavigation
          approvalCount={pendingApprovalCount}
          authorizationCount={authorizationSummary.data?.activeCount ?? 0}
        />
      ) : null}
    </div>
  );
}

function BottomNavigation({
  approvalCount,
  authorizationCount,
}: {
  approvalCount: number;
  authorizationCount: number;
}) {
  return (
    <nav
      aria-label="Primary navigation"
      className="fixed bottom-[calc(0.75rem+env(safe-area-inset-bottom))] left-1/2 z-40 grid w-[min(calc(100%_-_1.5rem),34rem)] -translate-x-1/2 grid-cols-4 gap-1 rounded-[1.5rem] border border-white/10 bg-[#171717]/75 p-1.5 shadow-[0_18px_60px_rgba(0,0,0,0.55)] backdrop-blur-2xl"
    >
      <BottomNavigationLink to="/requests" label="Approvals" count={approvalCount} />
      <BottomNavigationLink to="/activity" label="Activity" />
      <BottomNavigationLink
        to="/authorizations"
        label="Access"
        count={authorizationCount}
      />
      <Link
        to="/management"
        search={{ section: "approvers" }}
        className="relative grid min-h-12 place-items-center rounded-[1.05rem] px-2 text-sm text-secondary transition-colors hover:text-foreground"
        activeProps={{ className: "bg-white/10 text-foreground" }}
      >
        Manage
      </Link>
    </nav>
  );
}

function BottomNavigationLink({
  count = 0,
  label,
  to,
}: {
  count?: number;
  label: string;
  to: "/activity" | "/authorizations" | "/requests";
}) {
  return (
    <Link
      to={to}
      className="relative grid min-h-12 place-items-center rounded-[1.05rem] px-2 text-sm text-secondary transition-colors hover:text-foreground"
      activeProps={{ className: "bg-white/10 text-foreground" }}
    >
      <span className="relative">
        {label}
        <NavigationBadge count={count} />
      </span>
    </Link>
  );
}

function NavigationBadge({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="absolute -right-4 -top-2 min-w-4 rounded-pill bg-danger-text px-1 text-center font-mono text-[9px] font-semibold leading-4 text-background">
      {count > 99 ? "99+" : count}
    </span>
  );
}

function RefreshPageButton() {
  return (
    <button
      type="button"
      aria-label="Reload the entire page"
      title="Reload page"
      onClick={() => window.location.reload()}
      className="grid h-10 w-12 place-items-center rounded-pill border border-subtle bg-surface text-secondary transition-colors hover:text-foreground"
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.75"
        className="size-4"
      >
        <path d="M20 11a8 8 0 1 0-2.34 5.66" />
        <path d="M20 4v7h-7" />
      </svg>
    </button>
  );
}
