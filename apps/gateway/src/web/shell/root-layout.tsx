import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { Link, Outlet } from "@tanstack/react-router";

import {
  getAuthorizationSummary,
  getHumanState,
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
      <main
        id="main-content"
        className="mx-auto min-w-0 max-w-[960px] px-4 pb-[calc(7.5rem+env(safe-area-inset-bottom))] pt-[calc(1.5rem+env(safe-area-inset-top))] sm:px-6 sm:pt-[calc(3rem+env(safe-area-inset-top))]"
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
        activeOptions={{ includeSearch: false }}
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
