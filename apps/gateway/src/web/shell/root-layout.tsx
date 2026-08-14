import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
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
import { environmentCopy, toErrorMessage } from "../utils/presentation";

export function RootLayout() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const mobileMenuRef = useRef<HTMLDivElement>(null);
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
  const authorizationSummary = useQuery({
    enabled: Boolean(humanState.data?.authenticated && humanState.data.deviceTrusted),
    queryFn: getAuthorizationSummary,
    queryKey: ["authorization-summary"],
    refetchOnWindowFocus: "always",
  });
  useHumanRealtime(Boolean(humanState.data?.authenticated && humanState.data.deviceTrusted));
  useApprovalAppBadge(Boolean(humanState.data?.authenticated && humanState.data.deviceTrusted));

  useEffect(() => {
    if (!mobileMenuOpen) return;
    const closeOnEscape = (event: KeyboardEvent): void => {
      if (event.key === "Escape") setMobileMenuOpen(false);
    };
    const closeOnOutsidePointer = (event: PointerEvent): void => {
      if (event.target instanceof Node && !mobileMenuRef.current?.contains(event.target)) {
        setMobileMenuOpen(false);
      }
    };
    document.addEventListener("keydown", closeOnEscape);
    document.addEventListener("pointerdown", closeOnOutsidePointer);
    return () => {
      document.removeEventListener("keydown", closeOnEscape);
      document.removeEventListener("pointerdown", closeOnOutsidePointer);
    };
  }, [mobileMenuOpen]);

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

  const environment = health.isSuccess
    ? environmentCopy(health.data.environment)
    : "Connecting";
  const authenticated = Boolean(humanState.data?.authenticated);
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
      <header className="fixed inset-x-0 top-0 z-40 border-b border-subtle bg-background/95 pt-[env(safe-area-inset-top)] backdrop-blur-xl">
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
          <div className="ml-auto hidden items-center sm:flex">
            <RefreshPageButton />
            {humanState.data?.deviceTrusted ? (
              <nav aria-label="Primary navigation" className="mx-3 flex items-center gap-1 text-xs">
                <Link
                  to="/requests"
                  className="rounded-control px-2 py-2 text-secondary hover:text-foreground"
                  activeProps={{ className: "bg-muted text-foreground" }}
                >
                  Approvals
                </Link>
                <Link
                  to="/activity"
                  className="rounded-control px-2 py-2 text-secondary hover:text-foreground"
                  activeProps={{ className: "bg-muted text-foreground" }}
                >
                  Activity
                </Link>
                <Link
                  to="/authorizations"
                  className="rounded-control px-2 py-2 text-secondary hover:text-foreground"
                  activeProps={{ className: "bg-muted text-foreground" }}
                >
                  Access
                </Link>
                <Link
                  to="/management"
                  search={{ section: "approvers" }}
                  className="rounded-control px-2 py-2 text-secondary hover:text-foreground"
                  activeProps={{ className: "bg-muted text-foreground" }}
                >
                  Manage
                </Link>
              </nav>
            ) : null}
            {health.isError ? (
              <button
                type="button"
                onClick={() => void health.refetch()}
                className="flex h-10 items-center gap-2 rounded-control px-2 text-xs text-danger-text"
              >
                <span aria-hidden="true" className="size-1.5 rounded-full bg-danger-text" />
                Connection failed · Retry
              </button>
            ) : (
              <div
                className="rounded-pill border border-subtle px-3 py-1.5 text-xs text-secondary"
                aria-live="polite"
                title={`Gateway ${health.data?.version ?? "unknown"} (${health.data?.channel ?? "unknown"}) · PWA ${PWA_RELEASE_METADATA.releaseVersion} (${PWA_RELEASE_METADATA.releaseChannel}) · ${PWA_RELEASE_METADATA.sourceCommit}`}
              >
                {environment}{authenticated ? " · Signed in" : ""}
              </div>
            )}
          </div>
          <div className="ml-auto flex items-center gap-2 sm:hidden">
            <RefreshPageButton />
            {humanState.data?.deviceTrusted ? (
              <RememberedAccessButton count={authorizationSummary.data?.activeCount ?? 0} />
            ) : null}
            <div ref={mobileMenuRef} className="relative">
              <button
                type="button"
                aria-controls="mobile-navigation"
                aria-expanded={mobileMenuOpen}
                aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
                onClick={() => setMobileMenuOpen((open) => !open)}
                className="grid size-11 place-items-center rounded-control border border-subtle bg-surface"
              >
                <span aria-hidden="true" className="grid gap-1">
                  <span className="block h-px w-4 bg-foreground" />
                  <span className="block h-px w-4 bg-foreground" />
                  <span className="block h-px w-4 bg-foreground" />
                </span>
              </button>
              {mobileMenuOpen ? (
                <div
                  id="mobile-navigation"
                  className="absolute right-0 top-[calc(100%+0.5rem)] w-56 rounded-dialog border border-subtle bg-surface p-2 shadow-2xl"
                >
                  {humanState.data?.deviceTrusted ? (
                    <nav aria-label="Mobile primary navigation" className="grid gap-1 text-sm">
                      <Link
                        to="/requests"
                        onClick={() => setMobileMenuOpen(false)}
                        className="rounded-control px-3 py-3 text-secondary"
                        activeProps={{ className: "bg-muted text-foreground" }}
                      >
                        Approval queue
                      </Link>
                      <Link
                        to="/activity"
                        onClick={() => setMobileMenuOpen(false)}
                        className="rounded-control px-3 py-3 text-secondary"
                        activeProps={{ className: "bg-muted text-foreground" }}
                      >
                        Activity
                      </Link>
                      <Link
                        to="/authorizations"
                        onClick={() => setMobileMenuOpen(false)}
                        className="rounded-control px-3 py-3 text-secondary"
                        activeProps={{ className: "bg-muted text-foreground" }}
                      >
                        Remembered access
                      </Link>
                      <Link
                        to="/management"
                        search={{ section: "approvers" }}
                        onClick={() => setMobileMenuOpen(false)}
                        className="rounded-control px-3 py-3 text-secondary"
                        activeProps={{ className: "bg-muted text-foreground" }}
                      >
                        Approver management
                      </Link>
                    </nav>
                  ) : null}
                  <div className={`${humanState.data?.deviceTrusted ? "mt-2 border-t border-subtle pt-2" : ""} px-3 py-2 text-xs text-secondary`}>
                    {health.isError ? (
                      <button
                        type="button"
                        onClick={() => void health.refetch()}
                        className="text-danger-text"
                      >
                        Gateway connection failed · Retry
                      </button>
                    ) : (
                      <p aria-live="polite">{environment}{authenticated ? " · Signed in" : ""}</p>
                    )}
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      </header>
      <main
        id="main-content"
        className="mx-auto min-w-0 max-w-[960px] px-4 pb-10 pt-[calc(5.25rem+env(safe-area-inset-top))] sm:px-6 sm:pb-16 sm:pt-[calc(8rem+env(safe-area-inset-top))]"
      >
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
        {humanState.data && !humanState.data.initialized ? (
          <BootstrapPage />
        ) : null}
        {humanState.data?.initialized && !humanState.data.authenticated ? <LoginPage /> : null}
        {humanState.data?.authenticated && !humanState.data.deviceTrusted ? (
          <DeviceSetupPage />
        ) : null}
        {humanState.data?.deviceTrusted ? <Outlet /> : null}
      </main>
    </div>
  );
}

function RememberedAccessButton({ count }: { count: number }) {
  const badge = count > 99 ? "99+" : String(count);
  return (
    <Link
      to="/authorizations"
      aria-label={`Remembered access, ${count} active`}
      title="Remembered access"
      className="relative grid size-11 place-items-center rounded-control border border-subtle bg-surface text-secondary transition-colors hover:text-foreground"
      activeProps={{ className: "text-foreground" }}
    >
      <svg
        aria-hidden="true"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.75"
        className="size-[18px]"
      >
        <path d="M12 3 4.5 6v5.3c0 4.6 3.1 8.3 7.5 9.7 4.4-1.4 7.5-5.1 7.5-9.7V6L12 3Z" />
        <path d="m8.7 12 2.1 2.1 4.5-4.5" />
      </svg>
      {count > 0 ? (
        <span className="absolute -right-1 -top-1 min-w-5 rounded-pill border-2 border-background bg-danger-text px-1 text-center font-mono text-[10px] font-semibold leading-4 text-background">
          {badge}
        </span>
      ) : null}
    </Link>
  );
}

function RefreshPageButton() {
  return (
    <button
      type="button"
      aria-label="Reload the entire page"
      title="Reload page"
      onClick={() => window.location.reload()}
      className="grid size-11 place-items-center rounded-control border border-subtle bg-surface text-secondary transition-colors hover:text-foreground"
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
