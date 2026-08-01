import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import {
  useInfiniteQuery,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import {
  Link,
  Outlet,
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
} from "@tanstack/react-router";
import type {
  ApprovalAction,
  ApprovalStatus,
  RequestDetail,
  RequestSummary,
  SshAuthorizationDuration,
} from "@onenod/protocol";

import {
  ApiError,
  authorizeCredentialRegistration,
  authorizeBootstrapToken,
  beginApprovalDecision,
  beginBootstrapRegistration,
  beginGatewayUnlock,
  beginCredentialRegistration,
  beginCredentialRevoke,
  beginDeviceRegistration,
  beginDeviceRevoke,
  beginHumanSession,
  beginRequesterEnrollmentDecision,
  beginRequesterRename,
  beginRequesterRevoke,
  deletePushSubscription,
  getHumanState,
  getHumanManagement,
  getPushConfig,
  getRequest,
  getRequesterEnrollments,
  getRequests,
  getSystemHealth,
  lockGateway,
  putPushSubscription,
  revokeSshAuthorization,
  verifyApprovalDecision,
  verifyBootstrapRegistration,
  verifyCredentialRegistration,
  verifyCredentialRevoke,
  verifyDeviceRegistration,
  verifyDeviceRevoke,
  verifyHumanSession,
  verifyGatewayUnlock,
  verifyRequesterEnrollmentDecision,
  verifyRequesterRename,
  verifyRequesterRevoke,
  type ApprovalDecision,
  type DeviceRegistrationInput,
  type HumanCredentialSummary,
  type HumanDeviceSummary,
  type RequesterEnrollment,
  type RequesterSummary,
  type SshAuthorizationSummary,
} from "./api";
import {
  deviceProofMessage,
  getOrCreateDeviceIdentity,
  suggestedDeviceDetails,
} from "./device-identity";
import { consumeBootstrapFragment } from "./bootstrap-fragment";
import { PWA_RELEASE_METADATA } from "./release-metadata";

const statusCopy: Record<ApprovalStatus, string> = {
  approved: "Approved",
  consumed: "Released",
  authenticating: "Authenticating",
  denied: "Denied",
  error: "Needs attention",
  expired: "Expired",
  pending: "Pending",
  submitting: "Submitting",
};

const statusClass: Record<ApprovalStatus, string> = {
  approved: "border-success-border bg-success-muted text-success",
  consumed: "border-success-border bg-success-muted text-success",
  authenticating: "border-focus/40 bg-focus/10 text-focus",
  denied: "border-danger-border bg-danger-muted text-danger-text",
  error: "border-danger-border bg-danger-muted text-danger-text",
  expired: "border-subtle bg-muted text-secondary",
  pending: "border-warning-border bg-warning-muted text-warning",
  submitting: "border-focus/40 bg-focus/10 text-focus",
};

const sshAuthorizationDurationCopy: Record<SshAuthorizationDuration, string> = {
  "until-lock": "Until Lock mode",
  "until-agent-quits": "Until SSH Agent quits",
  "4-hours": "For 4 hours",
  "12-hours": "For 12 hours",
  "24-hours": "For 24 hours",
};

const sshAuthorizationDurations = Object.keys(
  sshAuthorizationDurationCopy,
) as SshAuthorizationDuration[];

function approvalActionCopy(action: ApprovalAction): string {
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

function approvalQuestion(request: RequestSummary): string {
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

const rootRoute = createRootRoute({
  component: RootLayout,
  notFoundComponent: NotFoundPage,
});

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  beforeLoad: () => {
    throw redirect({ to: "/requests" });
  },
});

const requestsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/requests",
  component: RequestsPage,
});

const activityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/activity",
  component: ActivityPage,
});

const managementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/management",
  component: ManagementPage,
});

const routeTree = rootRoute.addChildren([
  indexRoute,
  requestsRoute,
  activityRoute,
  managementRoute,
]);

export const router = createRouter({
  routeTree,
  defaultPreload: "intent",
  defaultPreloadStaleTime: 0,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

function RootLayout() {
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

  const environment = health.isSuccess
    ? environmentCopy(health.data.environment)
    : "Connecting";
  const authenticated = Boolean(humanState.data?.authenticated);
  const releaseMismatch = Boolean(
    health.data && health.data.version !== PWA_RELEASE_METADATA.releaseVersion,
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
                  to="/management"
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
                title={`Gateway ${health.data?.version ?? "unknown"} · PWA ${PWA_RELEASE_METADATA.releaseVersion} · ${PWA_RELEASE_METADATA.sourceCommit}`}
              >
                {environment}{authenticated ? " · Signed in" : ""}
              </div>
            )}
          </div>
          <div className="ml-auto flex items-center gap-2 sm:hidden">
            <RefreshPageButton />
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
                        to="/management"
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
        className="mx-auto min-w-0 max-w-[960px] px-4 pb-10 pt-[calc(6.5rem+env(safe-area-inset-top))] sm:px-6 sm:pb-16 sm:pt-[calc(8rem+env(safe-area-inset-top))]"
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

function useApprovalAppBadge(enabled: boolean): void {
  const requests = useQuery({
    enabled,
    queryKey: ["requests"],
    queryFn: () => getRequests(undefined, true),
  });
  const enrollments = useQuery({
    enabled,
    queryKey: ["requester-enrollments"],
    queryFn: getRequesterEnrollments,
  });

  useEffect(() => {
    if (!enabled || !requests.isSuccess || !enrollments.isSuccess) return;
    const pendingRequests = requests.data.requests.filter(
      (request) => effectiveStatus(request) === "pending",
    ).length;
    const pendingEnrollments = enrollments.data.enrollments.filter(
      (enrollment) => enrollment.status === "pending" && !isPast(enrollment.expiresAt),
    ).length;
    void updateAppBadge(pendingRequests + pendingEnrollments);
  }, [enabled, enrollments.data, enrollments.isSuccess, requests.data, requests.isSuccess]);
}

async function updateAppBadge(pendingCount: number): Promise<void> {
  const badgeNavigator = navigator as Navigator & {
    clearAppBadge?: () => Promise<void>;
    setAppBadge?: (contents?: number) => Promise<void>;
  };
  try {
    if (pendingCount > 0 && typeof badgeNavigator.setAppBadge === "function") {
      await badgeNavigator.setAppBadge(pendingCount);
      return;
    }
    if (typeof badgeNavigator.clearAppBadge === "function") {
      await badgeNavigator.clearAppBadge();
      return;
    }
    if (typeof badgeNavigator.setAppBadge === "function") {
      await badgeNavigator.setAppBadge(0);
    }
  } catch {
    // The approval queue remains authoritative when the platform rejects badging.
  }
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

function BootstrapPage() {
  usePageTitle("Initialize approver · OneNod");
  const queryClient = useQueryClient();
  const bootstrapToken = useRef<string | undefined>(
    bootstrapFragmentState.value.status === "ready"
      ? bootstrapFragmentState.value.token
      : undefined,
  );
  const [bootstrapStatus] = useState(bootstrapFragmentState.value.status);
  const [authorized, setAuthorized] = useState(false);
  const registration = useMutation({
    mutationFn: async () => {
      if (!authorized) {
        if (!bootstrapToken.current) {
          throw new Error("The one-time initialization link is missing or invalid.");
        }
        await authorizeBootstrapToken(bootstrapToken.current);
        bootstrapToken.current = undefined;
        bootstrapFragmentState.value = { status: "missing" };
        setAuthorized(true);
      }
      const challenge = await beginBootstrapRegistration();
      const response = await startRegistration({ optionsJSON: challenge.options });
      return verifyBootstrapRegistration(challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard eyebrow="Secure bootstrap" title="Register the first approval passkey">
      <p className="text-sm leading-6 text-secondary">
        This is the one-time initialization for this approval gateway.
        WebAuthn and your chosen passkey provider create the credential; the private key stays
        with that provider and the gateway stores only the public key.
      </p>
      {bootstrapStatus === "ready" ? (
        <p className="mt-5 rounded-card border border-subtle bg-muted p-4 text-sm leading-6 text-secondary">
          One-time initialization link accepted. Its secret fragment has already been removed
          from the address bar and exists only in this page memory.
        </p>
      ) : (
        <div className="mt-5 rounded-card border border-danger-border bg-danger-muted p-4 text-sm leading-6 text-danger-text">
          {bootstrapStatus === "missing"
            ? "This page was opened without its one-time initialization link. Return to the operator setup flow and open the complete URL it provides."
            : "This one-time initialization link is invalid. Return to the operator setup flow and generate a new deployment plan."}
        </div>
      )}
      {authorized ? (
        <div className="mt-4 rounded-card border border-success-border bg-success-muted p-4 text-sm text-success">
          Setup code accepted. Complete passkey registration within two minutes.
        </div>
      ) : null}
      {registration.isError ? (
        <ActionError error={registration.error} onDismiss={() => registration.reset()} />
      ) : null}
      <button
        type="button"
        disabled={
          registration.isPending ||
          (!authorized && bootstrapStatus !== "ready")
        }
        onClick={() => registration.mutate()}
        className={`mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-60 ${registration.isPending ? "cursor-wait" : "disabled:cursor-not-allowed"}`}
      >
        {registration.isPending
          ? "Waiting for passkey provider…"
          : authorized
            ? "Register passkey"
            : "Authorize and register passkey"}
      </button>
    </HumanGateCard>
  );
}

function LoginPage() {
  usePageTitle("Sign in to approvals · OneNod");
  const queryClient = useQueryClient();
  const login = useMutation({
    mutationFn: performHumanLogin,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard eyebrow="Human session" title="Open the approval queue">
      <p className="text-sm leading-6 text-secondary">
        Approval details are never public. Use a registered passkey to establish a viewing session.
        Every approval or rejection still requires fresh passkey verification.
      </p>
      {login.isError ? <ActionError error={login.error} onDismiss={() => login.reset()} /> : null}
      <button
        type="button"
        disabled={login.isPending}
        onClick={() => login.mutate()}
        className="mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:cursor-wait disabled:opacity-60"
      >
        {login.isPending ? "Waiting for passkey provider…" : "Sign in with a passkey"}
      </button>
    </HumanGateCard>
  );
}

function DeviceSetupPage() {
  usePageTitle("Register approval device · OneNod");
  const queryClient = useQueryClient();
  const suggested = suggestedDeviceDetails();
  const [label, setLabel] = useState(suggested.label);

  const registration = useMutation({
    mutationFn: async () => {
      const identity = await getOrCreateDeviceIdentity();
      const input: DeviceRegistrationInput = {
        device_id: identity.deviceId,
        label,
        platform: suggested.platform,
        public_key: identity.publicKey,
      };
      const challenge = await beginDeviceRegistration(input);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      const signature = await identity.sign(
        deviceProofMessage(
          "device_registration",
          challenge.challenge_id,
          challenge.device_challenge,
          identity.deviceId,
        ),
      );
      return verifyDeviceRegistration(challenge.challenge_id, signature, response);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["human-state"] });
    },
  });

  return (
    <HumanGateCard
      eyebrow="Approval device"
      title="Register this approval device"
    >
      <p className="text-sm leading-6 text-secondary">
        Your passkey proves your human identity. This PWA also creates a non-exportable local device key so this installation can be identified and revoked independently.
      </p>
      <label className="mt-5 block text-xs text-secondary" htmlFor="device-label">
        Device name
      </label>
      <input
        id="device-label"
        value={label}
        maxLength={80}
        onChange={(event) => setLabel(event.target.value)}
        className="mt-2 h-11 w-full rounded-control border border-subtle bg-background px-3 text-sm"
      />
      <div className="mt-4 rounded-card border border-subtle bg-muted p-4 text-sm leading-5 text-secondary">
        Any registered passkey may authorize this installation. No approval from another device is required.
      </div>
      {registration.isError ? (
        <ActionError error={registration.error} onDismiss={() => registration.reset()} />
      ) : null}
      <button
        type="button"
        disabled={!label.trim() || registration.isPending}
        onClick={() => registration.mutate()}
        className="mt-6 h-12 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-60"
      >
        {registration.isPending ? "Waiting for passkey provider…" : "Register with passkey"}
      </button>
    </HumanGateCard>
  );
}

function RequestsPage() {
  usePageTitle("Approval queue · OneNod");
  const requests = useQuery({
    queryKey: ["requests"],
    queryFn: () => getRequests(undefined, true),
  });
  const enrollments = useQuery({
    queryKey: ["requester-enrollments"],
    queryFn: getRequesterEnrollments,
  });
  useSessionExpiryRecovery(requests.error ?? enrollments.error);
  const pendingRequests =
    requests.data?.requests.filter(
      (request) => effectiveStatus(request) === "pending",
    ) ?? [];
  const pendingEnrollments =
    enrollments.data?.enrollments.filter(
      (enrollment) => enrollment.status === "pending" && !isPast(enrollment.expiresAt),
    ) ?? [];
  useRequestDeepLinkFocus(requests.isSuccess);

  return (
    <section aria-labelledby="requests-title">
      <div className="mb-8 flex items-end justify-between gap-4">
        <div>
          <p className="mb-2 font-mono text-xs uppercase tracking-[0.12em] text-secondary">
            Approval Queue
          </p>
          <h1
            id="requests-title"
            className="text-2xl font-semibold tracking-[-0.03em] sm:text-[2rem] sm:leading-10"
          >
            Pending approvals
          </h1>
          <p className="mt-3 max-w-xl text-sm leading-6 text-secondary">
            Approve or deny requests using the operation, local application, and verified requester device.
          </p>
        </div>
        <span className="whitespace-nowrap rounded-pill border border-subtle bg-muted px-3 py-1 font-mono text-xs tabular-nums text-secondary">
          {pendingRequests.length + pendingEnrollments.length}{" "}
          items
        </span>
      </div>

      <LockModeControl />

      {pendingEnrollments.length ? (
        <section aria-labelledby="enrollment-title" className="mb-10">
          <div className="mb-3 flex items-center justify-between">
            <h2 id="enrollment-title" className="text-sm font-medium">
              Pending Agent devices
            </h2>
            <span className="text-xs text-secondary">A device can submit requests only after registration</span>
          </div>
          <ul className="grid gap-3">
            {pendingEnrollments.map((enrollment) => (
              <RequesterEnrollmentCard key={enrollment.id} enrollment={enrollment} />
            ))}
          </ul>
        </section>
      ) : null}

      {requests.isPending || enrollments.isPending ? <RequestListSkeleton /> : null}
      {requests.isError ? (
        <InlineError
          message={toErrorMessage(requests.error)}
          onRetry={() => void requests.refetch()}
        />
      ) : null}
      {enrollments.isError && !requests.isError ? (
        <InlineError
          title="Unable to load device registrations"
          message={toErrorMessage(enrollments.error)}
          onRetry={() => void enrollments.refetch()}
        />
      ) : null}
      {requests.isSuccess &&
      enrollments.isSuccess &&
      pendingRequests.length === 0 &&
      pendingEnrollments.length === 0 ? (
        <EmptyQueue />
      ) : null}
      {pendingRequests.length ? (
        <ul className="grid gap-3">
          {pendingRequests.map((request) => (
            <RequestCard key={request.requestId} request={request} />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function useRequestDeepLinkFocus(ready: boolean): void {
  useEffect(() => {
    if (!ready || !window.location.hash.startsWith("#request-")) return;
    const frame = window.requestAnimationFrame(() => {
      const target = document.getElementById(window.location.hash.slice(1));
      target?.scrollIntoView({ behavior: "smooth", block: "center" });
      target?.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [ready]);
}

function RequesterEnrollmentCard({ enrollment }: { enrollment: RequesterEnrollment }) {
  const queryClient = useQueryClient();
  const decision = useMutation({
    mutationFn: async (value: ApprovalDecision) => {
      const challenge = await beginRequesterEnrollmentDecision(enrollment.id, value);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyRequesterEnrollmentDecision(
        enrollment.id,
        challenge.challenge_id,
        value,
        response,
      );
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] });
    },
    onError: async (error) => {
      if (isRefreshableDecisionError(error)) {
        await queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] });
      }
    },
  });
  useSessionExpiryRecovery(decision.error);

  const expired = isPast(enrollment.expiresAt);
  const disabled = decision.isPending || expired || enrollment.status !== "pending";

  return (
    <li className="rounded-card border border-warning-border bg-warning-muted/40 p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-2 flex min-w-0 flex-wrap items-center gap-2">
            <span className="rounded-pill border border-warning-border bg-warning-muted px-2.5 py-1 text-xs font-medium text-warning">
              {expired ? "Expired" : "Pending registration"}
            </span>
            <span className="min-w-0 break-all font-mono text-xs text-secondary">{enrollment.deviceId}</span>
          </div>
          <h3 className="text-base font-medium">{enrollment.displayName}</h3>
          <p className="mt-1 text-sm leading-5 text-secondary">
            Requested {formatDateTime(enrollment.createdAt)} · expires {formatTime(enrollment.expiresAt)}
          </p>
          <dl className="mt-3 grid gap-1 text-xs text-secondary">
            <div className="grid gap-1 sm:grid-cols-[92px_1fr]">
              <dt>Enrollment ID</dt>
              <dd className="break-all font-mono text-foreground">{enrollment.id}</dd>
            </div>
            <div className="grid gap-1 sm:grid-cols-[92px_1fr]">
              <dt>Public-key fingerprint</dt>
              <dd className="break-all font-mono text-foreground">
                {enrollment.publicKeyFingerprint}
              </dd>
            </div>
          </dl>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            disabled={disabled}
            onClick={() => decision.mutate("reject")}
            className="h-10 rounded-control border border-subtle bg-background px-3 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
          >
            {decision.isPending && decision.variables === "reject" ? "Verifying…" : "Reject"}
          </button>
          <button
            type="button"
            disabled={disabled}
            onClick={() => decision.mutate("approve")}
            className="h-10 rounded-control bg-foreground px-3 text-sm font-medium text-background disabled:cursor-not-allowed disabled:opacity-50"
          >
            {decision.isPending && decision.variables === "approve" ? "Verifying…" : "Register"}
          </button>
        </div>
      </div>
      {decision.isError ? (
        <ActionError error={decision.error} onDismiss={() => decision.reset()} compact />
      ) : null}
    </li>
  );
}

function LockModeControl() {
  const queryClient = useQueryClient();
  const state = useQuery({
    queryKey: ["human-state"],
    queryFn: getHumanState,
  });
  const lockMode = useMutation({
    mutationFn: async (locked: boolean) => {
      if (locked) return lockGateway();
      const challenge = await beginGatewayUnlock();
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyGatewayUnlock(challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
        queryClient.invalidateQueries({ queryKey: ["requests"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(state.error ?? lockMode.error);
  const locked = state.data?.locked ?? false;

  return (
    <section
      aria-labelledby="lock-mode-title"
      className={`mb-8 rounded-card border p-4 ${
        locked
          ? "border-danger-border bg-danger-muted"
          : "border-subtle bg-surface"
      }`}
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 id="lock-mode-title" className="text-sm font-medium">
            Lock mode
          </h2>
          <p className="mt-1 text-xs leading-5 text-secondary">
            {locked
              ? "Locked. New requester operations are rejected without an approval notification."
              : "Unlocked. Requests may be approved once or through an active SSH authorization."}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={locked}
          aria-label={locked ? "Unlock gateway" : "Lock gateway"}
          disabled={state.isPending || lockMode.isPending}
          onClick={() => lockMode.mutate(!locked)}
          className={`relative h-7 w-12 shrink-0 rounded-pill border transition-colors disabled:opacity-50 ${
            locked
              ? "border-danger-border bg-danger-text"
              : "border-subtle bg-muted"
          }`}
        >
          <span
            aria-hidden="true"
            className={`absolute left-[3px] top-[3px] size-5 rounded-full bg-background transition-transform ${
              locked ? "translate-x-5" : "translate-x-0"
            }`}
          />
        </button>
      </div>
      {lockMode.isPending && !locked ? (
        <p className="mt-3 text-xs text-secondary">
          Locking and rejecting pending requests…
        </p>
      ) : null}
      {lockMode.isPending && locked ? (
        <p className="mt-3 text-xs text-secondary">
          Verify your Passkey to leave Lock mode.
        </p>
      ) : null}
      {lockMode.isError ? (
        <ActionError error={lockMode.error} onDismiss={() => lockMode.reset()} compact />
      ) : null}
    </section>
  );
}

function RequestCard({ request }: { request: RequestSummary }) {
  const status = effectiveStatus(request);
  const decision = useRequestDecision(request.requestId);
  const canDecide = status === "pending";

  return (
    <li
      id={`request-${request.requestId}`}
      tabIndex={-1}
      className="scroll-mt-24 rounded-dialog border border-subtle bg-surface p-5 outline-none transition-[border-color,box-shadow] target:border-focus target:shadow-[0_0_0_1px_var(--color-focus)] sm:p-6"
    >
      <div className="grid gap-6 md:grid-cols-[minmax(0,1fr)_minmax(380px,420px)] md:items-end">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold leading-7 tracking-[-0.02em] [overflow-wrap:anywhere]">
            {approvalQuestion(request)}
          </h2>
          <dl className="mt-5 grid gap-4 rounded-card border border-subtle bg-muted p-4 sm:grid-cols-2">
            <div className="min-w-0">
              <dt className="text-xs text-secondary">Local application · advisory</dt>
              <dd className="mt-1 break-words text-sm font-medium">
                {request.client.application}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-secondary">Requester device · verified</dt>
              <dd className="mt-1 break-words text-sm font-medium">
                {request.requesterName}
              </dd>
            </div>
          </dl>
          <p className="mt-3 text-xs text-secondary">
            Expires{" "}
            <time dateTime={request.expiresAt}>{formatDateTime(request.expiresAt)}</time>
          </p>
          {request.client.source === "unavailable" ? (
            <p className="mt-3 text-xs leading-5 text-secondary">
              The local application could not be identified. Verify the requester device before approving.
            </p>
          ) : null}
        </div>
        {canDecide ? (
          <ApprovalControls
            canDecide
            decision={decision}
            request={request}
          />
        ) : (
          <StatusBadge status={status} />
        )}
      </div>
      {decision.isError ? (
        <ActionError error={decision.error} onDismiss={() => decision.reset()} compact />
      ) : null}
    </li>
  );
}

interface RequestDecisionInput {
  authorizationDuration?: SshAuthorizationDuration;
  decision: ApprovalDecision;
}

function useRequestDecision(requestId: string) {
  const queryClient = useQueryClient();
  const decision = useMutation({
    mutationFn: async (value: RequestDecisionInput) => {
      const challenge = await beginApprovalDecision(
        requestId,
        value.decision,
        value.authorizationDuration,
      );
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyApprovalDecision(
        requestId,
        challenge.challenge_id,
        value.decision,
        response,
        value.authorizationDuration,
      );
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["request", requestId] }),
        queryClient.invalidateQueries({ queryKey: ["requests"] }),
      ]);
    },
    onError: async (error) => {
      if (isRefreshableDecisionError(error)) {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ["request", requestId] }),
          queryClient.invalidateQueries({ queryKey: ["requests"] }),
        ]);
      }
    },
  });
  useSessionExpiryRecovery(decision.error);
  return decision;
}

function ApprovalControls({
  canDecide,
  decision,
  request,
}: {
  canDecide: boolean;
  decision: ReturnType<typeof useRequestDecision>;
  request: RequestSummary;
}) {
  const humanState = useQuery({
    queryKey: ["human-state"],
    queryFn: getHumanState,
  });
  const locked = humanState.data?.locked ?? false;
  const disabled = !canDecide || decision.isPending || locked;
  const canRemember =
    request.action === "ssh.sign" && Boolean(request.authorizationSession);

  return (
    <div className="grid grid-cols-2 gap-3">
      <button
        type="button"
        aria-label={`Deny ${request.targetLabel}`}
        disabled={disabled}
        onClick={() => decision.mutate({ decision: "reject" })}
        className="h-12 rounded-control border border-subtle bg-background px-4 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
      >
        {decision.isPending && decision.variables?.decision === "reject"
          ? "Verifying…"
          : "Deny"}
      </button>
      <div className="flex min-w-0">
        <button
          type="button"
          aria-label={`Approve ${request.targetLabel} once`}
          title="Approve once with Passkey verification"
          disabled={disabled}
          onClick={() => decision.mutate({ decision: "approve" })}
          className={`h-12 min-w-0 flex-1 whitespace-nowrap rounded-l-control bg-foreground px-4 text-sm font-medium text-background disabled:cursor-not-allowed disabled:opacity-50 ${
            canRemember ? "" : "rounded-r-control"
          }`}
        >
          {decision.isPending && decision.variables?.decision === "approve"
            ? "Verifying…"
            : (
                <>
                  Approve
                  <span className="hidden lg:inline"> with Passkey</span>
                </>
              )}
        </button>
        {canRemember ? (
          <details className="group relative">
            <summary
              aria-label="Choose how long to remember this SSH approval"
              className="grid h-12 w-11 cursor-pointer list-none place-items-center rounded-r-control border-l border-background/20 bg-foreground text-background marker:content-none"
            >
              <svg
                aria-hidden="true"
                viewBox="0 0 16 16"
                className="size-4"
                fill="none"
              >
                <path
                  d="m4 6 4 4 4-4"
                  stroke="currentColor"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="1.5"
                />
              </svg>
            </summary>
            <div className="absolute bottom-[calc(100%+0.5rem)] right-0 z-50 w-64 overflow-hidden rounded-card border border-subtle bg-surface p-1 shadow-2xl">
              <p className="px-3 py-2 text-xs leading-5 text-secondary">
                Allow this {request.authorizationSession?.scopeKind === "terminal-session" ? "application and terminal session" : "application"} to use this SSH key.
              </p>
              {sshAuthorizationDurations.map((duration) => (
                <button
                  key={duration}
                  type="button"
                  disabled={disabled}
                  onClick={() =>
                    decision.mutate({
                      authorizationDuration: duration,
                      decision: "approve",
                    })
                  }
                  className="block w-full rounded-control px-3 py-2 text-left text-sm hover:bg-muted disabled:opacity-50"
                >
                  {sshAuthorizationDurationCopy[duration]}
                </button>
              ))}
            </div>
          </details>
        ) : null}
      </div>
    </div>
  );
}

function ActivityPage() {
  usePageTitle("Request activity · OneNod");
  const requests = useInfiniteQuery({
    initialPageParam: undefined as string | undefined,
    queryKey: ["requests", "activity"],
    queryFn: ({ pageParam }) => getRequests(pageParam),
    getNextPageParam: (page) => page.nextCursor,
  });
  useSessionExpiryRecovery(requests.error);
  const activity = requests.data?.pages.flatMap((page) => page.requests) ?? [];

  return (
    <section aria-labelledby="activity-title">
      <div className="mb-8">
        <p className="mb-2 font-mono text-xs uppercase tracking-[0.12em] text-secondary">
          Activity
        </p>
        <h1
          id="activity-title"
          className="text-2xl font-semibold tracking-[-0.03em] sm:text-[2rem] sm:leading-10"
        >
          Recent requests
        </h1>
        <p className="mt-3 max-w-xl text-sm leading-6 text-secondary">
          A bounded history of request outcomes. This page cannot approve requests.
        </p>
      </div>

      {requests.isPending ? <RequestListSkeleton /> : null}
      {requests.isError ? (
        <InlineError
          message={toErrorMessage(requests.error)}
          onRetry={() => void requests.refetch()}
        />
      ) : null}
      {requests.isSuccess && activity.length === 0 ? (
        <div className="grid min-h-64 place-items-center rounded-card border border-dashed border-subtle bg-surface px-6 text-center">
          <div>
            <h2 className="text-base font-medium">No recent activity</h2>
            <p className="mt-2 text-sm text-secondary">
              Completed requests appear here.
            </p>
          </div>
        </div>
      ) : null}
      {activity.length ? (
        <ul className="grid gap-3">
          {activity.map((request) => (
            <ActivityCard key={request.requestId} request={request} />
          ))}
        </ul>
      ) : null}
      {requests.hasNextPage ? (
        <div className="mt-6 flex justify-center">
          <button
            type="button"
            disabled={requests.isFetchingNextPage}
            onClick={() => void requests.fetchNextPage()}
            className="h-10 rounded-control border border-subtle bg-surface px-4 text-sm font-medium hover:border-subtle-active disabled:opacity-50"
          >
            {requests.isFetchingNextPage ? "Loading…" : "Load older activity"}
          </button>
        </div>
      ) : null}
    </section>
  );
}

function ActivityCard({ request }: { request: RequestSummary }) {
  const [expanded, setExpanded] = useState(false);
  const status = effectiveStatus(request);

  return (
    <li className="rounded-card border border-subtle bg-surface">
      <div className="grid gap-4 p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <StatusBadge status={status} />
            <span className="text-xs text-secondary">
              {approvalActionCopy(request.action)}
            </span>
          </div>
          <h2 className="text-base font-medium [overflow-wrap:anywhere]">
            {request.targetLabel}
          </h2>
          <p className="mt-2 text-sm leading-5 text-secondary">
            {request.client.application}
            <span aria-hidden="true"> · </span>
            {request.requesterName}
          </p>
        </div>
        <time
          dateTime={request.createdAt}
          className="font-mono text-xs tabular-nums text-secondary"
        >
          {formatDateTime(request.createdAt)}
        </time>
      </div>
      <details
        onToggle={(event) => setExpanded(event.currentTarget.open)}
        className="border-t border-subtle"
      >
        <summary className="cursor-pointer select-none px-5 py-3 text-sm text-secondary">
          Technical details
        </summary>
        {expanded ? <ActivityTechnicalDetails request={request} /> : null}
      </details>
    </li>
  );
}

function ActivityTechnicalDetails({ request }: { request: RequestSummary }) {
  const detail = useQuery({
    queryKey: ["request", request.requestId],
    queryFn: () => getRequest(request.requestId),
  });
  useSessionExpiryRecovery(detail.error);

  if (detail.isPending) {
    return (
      <p className="border-t border-subtle px-5 py-4 text-sm text-secondary">
        Loading diagnostic evidence…
      </p>
    );
  }
  if (detail.isError) {
    return (
      <div className="border-t border-subtle p-5">
        <InlineError
          title="Unable to load diagnostic evidence"
          message={toErrorMessage(detail.error)}
          onRetry={() => void detail.refetch()}
        />
      </div>
    );
  }

  return <ActivityFacts request={detail.data} />;
}

function ActivityFacts({ request }: { request: RequestDetail }) {
  return (
    <dl className="divide-y divide-subtle border-t border-subtle">
      <Fact label="Request ID" value={request.requestId} mono />
      <Fact label="Created" value={formatDateTime(request.createdAt)} />
      <Fact label="Expires" value={formatDateTime(request.expiresAt)} />
      <Fact label="Item version" value={String(request.verifiedVersion)} mono />
      <Fact label="Client observation" value={request.client.source} />
      {request.verifiedFacts.map((fact) => (
        <Fact
          key={`${fact.label}:${fact.value}`}
          label={fact.label}
          value={fact.value}
        />
      ))}
    </dl>
  );
}

function ManagementPage() {
  usePageTitle("Approver management · OneNod");
  const queryClient = useQueryClient();
  const management = useQuery({ queryFn: getHumanManagement, queryKey: ["management"] });
  const push = useQuery({ queryFn: getPushConfig, queryKey: ["push-config"] });
  const [pushError, setPushError] = useState<unknown>();
  const [pushPending, setPushPending] = useState(false);
  useSessionExpiryRecovery(management.error ?? push.error);

  async function enablePush(): Promise<void> {
    setPushPending(true);
    setPushError(undefined);
    try {
      if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
        throw new Error("This browser does not support Web Push.");
      }
      if (!push.data?.configured || !push.data.public_key) {
        throw new Error("The server has no VAPID key configured.");
      }
      const permission = await Notification.requestPermission();
      if (permission !== "granted") throw new Error("System notification permission was not granted.");
      const registration = await navigator.serviceWorker.ready;
      const existing = await registration.pushManager.getSubscription();
      const subscription =
        existing ??
        (await registration.pushManager.subscribe({
          applicationServerKey: decodeBase64Url(push.data.public_key),
          userVisibleOnly: true,
        }));
      await putPushSubscription(subscription.toJSON());
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]);
    } catch (error) {
      setPushError(error);
    } finally {
      setPushPending(false);
    }
  }

  async function disablePush(): Promise<void> {
    setPushPending(true);
    setPushError(undefined);
    try {
      await deletePushSubscription();
      const registration = await navigator.serviceWorker.ready;
      const subscription = await registration.pushManager.getSubscription();
      await subscription?.unsubscribe();
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]);
    } catch (error) {
      setPushError(error);
    } finally {
      setPushPending(false);
    }
  }

  if (management.isPending) return <PagePanelSkeleton />;
  if (management.isError) {
    return <InlineError message={toErrorMessage(management.error)} onRetry={() => void management.refetch()} />;
  }

  return (
    <section aria-labelledby="management-title">
      <p className="mb-2 font-mono text-xs uppercase tracking-[0.12em] text-secondary">
        Human control plane
      </p>
      <h1 id="management-title" className="text-2xl font-semibold tracking-[-0.03em]">
        Approver management
      </h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-secondary">
        A passkey verifies your human identity. A device key identifies one PWA installation. Revoking a device does not delete a passkey synced to other devices.
      </p>

      <section className="mt-10 rounded-card border border-subtle bg-surface p-5" aria-labelledby="push-title">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 id="push-title" className="text-base font-medium">System notifications on this device</h2>
            <p className="mt-2 text-sm leading-5 text-secondary">
              Notifications reveal only that a new request exists. They never show the item, field, or client observation on the lock screen.
            </p>
          </div>
          <button
            type="button"
            disabled={pushPending || push.isPending || !push.data?.configured}
            onClick={() => void (push.data?.enabled ? disablePush() : enablePush())}
            className="h-10 rounded-control border border-subtle bg-background px-4 text-sm font-medium disabled:opacity-50"
          >
            {pushPending ? "Working…" : push.data?.enabled ? "Disable notifications" : "Enable notifications"}
          </button>
        </div>
        {pushError ? <ActionError error={pushError} onDismiss={() => setPushError(undefined)} compact /> : null}
        {!push.data?.configured ? (
          <p className="mt-3 text-xs text-warning">The server has no VAPID key. Subscriptions remain unavailable until deployment setup is complete.</p>
        ) : null}
      </section>

      <section className="mt-10" aria-labelledby="devices-title">
        <div className="flex items-center justify-between gap-4">
          <h2 id="devices-title" className="text-base font-medium">Approval devices</h2>
          <span className="font-mono text-xs text-secondary">{management.data.devices.length} devices</span>
        </div>
        <ul className="mt-4 grid gap-3">
          {management.data.devices.map((device) => (
            <HumanDeviceCard
              key={device.id}
              device={device}
              canRevoke={management.data.devices.length > 1}
            />
          ))}
        </ul>
      </section>

      <section className="mt-10" aria-labelledby="requesters-title">
        <div className="flex items-center justify-between gap-4">
          <h2 id="requesters-title" className="text-base font-medium">
            Requester devices
          </h2>
          <span className="font-mono text-xs text-secondary">
            {management.data.requesters.length} requesters
          </span>
        </div>
        <p className="mt-2 text-sm leading-5 text-secondary">
          These Origin-scoped public keys identify enrolled Macs that may submit
          approval requests. They do not identify an application or authorize
          approval. Revoking one immediately blocks new requests, status polling,
          and result consumption from that requester.
        </p>
        <ul className="mt-4 grid gap-3">
          {management.data.requesters.map((requester) => (
            <RequesterCard key={requester.deviceId} requester={requester} />
          ))}
        </ul>
      </section>

      <section className="mt-10" aria-labelledby="ssh-authorizations-title">
        <div className="flex items-center justify-between gap-4">
          <h2 id="ssh-authorizations-title" className="text-base font-medium">
            Remembered SSH approvals
          </h2>
          <span className="font-mono text-xs text-secondary">
            {management.data.sshAuthorizations.length} remembered
          </span>
        </div>
        <p className="mt-2 text-sm leading-5 text-secondary">
          These grants remember one SSH key for one locally observed application
          session. Lock mode rejects their use immediately.
        </p>
        {management.data.sshAuthorizations.length > 0 ? (
          <ul className="mt-4 grid gap-3">
            {management.data.sshAuthorizations.map((authorization) => (
              <SshAuthorizationCard
                authorization={authorization}
                key={authorization.id}
                requesterName={
                  management.data.requesters.find(
                    (requester) =>
                      requester.deviceId === authorization.requesterDeviceId,
                  )?.displayName ?? authorization.requesterDeviceId
                }
              />
            ))}
          </ul>
        ) : (
          <p className="mt-4 rounded-card border border-subtle bg-surface p-4 text-sm text-secondary">
            No SSH approvals are currently remembered.
          </p>
        )}
      </section>

      <CredentialsSection credentials={management.data.credentials} />
    </section>
  );
}

function SshAuthorizationCard({
  authorization,
  requesterName,
}: {
  authorization: SshAuthorizationSummary;
  requesterName: string;
}) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: () => revokeSshAuthorization(authorization.id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  useSessionExpiryRecovery(revoke.error);

  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        <h3 className="font-medium">{authorization.itemTitle}</h3>
        <p className="mt-2 text-sm text-secondary">
          {authorization.application} · {requesterName} ·{" "}
          {authorization.scopeKind === "terminal-session"
            ? "Application and terminal session"
            : "Application"}{" "}
          · {sshAuthorizationDurationCopy[authorization.duration]}
        </p>
        {authorization.expiresAt ? (
          <p className="mt-2 text-xs text-secondary">
            Expires {formatDateTime(authorization.expiresAt)}
          </p>
        ) : null}
        <p className="mt-3 break-all font-mono text-[11px] text-secondary">
          {authorization.fingerprint}
        </p>
      </div>
      <button
        type="button"
        disabled={revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-50"
      >
        {revoke.isPending ? "Revoking…" : "Revoke"}
      </button>
      {revoke.isError ? (
        <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
      ) : null}
    </li>
  );
}

function RequesterCard({ requester }: { requester: RequesterSummary }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [displayName, setDisplayName] = useState(requester.displayName);
  const rename = useMutation({
    mutationFn: async (nextDisplayName: string) => {
      const challenge = await beginRequesterRename(
        requester.deviceId,
        nextDisplayName,
      );
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyRequesterRename(
        requester.deviceId,
        challenge.challenge_id,
        response,
      );
    },
    onSuccess: async () => {
      setEditing(false);
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginRequesterRevoke(requester.deviceId);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyRequesterRevoke(
        requester.deviceId,
        challenge.challenge_id,
        response,
      );
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(rename.error ?? revoke.error);
  const normalizedName = displayName.trim();

  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        {editing ? (
          <div className="max-w-sm">
            <label htmlFor={`requester-name-${requester.deviceId}`} className="text-xs text-secondary">
              Requester device name
            </label>
            <input
              id={`requester-name-${requester.deviceId}`}
              autoFocus
              maxLength={80}
              value={displayName}
              onChange={(event) => setDisplayName(event.target.value)}
              className="mt-2 h-10 w-full rounded-control border border-subtle bg-background px-3 text-sm outline-none focus:border-focus"
            />
          </div>
        ) : (
          <h3 className="font-medium">{requester.displayName}</h3>
        )}
        <p className="mt-2 text-xs text-secondary">
          Enrolled {formatDateTime(requester.createdAt)}
        </p>
        <p className="mt-3 max-w-full break-all font-mono text-[11px] text-secondary">
          Device {requester.deviceId}
        </p>
        <p className="mt-2 max-w-full break-all font-mono text-[11px] text-secondary">
          Fingerprint {requester.publicKeyFingerprint}
        </p>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:flex">
        {editing ? (
          <>
            <button
              type="button"
              disabled={rename.isPending}
              onClick={() => {
                setDisplayName(requester.displayName);
                setEditing(false);
                rename.reset();
              }}
              className="h-10 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={
                rename.isPending ||
                normalizedName.length === 0 ||
                normalizedName === requester.displayName
              }
              onClick={() => rename.mutate(normalizedName)}
              className="h-10 rounded-control bg-foreground px-3 text-sm text-background disabled:opacity-40"
            >
              {rename.isPending ? "Verifying…" : "Save name"}
            </button>
          </>
        ) : (
          <button
            type="button"
            disabled={revoke.isPending}
            onClick={() => setEditing(true)}
            className="h-10 rounded-control border border-subtle px-3 text-sm disabled:opacity-40"
          >
            Rename device
          </button>
        )}
        {!editing ? (
          <button
            type="button"
            disabled={revoke.isPending}
            onClick={() => revoke.mutate()}
            className="h-10 rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40"
          >
            {revoke.isPending ? "Verifying…" : "Revoke requester"}
          </button>
        ) : null}
      </div>
      {rename.isError ? (
        <ActionError error={rename.error} onDismiss={() => rename.reset()} compact />
      ) : null}
      {revoke.isError ? (
        <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
      ) : null}
    </li>
  );
}

function HumanDeviceCard({
  canRevoke,
  device,
}: {
  canRevoke: boolean;
  device: HumanDeviceSummary;
}) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginDeviceRevoke(device.id);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyDeviceRevoke(device.id, challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    },
  });
  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-medium">{device.label}</h3>
          {device.current ? <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">Current device</span> : null}
          {device.pushEnabled ? <span className="rounded-pill bg-success-muted px-2 py-1 text-xs text-success">Push enabled</span> : null}
        </div>
        <p className="mt-2 text-xs text-secondary">
          {device.platform} · last active {formatDateTime(device.lastSeenAt)}
        </p>
      </div>
      <button
        type="button"
        disabled={!canRevoke || revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:w-auto"
      >
        {revoke.isPending ? "Verifying…" : "Revoke device"}
      </button>
      {revoke.isError ? <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact /> : null}
    </li>
  );
}

function CredentialsSection({ credentials }: { credentials: HumanCredentialSummary[] }) {
  const queryClient = useQueryClient();
  const [label, setLabel] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      const authorization = await beginCredentialRegistration(label);
      const authorizationResponse = await startAuthentication({ optionsJSON: authorization.options });
      const registration = await authorizeCredentialRegistration(
        authorization.challenge_id,
        authorizationResponse,
      );
      const registrationResponse = await startRegistration({ optionsJSON: registration.options });
      return verifyCredentialRegistration(registration.challenge_id, registrationResponse);
    },
    onSuccess: async () => {
      setLabel("");
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  return (
    <section className="mt-10" aria-labelledby="credentials-title">
      <h2 id="credentials-title" className="text-base font-medium">Human passkey credentials</h2>
      <p className="mt-2 text-sm leading-5 text-secondary">
        One synced passkey can serve multiple devices. Adding a passkey here creates a separate WebAuthn credential for recovery or isolation.
      </p>
      <div className="mt-4 grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_auto]">
        <input
          value={label}
          maxLength={80}
          onChange={(event) => setLabel(event.target.value)}
          placeholder="New credential name"
          className="h-11 min-w-0 flex-1 rounded-control border border-subtle bg-background px-3 text-sm"
        />
        <button
          type="button"
          disabled={!label.trim() || add.isPending}
          onClick={() => add.mutate()}
          className="h-11 w-full rounded-control bg-foreground px-4 text-sm font-medium text-background disabled:opacity-50 sm:w-auto"
        >
          {add.isPending ? "Registering…" : "Add passkey"}
        </button>
      </div>
      {add.isError ? <ActionError error={add.error} onDismiss={() => add.reset()} compact /> : null}
      <ul className="mt-4 grid gap-3">
        {credentials.map((credential) => (
          <HumanCredentialCard
            key={credential.id}
            credential={credential}
            canRevoke={credentials.length > 1}
          />
        ))}
      </ul>
    </section>
  );
}

function HumanCredentialCard({
  canRevoke,
  credential,
}: {
  canRevoke: boolean;
  credential: HumanCredentialSummary;
}) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: async () => {
      const challenge = await beginCredentialRevoke(credential.id);
      const response = await startAuthentication({ optionsJSON: challenge.options });
      return verifyCredentialRevoke(credential.id, challenge.challenge_id, response);
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    },
  });
  return (
    <li className="grid min-w-0 gap-4 rounded-card border border-subtle bg-surface p-5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="font-medium">{credential.label}</h3>
          {credential.current ? <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">Current credential</span> : null}
          {credential.backedUp ? <span className="rounded-pill bg-muted px-2 py-1 text-xs text-secondary">Synced</span> : null}
        </div>
        <p className="mt-2 text-xs text-secondary">
          {credential.deviceType} · last used {credential.lastUsedAt ? formatDateTime(credential.lastUsedAt) : "Unknown"}
        </p>
        <p className="mt-2 max-w-full break-all font-mono text-[11px] text-secondary">{credential.id}</p>
      </div>
      <button
        type="button"
        disabled={!canRevoke || revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 w-full rounded-control border border-danger-border px-3 text-sm text-danger-text disabled:opacity-40 sm:w-auto"
      >
        {revoke.isPending ? "Verifying…" : "Revoke credential"}
      </button>
      {revoke.isError ? <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact /> : null}
    </li>
  );
}

function HumanGateCard({
  children,
  eyebrow,
  title,
}: {
  children: React.ReactNode;
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

function HumanGateSkeleton() {
  return (
    <div
      aria-label="Checking approver state"
      aria-busy="true"
      className="mx-auto h-72 max-w-[520px] animate-pulse rounded-dialog border border-subtle bg-surface"
    />
  );
}

function Fact({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid min-w-0 gap-1 px-4 py-3 sm:grid-cols-[132px_minmax(0,1fr)] sm:gap-4">
      <dt className="text-xs text-secondary">{label}</dt>
      <dd className={`min-w-0 text-sm [overflow-wrap:anywhere] ${mono ? "font-mono tabular-nums" : ""}`}>{value}</dd>
    </div>
  );
}

function StatusBadge({ status }: { status: ApprovalStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-pill border px-2.5 py-1 text-xs font-medium ${statusClass[status]}`}
    >
      {statusCopy[status]}
    </span>
  );
}

function EmptyQueue() {
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

function InlineError({
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

function ActionError({
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

function RequestListSkeleton() {
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

function PagePanelSkeleton() {
  return (
    <div
      aria-label="Loading page"
      aria-busy="true"
      className="mx-auto h-[560px] max-w-[640px] animate-pulse rounded-dialog border border-subtle bg-surface"
    />
  );
}

function NotFoundPage() {
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

function useSessionExpiryRecovery(error: unknown): void {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!(error instanceof ApiError) || error.status !== 401) return;
    void queryClient.invalidateQueries({ queryKey: ["human-state"] });
  }, [error, queryClient]);
}

function usePageTitle(title: string): void {
  useEffect(() => {
    document.title = title;
  }, [title]);
}

function useHumanRealtime(enabled: boolean): void {
  const queryClient = useQueryClient();
  const reconnectTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let socket: WebSocket | undefined;
    let retryDelay = 500;

    const refreshAll = (): void => {
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: ["requests"] }),
        queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["push-config"] }),
        queryClient.invalidateQueries({ queryKey: ["human-state"] }),
      ]);
    };
    const connect = (): void => {
      if (stopped || socket?.readyState === WebSocket.OPEN || socket?.readyState === WebSocket.CONNECTING) {
        return;
      }
      const url = new URL("/v1/human/events", window.location.href);
      url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
      socket = new WebSocket(url);
      socket.onopen = () => {
        retryDelay = 500;
        refreshAll();
      };
      socket.onmessage = (event) => {
        let value: unknown;
        try {
          value = JSON.parse(String(event.data));
        } catch {
          return;
        }
        if (!value || typeof value !== "object") return;
        const message = value as { entity_id?: unknown; type?: unknown };
        if (message.type === "request.changed" && typeof message.entity_id === "string") {
          void Promise.all([
            queryClient.invalidateQueries({ queryKey: ["requests"] }),
            queryClient.invalidateQueries({ queryKey: ["request", message.entity_id] }),
          ]);
          return;
        }
        if (message.type === "requester-enrollment.changed") {
          void queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] });
          return;
        }
        if (message.type === "management.changed") {
          void queryClient.invalidateQueries({ queryKey: ["management"] });
          return;
        }
        if (message.type === "lock.changed") {
          void Promise.all([
            queryClient.invalidateQueries({ queryKey: ["human-state"] }),
            queryClient.invalidateQueries({ queryKey: ["requests"] }),
            queryClient.invalidateQueries({ queryKey: ["management"] }),
          ]);
          return;
        }
        if (message.type === "ready") refreshAll();
      };
      socket.onclose = (event) => {
        socket = undefined;
        if (stopped) return;
        if (event.code === 4401 || event.code === 4403) {
          void queryClient.invalidateQueries({ queryKey: ["human-state"] });
          return;
        }
        reconnectTimer.current = window.setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 2, 10_000);
      };
    };
    const handleOnline = (): void => connect();
    window.addEventListener("online", handleOnline);
    connect();
    return () => {
      stopped = true;
      window.removeEventListener("online", handleOnline);
      if (reconnectTimer.current !== undefined) window.clearTimeout(reconnectTimer.current);
      socket?.close(1000, "page_unmounted");
    };
  }, [enabled, queryClient, reconnectTimer]);
}

async function performHumanLogin(): Promise<{
  csrf_token: string;
  device_trusted: boolean;
  ok: true;
}> {
  const identity = await getOrCreateDeviceIdentity();
  const challenge = await beginHumanSession(identity.deviceId);
  const response = await startAuthentication({ optionsJSON: challenge.options });
  const signature = challenge.device_trusted
    ? await identity.sign(
        deviceProofMessage(
          "human_session",
          challenge.challenge_id,
          challenge.device_challenge,
          identity.deviceId,
        ),
      )
    : undefined;
  return verifyHumanSession(challenge.challenge_id, response, signature);
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function environmentCopy(value: string): string {
  if (value === "dev") return "Development";
  if (value === "prod") return "Production";
  return `${value} environment`;
}

function effectiveStatus(request: RequestSummary): ApprovalStatus {
  return request.status === "pending" && isPast(request.expiresAt) ? "expired" : request.status;
}

function isRefreshableDecisionError(error: unknown): boolean {
  return error instanceof ApiError && [401, 404, 409, 410].includes(error.status);
}

function isPast(value: string): boolean {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && timestamp <= Date.now();
}

function toErrorMessage(error: unknown): string {
  if (error instanceof DOMException && error.name === "NotAllowedError") {
    return "Passkey verification was cancelled or timed out, or this passkey is unavailable for the current site.";
  }
  if (error instanceof Error) return error.message;
  return "An unknown error occurred. Reload the page and try again.";
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", { hour: "2-digit", minute: "2-digit" }).format(
    new Date(value),
  );
}

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "medium",
  }).format(new Date(value));
}
const bootstrapFragmentState = {
  value: consumeBootstrapFragment(window.location, window.history),
};
