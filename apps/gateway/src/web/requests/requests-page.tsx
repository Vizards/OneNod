import { startAuthentication } from "@simplewebauthn/browser";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo } from "react";
import type {
  ApplicationRecognition,
  RequestSummary,
  SshAuthorizationDuration,
} from "@onenod/protocol";

import {
  beginApprovalDecision,
  beginGatewayUnlock,
  beginRequesterEnrollmentDecision,
  getHumanState,
  getRequesterEnrollments,
  getRequests,
  getServiceAccountQuota,
  lockGateway,
  verifyApprovalDecision,
  verifyGatewayUnlock,
  verifyRequesterEnrollmentDecision,
  type ApprovalDecision,
  type RequesterEnrollment,
} from "../api";
import {
  ActionError,
  EmptyQueue,
  InlineError,
  RequestListSkeleton,
  StatusBadge,
} from "../components/common";
import { LiveCountdown } from "../components/live-countdown";
import {
  useExpiryRefresh,
  useServerClock,
} from "../hooks/live-clock";
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import {
  approvalQuestion,
  effectiveStatus,
  formatDateTime,
  isPast,
  isRefreshableDecisionError,
  secretAuthorizationDurations,
  sshAuthorizationDurationCopy,
  sshAuthorizationDurations,
  toErrorMessage,
} from "../utils/presentation";

export function RequestsPage() {
  usePageTitle("Approval queue · OneNod");
  const queryClient = useQueryClient();
  const requests = useQuery({
    queryKey: ["requests"],
    queryFn: () => getRequests(undefined, true),
  });
  const enrollments = useQuery({
    queryKey: ["requester-enrollments"],
    queryFn: getRequesterEnrollments,
  });
  useSessionExpiryRecovery(requests.error ?? enrollments.error);
  const refreshQueue = (): void => {
    void Promise.all([
      queryClient.invalidateQueries({ queryKey: ["requests"] }),
      queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
    ]);
  };
  const serverTime = requests.data?.serverTime ?? enrollments.data?.serverTime;
  const now = useServerClock(serverTime, refreshQueue);
  const pendingRequests =
    requests.data?.requests.filter(
      (request) => effectiveStatus(request, now) === "pending",
    ) ?? [];
  const pendingEnrollments =
    enrollments.data?.enrollments.filter(
      (enrollment) =>
        enrollment.status === "pending" && !isPast(enrollment.expiresAt, now),
    ) ?? [];
  const deadlines = useMemo(
    () => [
      ...(requests.data?.requests.map((request) => ({
        expiresAt: request.expiresAt,
        id: `request:${request.requestId}`,
      })) ?? []),
      ...(enrollments.data?.enrollments.map((enrollment) => ({
        expiresAt: enrollment.expiresAt,
        id: `enrollment:${enrollment.id}`,
      })) ?? []),
    ],
    [enrollments.data?.enrollments, requests.data?.requests],
  );
  useExpiryRefresh(deadlines, now, refreshQueue);
  useRequestDeepLinkFocus(requests.isSuccess);

  return (
    <section aria-labelledby="requests-title">
      <header className="mb-4">
        <div className="flex items-center justify-between gap-3">
          <h1
            id="requests-title"
            className="text-2xl font-semibold tracking-[-0.03em] sm:text-[2rem] sm:leading-10"
          >
            Pending approvals
          </h1>
          <span className="shrink-0 rounded-pill border border-subtle bg-muted px-2.5 py-1 font-mono text-xs tabular-nums text-secondary">
            {pendingRequests.length + pendingEnrollments.length}
          </span>
        </div>
        <p className="mt-1 text-sm text-secondary">Review requests waiting for you.</p>
      </header>

      <LockModeControl />
      <ServiceAccountQuotaStatus />

      {pendingEnrollments.length > 0 ? (
        <section aria-labelledby="enrollment-title" className="mb-6">
          <div className="mb-2 flex items-center justify-between gap-3">
            <h2 id="enrollment-title" className="text-sm font-medium">
              Pending Agent registration
            </h2>
            <span className="font-mono text-xs tabular-nums text-secondary">
              {pendingEnrollments.length}
            </span>
          </div>
          <ul className="grid gap-3">
            {pendingEnrollments.map((enrollment) => (
              <RequesterEnrollmentCard
                enrollment={enrollment}
                key={enrollment.id}
                now={now}
              />
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
      {pendingRequests.length > 0 ? (
        <ul className="grid gap-3">
          {pendingRequests.map((request) => (
            <RequestCard key={request.requestId} now={now} request={request} />
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

function RequesterEnrollmentCard({
  enrollment,
  now,
}: {
  enrollment: RequesterEnrollment;
  now: number;
}) {
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
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
      ]);
    },
    onError: async (error) => {
      if (isRefreshableDecisionError(error)) {
        await queryClient.invalidateQueries({ queryKey: ["requester-enrollments"] });
      }
    },
  });
  useSessionExpiryRecovery(decision.error);

  const expired = isPast(enrollment.expiresAt, now);
  const disabled = decision.isPending || expired || enrollment.status !== "pending";

  return (
    <li className="rounded-card border border-warning-border bg-warning-muted/40 p-4">
      <div className="min-w-0">
        <span className="text-xs font-medium text-warning">
          {expired ? "Expired" : "New requester Mac"}
        </span>
        <h3 className="mt-1 truncate text-base font-medium">{enrollment.displayName}</h3>
      </div>
      <details className="group mt-2 border-t border-warning-border/60 pt-1">
        <summary className="flex min-h-11 cursor-pointer list-none items-center justify-between gap-3 text-sm text-secondary marker:content-none">
          <span>Registration details</span>
          <DisclosureChevron />
        </summary>
        <dl className="grid gap-3 pb-3 text-xs">
          <IdentityFact label="Device ID" value={enrollment.deviceId} />
          <IdentityFact label="Enrollment ID" value={enrollment.id} />
          <IdentityFact
            label="Public-key fingerprint"
            value={enrollment.publicKeyFingerprint}
          />
          <IdentityFact label="Requested" value={formatDateTime(enrollment.createdAt)} />
          <IdentityFact label="Expires" value={formatDateTime(enrollment.expiresAt)} />
        </dl>
      </details>
      <div className="grid grid-cols-2 gap-2">
        <button
          type="button"
          disabled={disabled}
          onClick={() => decision.mutate("reject")}
          className="grid min-h-12 place-items-center rounded-control border border-subtle bg-background px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
        >
          {decision.isPending && decision.variables === "reject" ? (
            "Verifying…"
          ) : expired ? (
            "Expired"
          ) : (
            <span className="grid leading-tight">
              <span>Reject</span>
              <span className="mt-0.5 text-[10px] font-normal tabular-nums text-secondary">
                <LiveCountdown expiresAt={enrollment.expiresAt} label="Expires" now={now} />
              </span>
            </span>
          )}
        </button>
        <button
          type="button"
          disabled={disabled}
          onClick={() => decision.mutate("approve")}
          className="h-11 rounded-control bg-foreground px-3 text-sm font-medium text-background disabled:cursor-not-allowed disabled:opacity-50"
        >
          {decision.isPending && decision.variables === "approve" ? "Verifying…" : "Register"}
        </button>
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
        queryClient.invalidateQueries({ queryKey: ["authorization-summary"] }),
      ]);
    },
  });
  useSessionExpiryRecovery(state.error ?? lockMode.error);
  const locked = state.data?.locked ?? false;
  const status = lockMode.isPending
    ? locked
      ? "Verify with your passkey…"
      : "Blocking new requests…"
    : locked
      ? "New requests blocked"
      : "Requests allowed";

  return (
    <section
      aria-labelledby="lock-mode-title"
      className={`mb-4 flex min-h-14 flex-wrap items-center justify-between gap-x-4 rounded-card border px-3 py-1.5 ${
        locked
          ? "border-danger-border bg-danger-muted"
          : "border-subtle bg-surface"
      }`}
    >
      <div className="min-w-0">
        <h2 id="lock-mode-title" className="text-sm font-medium">Lock mode</h2>
        <p className="truncate text-xs text-secondary">{status}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={locked}
        aria-label={locked ? "Unlock gateway" : "Lock gateway"}
        disabled={state.isPending || lockMode.isPending}
        onClick={() => lockMode.mutate(!locked)}
        className="relative h-11 w-12 shrink-0 disabled:opacity-50"
      >
        <span
          aria-hidden="true"
          className={`absolute inset-x-0 top-2 h-7 rounded-pill border transition-colors ${
            locked
              ? "border-danger-border bg-danger-text"
              : "border-subtle bg-muted"
          }`}
        >
          <span
            className={`absolute left-[3px] top-[3px] size-5 rounded-full bg-background transition-transform ${
              locked ? "translate-x-5" : "translate-x-0"
            }`}
          />
        </span>
      </button>
      {lockMode.isError ? (
        <div className="basis-full">
          <ActionError error={lockMode.error} onDismiss={() => lockMode.reset()} compact />
        </div>
      ) : null}
    </section>
  );
}

function ServiceAccountQuotaStatus() {
  const quota = useQuery({
    queryKey: ["service-account-quota"],
    queryFn: getServiceAccountQuota,
    refetchInterval: 60_000,
    refetchOnWindowFocus: "always",
  });
  useSessionExpiryRecovery(quota.error);
  const remaining = quota.data?.dailyRemaining;
  const limit = quota.data?.dailyLimit;
  const low = remaining !== undefined && limit !== undefined && remaining <= limit * 0.1;
  const status = quota.isPending
    ? "Checking…"
    : quota.data?.exhausted
      ? "Quota exhausted"
      : remaining === undefined || limit === undefined
        ? "24h remaining unavailable"
        : `${remaining.toLocaleString()} of ${limit.toLocaleString()} remaining`;

  return (
    <section
      aria-labelledby="service-account-quota-title"
      className={`mb-4 rounded-card border px-3 py-2.5 ${
        quota.data?.exhausted
          ? "border-danger-border bg-danger-muted"
          : low
            ? "border-warning-border bg-warning-muted/40"
            : "border-subtle bg-surface"
      }`}
      title={
        remaining === undefined
          ? "The Executor reports confirmed rate-limit exhaustion, but its SDK does not expose an authoritative account-wide remaining count."
          : "Authoritative account-wide 24-hour Service Account quota reported by 1Password."
      }
    >
      <div className="flex min-w-0 items-center justify-between gap-3">
        <h2 id="service-account-quota-title" className="text-sm font-medium">
          1Password quota
        </h2>
        <p
          className={`text-xs tabular-nums ${
            quota.data?.exhausted
              ? "text-danger-text"
              : low
                ? "text-warning"
                : "text-secondary"
          }`}
        >
          {status}
        </p>
      </div>
    </section>
  );
}

function RequestCard({ now, request }: { now: number; request: RequestSummary }) {
  const status = effectiveStatus(request, now);
  const decision = useRequestDecision(request.requestId);
  const canDecide = status === "pending";

  return (
    <li
      id={`request-${request.requestId}`}
      tabIndex={-1}
      className="scroll-mt-24 rounded-dialog border border-subtle bg-surface p-4 outline-none transition-[border-color,box-shadow] target:border-focus target:shadow-[0_0_0_1px_var(--color-focus)] sm:p-5"
    >
      <h2 className="text-lg font-semibold leading-6 tracking-[-0.02em] [overflow-wrap:anywhere]">
        {approvalQuestion(request)}
      </h2>
      <ApplicationIdentityDisclosure request={request} />
      <p className="mt-2 truncate text-xs text-secondary">
        {request.requesterName} · {formatDateTime(request.createdAt)}
      </p>
      <div className="mt-4">
        {canDecide ? (
          <ApprovalControls canDecide decision={decision} now={now} request={request} />
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

function ApplicationIdentityDisclosure({ request }: { request: RequestSummary }) {
  const identity = request.client.identity;
  const recognition = request.applicationRecognition;
  const warning = recognition !== "approved-before";
  const copy = applicationRecognitionCopy(recognition);
  const signer = applicationIdentitySigner(request);

  return (
    <details className="group mt-3 rounded-control border border-subtle bg-background/40">
      <summary className="flex min-h-11 cursor-pointer list-none items-center gap-2 px-3 py-2 marker:content-none">
        {warning ? (
          <span
            aria-hidden="true"
            className="grid size-4 shrink-0 place-items-center rounded-full border border-danger-border text-[10px] font-semibold text-danger-text"
          >
            !
          </span>
        ) : null}
        <span className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span
            className={`shrink-0 text-xs font-medium ${
              warning ? "text-danger-text" : "text-secondary"
            }`}
          >
            {copy}
          </span>
          <span className="min-w-0 break-words text-sm text-foreground">{signer}</span>
        </span>
        <DisclosureChevron />
      </summary>
      <dl className="grid gap-3 border-t border-subtle px-3 py-3 text-xs">
        <IdentityFact label="Application" value={request.client.application} />
        <IdentityFact
          label="Assurance"
          value={
            identity.assurance === "verified-code-signature"
              ? "Verified code signature"
              : "Not cryptographically verified"
          }
        />
        {identity.assurance === "verified-code-signature" ? (
          <>
            {identity.signerName ? (
              <IdentityFact label="Signer" value={identity.signerName} />
            ) : null}
            {identity.teamIdentifier ? (
              <IdentityFact label="Team ID" value={identity.teamIdentifier} />
            ) : null}
            <IdentityFact label="Signing identifier" value={identity.signingIdentifier} />
            <IdentityFact
              label="Application principal"
              value={identity.principalId}
            />
          </>
        ) : null}
      </dl>
    </details>
  );
}

function applicationRecognitionCopy(recognition: ApplicationRecognition): string {
  if (recognition === "unverified") {
    return "Unverified app";
  }
  if (recognition === "first-approval") {
    return "First request";
  }
  return "Known app";
}

function applicationIdentitySigner(request: RequestSummary): string {
  const identity = request.client.identity;
  if (identity.assurance !== "verified-code-signature") {
    return request.client.application;
  }
  return identity.signerName?.trim() || identity.signingIdentifier;
}

function IdentityFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid min-w-0 grid-cols-[7rem_minmax(0,1fr)] gap-3">
      <dt className="text-secondary">{label}</dt>
      <dd className="min-w-0 break-all font-mono text-foreground">{value}</dd>
    </div>
  );
}

function DisclosureChevron() {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 16 16"
      className="size-4 shrink-0 transition-transform group-open:rotate-180"
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
      );
    },
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["request", requestId] }),
        queryClient.invalidateQueries({ queryKey: ["requests"] }),
        queryClient.invalidateQueries({ queryKey: ["management"] }),
        queryClient.invalidateQueries({ queryKey: ["authorization-summary"] }),
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
  now,
  request,
}: {
  canDecide: boolean;
  decision: ReturnType<typeof useRequestDecision>;
  now: number;
  request: RequestSummary;
}) {
  const humanState = useQuery({
    queryKey: ["human-state"],
    queryFn: getHumanState,
  });
  const locked = humanState.data?.locked ?? false;
  const disabled = !canDecide || decision.isPending || locked;
  const authorizationResource = request.authorizationScope?.resource;
  const canRemember =
    Boolean(authorizationResource) &&
    request.client.identity.assurance === "verified-code-signature";
  const authorizationDurations = authorizationResource === "secret"
    ? secretAuthorizationDurations
    : sshAuthorizationDurations;

  return (
    <div className="grid w-full grid-cols-2 gap-2 sm:ml-auto sm:max-w-[560px]">
      <button
        type="button"
        aria-label={`Deny ${request.targetLabel}`}
        disabled={disabled}
        onClick={() => decision.mutate({ decision: "reject" })}
        className="grid min-h-12 place-items-center rounded-control border border-subtle bg-background px-4 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50"
      >
        {decision.isPending && decision.variables?.decision === "reject"
          ? "Verifying…"
          : (
              <span className="grid leading-tight">
                <span>Deny</span>
                <span className="mt-0.5 text-[10px] font-normal tabular-nums text-secondary">
                  <LiveCountdown expiresAt={request.expiresAt} label="Expires" now={now} />
                </span>
              </span>
            )}
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
            : "Approve"}
        </button>
        {canRemember ? (
          <details className="group relative">
            <summary
              aria-label={`Choose how long to remember this ${
                authorizationResource === "secret" ? "secret" : "SSH"
              } approval`}
              className="grid h-12 w-11 cursor-pointer list-none place-items-center rounded-r-control border-l border-background/20 bg-foreground text-background marker:content-none"
            >
              <DisclosureChevron />
            </summary>
            <div className="absolute bottom-[calc(100%+0.5rem)] right-0 z-50 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-card border border-subtle bg-surface p-1 shadow-2xl">
              <p className="px-3 pb-1 pt-2 text-xs text-secondary">
                Applies to the whole verified app.
              </p>
              <details className="px-3 pb-2 text-xs text-secondary">
                <summary className="min-h-7 cursor-pointer list-none py-1 font-medium text-foreground underline decoration-subtle underline-offset-4 marker:content-none">
                  Why?
                </summary>
                <p className="pb-1 leading-5">
                  OneNod cannot distinguish tasks inside {request.client.application}.
                  Any request with this same verified app signature on {request.requesterName}
                  may use the selected resource while access is active.
                </p>
              </details>
              {authorizationDurations.map((duration) => (
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
                  className="block min-h-11 w-full rounded-control px-3 py-2 text-left text-sm hover:bg-muted disabled:opacity-50"
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
