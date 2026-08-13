import { startAuthentication } from "@simplewebauthn/browser";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import type { RequestSummary, SshAuthorizationDuration } from "@onenod/protocol";

import {
  beginApprovalDecision,
  beginGatewayUnlock,
  beginRequesterEnrollmentDecision,
  getHumanState,
  getRequesterEnrollments,
  getRequests,
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
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import {
  applicationSignerCopy,
  approvalQuestion,
  effectiveStatus,
  formatDateTime,
  formatTime,
  isPast,
  isRefreshableDecisionError,
  secretAuthorizationDurations,
  sshAuthorizationDurationCopy,
  sshAuthorizationDurations,
  toErrorMessage,
} from "../utils/presentation";

export function RequestsPage() {
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
              : "Unlocked. Requests may be approved once or through an active remembered authorization."}
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
      <div className="flex min-w-0 flex-col gap-5">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold leading-7 tracking-[-0.02em] [overflow-wrap:anywhere]">
            {approvalQuestion(request)}
          </h2>
          <dl className="mt-5 grid gap-4 rounded-card border border-subtle bg-muted p-4 sm:grid-cols-2">
            <div className="min-w-0">
              <dt className="text-xs text-secondary">
                Application identity · {request.client.identity.assurance === "verified-code-signature" ? "verified" : "unverified"}
              </dt>
              <dd className="mt-1 break-words text-sm font-medium">
                {request.client.application}
              </dd>
              {request.client.identity.assurance === "verified-code-signature" ? (
                <dd className="mt-1 break-words font-mono text-[11px] text-secondary">
                  {applicationSignerCopy(request.client.identity)}
                </dd>
              ) : null}
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
          {request.client.identity.assurance === "unverified" ? (
            <p className="mt-3 text-xs leading-5 text-secondary">
              OneNod could not cryptographically verify this application. Only a one-time approval is available; verify the requester device before approving.
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
  const authorizationResource = request.authorizationScope?.resource;
  const canRemember =
    Boolean(authorizationResource) &&
    request.client.identity.assurance === "verified-code-signature";
  const authorizationDurations = authorizationResource === "secret"
    ? secretAuthorizationDurations
    : sshAuthorizationDurations;

  return (
    <div className="grid w-full grid-cols-2 gap-3 sm:ml-auto sm:max-w-[560px] lg:grid-cols-[minmax(10rem,0.8fr)_minmax(18rem,1.2fr)]">
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
              aria-label={`Choose how long to remember this ${authorizationResource === "secret" ? "secret" : "SSH"} approval`}
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
            <div className="absolute bottom-[calc(100%+0.5rem)] right-0 z-50 w-80 max-w-[calc(100vw-2rem)] overflow-hidden rounded-card border border-subtle bg-surface p-1 shadow-2xl">
              <p className="px-3 py-2 text-xs leading-5 text-secondary">
                <strong className="font-medium text-foreground">
                  Application-wide, not task-scoped.
                </strong>{" "}
                OneNod cannot distinguish tasks or sessions inside {request.client.application}.
                Any request carrying this verified code-signing identity on {request.requesterName} may {authorizationResource === "secret" ? "read this exact 1Password field" : "use this SSH key"} while the approval is active.
                If the identity belongs to a shared runtime such as Node, this includes every local program using that same signed runtime.
              </p>
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
