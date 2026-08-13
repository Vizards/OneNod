import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type {
  SecretAuthorizationSummary,
  SshAuthorizationSummary,
} from "../api";

import {
  getHumanManagement,
  revokeSecretAuthorization,
  revokeSshAuthorization,
} from "../api";
import { ActionError, InlineError, PagePanelSkeleton } from "../components/common";
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import {
  applicationSignerCopy,
  formatDateTime,
  sshAuthorizationDurationCopy,
  toErrorMessage,
} from "../utils/presentation";

type ActiveAuthorization =
  | { kind: "secret"; value: SecretAuthorizationSummary }
  | { kind: "ssh"; value: SshAuthorizationSummary };

export function AuthorizationsPage() {
  usePageTitle("Remembered access · OneNod");
  const management = useQuery({
    queryFn: getHumanManagement,
    queryKey: ["management"],
  });
  useSessionExpiryRecovery(management.error);

  if (management.isPending) return <PagePanelSkeleton />;
  if (management.isError) {
    return (
      <InlineError
        message={toErrorMessage(management.error)}
        onRetry={() => void management.refetch()}
      />
    );
  }

  const requesterNames = new Map(
    management.data.requesters.map((requester) => [
      requester.deviceId,
      requester.displayName,
    ]),
  );
  const authorizations: ActiveAuthorization[] = [
    ...management.data.secretAuthorizations.map(
      (value): ActiveAuthorization => ({ kind: "secret", value }),
    ),
    ...management.data.sshAuthorizations.map(
      (value): ActiveAuthorization => ({ kind: "ssh", value }),
    ),
  ].sort(
    (left, right) =>
      Date.parse(right.value.createdAt) - Date.parse(left.value.createdAt),
  );

  return (
    <section aria-labelledby="authorizations-title">
      <p className="mb-2 font-mono text-xs uppercase tracking-[0.12em] text-secondary">
        Application access
      </p>
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h1
          id="authorizations-title"
          className="text-2xl font-semibold tracking-[-0.03em]"
        >
          Remembered access
        </h1>
        <span className="rounded-pill border border-subtle px-3 py-1.5 font-mono text-xs text-secondary">
          {authorizations.length} active
        </span>
      </div>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-secondary">
        These approvals apply to the whole cryptographically verified application
        on one requester Mac—not to the Agent task or conversation that created
        them. A shared runtime identity, such as Node, can cover multiple local
        programs using that runtime. Revoke access you no longer expect.
      </p>

      {authorizations.length > 0 ? (
        <ul className="mt-8 grid gap-3">
          {authorizations.map((authorization) => (
            <AuthorizationCard
              authorization={authorization}
              key={`${authorization.kind}:${authorization.value.id}`}
              requesterName={
                requesterNames.get(authorization.value.requesterDeviceId) ??
                authorization.value.requesterDeviceId
              }
            />
          ))}
        </ul>
      ) : (
        <div className="mt-8 rounded-card border border-subtle bg-surface p-6">
          <h2 className="font-medium">No remembered access</h2>
          <p className="mt-2 text-sm leading-6 text-secondary">
            Approving once never appears here. Duration approvals will be listed
            until they expire, are invalidated, or you revoke them.
          </p>
        </div>
      )}
    </section>
  );
}
function AuthorizationCard({
  authorization,
  requesterName,
}: {
  authorization: ActiveAuthorization;
  requesterName: string;
}) {
  const queryClient = useQueryClient();
  const revoke = useMutation({
    mutationFn: () =>
      authorization.kind === "secret"
        ? revokeSecretAuthorization(authorization.value.id)
        : revokeSshAuthorization(authorization.value.id),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["management"] });
    },
  });
  useSessionExpiryRecovery(revoke.error);
  const value = authorization.value;
  const target = authorization.kind === "secret"
    ? `${authorization.value.itemTitle} · ${authorization.value.fieldLabel}`
    : authorization.value.itemTitle;

  return (
    <li className="grid min-w-0 gap-5 rounded-card border border-subtle bg-surface p-5 sm:p-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
      <div className="min-w-0">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <span className="rounded-pill border border-subtle bg-muted px-2 py-1 font-mono text-[10px] uppercase tracking-[0.08em] text-secondary">
            {authorization.kind === "secret" ? "Secret field" : "SSH key"}
          </span>
          <span className="font-mono text-[11px] text-secondary">
            Item version {value.itemVersion}
          </span>
        </div>
        <h2 className="mt-3 break-words text-base font-medium">{target}</h2>
        <dl className="mt-5 grid gap-4 sm:grid-cols-3">
          <div className="min-w-0">
            <dt className="text-xs text-secondary">Application identity · verified</dt>
            <dd className="mt-1 break-words text-sm font-medium">
              {value.application}
            </dd>
            <dd className="mt-1 break-words font-mono text-[11px] text-secondary">
              {applicationSignerCopy(value.applicationIdentity)}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-secondary">Requester device · verified</dt>
            <dd className="mt-1 break-words text-sm font-medium">
              {requesterName}
            </dd>
          </div>
          <div className="min-w-0">
            <dt className="text-xs text-secondary">Ends</dt>
            <dd className="mt-1 break-words text-sm font-medium">
              {authorizationEndCopy(authorization)}
            </dd>
          </div>
        </dl>
        <p className="mt-4 text-xs text-secondary">
          Granted {formatDateTime(value.createdAt)} · Whole application
        </p>
        {authorization.kind === "ssh" ? (
          <p className="mt-3 break-all font-mono text-[11px] text-secondary">
            {authorization.value.fingerprint}
          </p>
        ) : null}
      </div>
      <button
        type="button"
        disabled={revoke.isPending}
        onClick={() => revoke.mutate()}
        className="h-10 w-full rounded-control border border-danger-border px-4 text-sm text-danger-text disabled:opacity-50 lg:w-auto"
      >
        {revoke.isPending ? "Revoking…" : "Revoke access"}
      </button>
      {revoke.isError ? (
        <ActionError error={revoke.error} onDismiss={() => revoke.reset()} compact />
      ) : null}
    </li>
  );
}

function authorizationEndCopy(authorization: ActiveAuthorization): string {
  const value = authorization.value;
  if (value.expiresAt) return formatDateTime(value.expiresAt);
  if (value.duration === "until-lock") return "When Lock mode is enabled";
  if (authorization.kind === "ssh" && value.duration === "until-agent-quits") {
    return "When this SSH Agent quits";
  }
  return sshAuthorizationDurationCopy[value.duration];
}
