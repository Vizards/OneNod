import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import type { RequestDetail, RequestSummary } from "@onenod/protocol";

import { getRequest, getRequests } from "../api";
import {
  Fact,
  InlineError,
  PageHeading,
  RequestListSkeleton,
  StatusBadge,
} from "../components/common";
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import {
  approvalActionCopy,
  effectiveStatus,
  formatDateTime,
  toErrorMessage,
} from "../utils/presentation";

export function ActivityPage() {
  usePageTitle("Activity · OneNod");
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
      <PageHeading
        id="activity-title"
        title="Activity"
        description="Review recent request outcomes. This page cannot approve requests."
      />

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
