import { BeholderReviewLink } from "../components/beholder-diagnostic.js";
import { useInfiniteQuery } from "@tanstack/react-query";
import type { RequestSummary } from "@onenod/protocol";

import { getRequests } from "../api";
import {
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
      <div className="border-t border-subtle px-5 pb-2">
        <BeholderReviewLink request={request} showReason={false} />
      </div>
    </li>
  );
}
