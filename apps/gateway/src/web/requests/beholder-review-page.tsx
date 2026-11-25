import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";

import { getBeholderTrace, getRequest, type BeholderTrace } from "../api";
import { reviewReason } from "../components/beholder-diagnostic";
import { InlineError, RequestListSkeleton, StatusBadge } from "../components/common";
import { usePageTitle, useSessionExpiryRecovery } from "../hooks/human";
import { effectiveStatus, formatDateTime, toErrorMessage } from "../utils/presentation";

export function BeholderReviewPage() {
  const { requestId } = useParams({ from: "/requests/$requestId/review" });
  usePageTitle("Model review · OneNod");
  const request = useQuery({ queryKey: ["request", requestId], queryFn: () => getRequest(requestId) });
  const primary = useQuery({
    queryKey: ["beholder-review", requestId, "primary"],
    queryFn: () => getBeholderTrace(requestId, "primary"),
    enabled: request.isSuccess,
    refetchInterval: (query) => query.state.data && query.state.data.phase !== "finished" ? 3_000 : false,
  });
  const comparison = useQuery({
    queryKey: ["beholder-review", requestId, "comparison"],
    queryFn: () => getBeholderTrace(requestId, "comparison"),
    enabled: request.isSuccess,
    refetchInterval: (query) => {
      if (query.state.data && query.state.data.phase !== "finished") return 5_000;
      if (query.state.data === null && primary.data &&
          Date.parse(primary.data.created_at) + 180_000 > Date.now()) return 5_000;
      return false;
    },
  });
  useSessionExpiryRecovery(request.error ?? primary.error ?? comparison.error);

  if (request.isPending) return <RequestListSkeleton />;
  if (request.isError) return <InlineError message={toErrorMessage(request.error)} onRetry={() => void request.refetch()} />;
  const status = effectiveStatus(request.data);
  const primaryResult = primary.data?.events.findLast((event) => event.kind === "result");
  const result = asRecord(primaryResult?.value);
  const reason = request.data.client.beholderDiagnostic || !result
    ? reviewReason(request.data)
    : result.error_code || result.model_used === false
      ? `The model review could not complete automatically.${status === "pending" ? " Human review is required." : ""}`
      : result.decision === "escalate"
      ? "The model requested human review."
      : status === "pending" && result.decision === "allow"
        ? "The model recommended approval, but automatic authorization was not completed."
        : reviewReason(request.data);
  return (
    <section aria-labelledby="review-title">
      <Link
        to={status === "pending" ? "/requests" : "/activity"}
        className="inline-flex min-h-11 items-center text-sm text-secondary underline decoration-subtle underline-offset-4"
      >
        ← {status === "pending" ? "Back to approvals" : "Back to activity"}
      </Link>
      <header className="mb-6 mt-2">
        <div className="mb-3"><StatusBadge status={status} /></div>
        <h1 id="review-title" className="text-2xl font-semibold tracking-[-0.03em]">Model review</h1>
        <p className="mt-2 text-sm text-secondary [overflow-wrap:anywhere]">{request.data.targetLabel}</p>
      </header>
      <div className="rounded-card border border-subtle bg-surface p-5">
        <h2 className="text-sm font-semibold">{status === "pending" ? "Why you are being asked" : "Authorization"}</h2>
        <p className="mt-2 text-sm leading-6 text-secondary">{reason}</p>
        {typeof result?.reason === "string" ? (
          <p className="mt-3 whitespace-pre-wrap text-sm leading-6 [overflow-wrap:anywhere]">{result.reason}</p>
        ) : null}
        {status === "pending" ? (
          <Link
            to="/requests"
            hash={`request-${requestId}`}
            className="mt-4 inline-flex min-h-11 items-center font-medium underline decoration-subtle underline-offset-4"
          >
            Review and decide
          </Link>
        ) : null}
      </div>

      <TraceSection
        title="Decision review"
        description="The decision uses a thinking-disabled model call. Only reasoning actually returned by the provider can be shown."
        trace={primary.data}
        loading={primary.isPending}
        error={primary.error}
        retry={() => void primary.refetch()}
      />
      <TraceSection
        title="Thinking-enabled comparison"
        description="This separate review is for observation only; it cannot approve the request."
        trace={comparison.data}
        loading={comparison.isPending}
        error={comparison.error}
        retry={() => void comparison.refetch()}
      />
    </section>
  );
}

function TraceSection({ title, description, trace, loading, error, retry }: {
  title: string;
  description?: string;
  trace: BeholderTrace | null | undefined;
  loading: boolean;
  error: unknown;
  retry: () => void;
}) {
  return (
    <section className="mt-6" aria-label={title}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-lg font-semibold">{title}</h2>
        {trace ? <span className="text-xs text-secondary">Available until {formatDateTime(trace.expires_at)}</span> : null}
      </div>
      {trace ? <p className="mt-1 text-xs text-secondary">Model requested: {trace.requested_model}</p> : null}
      {description ? <p className="mt-1 text-sm text-secondary">{description}</p> : null}
      {loading ? <p className="mt-3 text-sm text-secondary">Loading review…</p> : null}
      {error ? <div className="mt-3"><InlineError message={toErrorMessage(error)} onRetry={retry} /></div> : null}
      {trace === null ? (
        <div className="mt-3 rounded-card border border-subtle bg-surface p-4 text-sm leading-6 text-secondary">
          No Worker review is available for this request. It may predate the Worker, still be starting, or never have reached a model.
          <button type="button" onClick={retry} className="ml-1 font-medium text-foreground underline underline-offset-4">Check again</button>
        </div>
      ) : null}
      {trace ? <ReviewEvents trace={trace} /> : null}
    </section>
  );
}

function ReviewEvents({ trace }: { trace: BeholderTrace }) {
  const toolNames = new Map<string, string>();
  let round = 0;
  return (
    <div className="mt-3 grid gap-3">
      {trace.phase !== "finished" ? <p className="text-sm text-secondary">Review in progress…</p> : null}
      {trace.events.map((event, index) => {
        const value = asRecord(event.value);
        if (!value) return null;
        if (event.kind === "initial") {
          return (
            <details key={index} className="rounded-card border border-subtle bg-surface p-4 text-sm">
              <summary className="cursor-pointer font-medium">Review instructions and request</summary>
              <TextBlock label="Request" value={value.input} />
              <TextBlock label="Instructions" value={value.policy} />
            </details>
          );
        }
        if (event.kind === "assistant") {
          round += 1;
          const message = asRecord(value.message);
          if (!message) return null;
          const calls = Array.isArray(message.tool_calls) ? message.tool_calls : [];
          for (const call of calls) {
            const item = asRecord(call);
            const fn = asRecord(item?.function);
            if (typeof item?.id === "string" && typeof fn?.name === "string") toolNames.set(item.id, fn.name);
          }
          return (
            <div key={index} className="rounded-card border border-subtle bg-surface p-4">
              <h3 className="text-sm font-semibold">Step {round}</h3>
              {typeof value.response_model === "string" ? <p className="mt-1 text-xs text-secondary">Provider response model: {value.response_model}</p> : null}
              {typeof message.reasoning_content === "string" && message.reasoning_content ? (
                <TextBlock label="Model reasoning" value={message.reasoning_content} />
              ) : <p className="mt-3 text-xs text-secondary">The provider did not return reasoning for this step.</p>}
              {calls.map((call, callIndex) => {
                const item = asRecord(call);
                const fn = asRecord(item?.function);
                return <TextBlock key={callIndex} label={`Context requested · ${String(fn?.name ?? "unknown")}`} value={fn?.arguments} />;
              })}
              {typeof message.content === "string" && message.content ? <TextBlock label="Model response" value={message.content} /> : null}
            </div>
          );
        }
        if (event.kind === "tool") {
          const name = typeof value.tool_call_id === "string" ? toolNames.get(value.tool_call_id) : undefined;
          return (
            <details key={index} className="rounded-card border border-subtle bg-surface p-4 text-sm">
              <summary className="cursor-pointer font-medium">Context returned{ name ? ` · ${name}` : "" }</summary>
              <TextBlock label="Original result" value={value.content} />
            </details>
          );
        }
        if (event.kind === "result") {
          return (
            <div key={index} className="rounded-card border border-subtle bg-surface p-4 text-sm">
              <h3 className="font-semibold">Result · {String(value.decision ?? "unavailable")}</h3>
              <TextBlock label="Reason" value={value.reason} />
              {value.error_code ? <TextBlock label="Reason code" value={value.error_code} /> : null}
              {value.evidence_refs ? <TextBlock label="Evidence references" value={value.evidence_refs} /> : null}
            </div>
          );
        }
        return null;
      })}
    </div>
  );
}

function TextBlock({ label, value }: { label: string; value: unknown }) {
  if (value === undefined || value === null || value === "") return null;
  let text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  if (typeof value === "string") {
    try { text = JSON.stringify(JSON.parse(value), null, 2); } catch { /* Keep original text. */ }
  }
  return (
    <div className="mt-3 min-w-0">
      <p className="text-xs font-medium text-secondary">{label}</p>
      <pre className="mt-1 whitespace-pre-wrap break-words font-sans text-sm leading-6 [overflow-wrap:anywhere]">{text}</pre>
    </div>
  );
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}
