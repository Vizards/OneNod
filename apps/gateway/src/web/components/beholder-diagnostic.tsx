import type { BeholderDiagnostic } from "@onenod/protocol";

export function BeholderDiagnosticDisclosure({
  diagnostic,
}: {
  diagnostic: BeholderDiagnostic | undefined;
}) {
  if (!diagnostic) return null;
  const summary =
    diagnostic.code === "model-escalated"
      ? "Beholder requested human review"
      : diagnostic.model_called === false
        ? "Beholder could not reach a model decision"
        : "Beholder decision unavailable";
  return (
    <details className="mt-3 rounded-control border border-subtle px-3 py-2 text-xs text-secondary">
      <summary className="cursor-pointer py-1">{summary}</summary>
      <p className="mt-2">Diagnostic reported by the requester.</p>
      <dl className="mt-2 grid gap-2 [overflow-wrap:anywhere]">
        <div>
          <dt>Stage</dt>
          <dd>{diagnostic.stage}</dd>
        </div>
        <div>
          <dt>Reason code</dt>
          <dd>{diagnostic.code}</dd>
        </div>
        <div>
          <dt>Model called</dt>
          <dd>
            {diagnostic.model_called === undefined
              ? "Unknown"
              : diagnostic.model_called
                ? "Yes"
                : "No"}
          </dd>
        </div>
        <div>
          <dt>Trace ID</dt>
          <dd className="font-mono">{diagnostic.trace_id}</dd>
        </div>
        {diagnostic.evidence_id ? (
          <div>
            <dt>Evidence ID</dt>
            <dd className="font-mono">{diagnostic.evidence_id}</dd>
          </div>
        ) : null}
      </dl>
    </details>
  );
}
