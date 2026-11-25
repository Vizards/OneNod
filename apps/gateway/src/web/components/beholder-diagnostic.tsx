import { Link } from "@tanstack/react-router";
import type { RequestSummary } from "@onenod/protocol";

export function reviewReason(request: RequestSummary): string {
  const diagnostic = request.client.beholderDiagnostic;
  if (request.authorizationSource === "beholder-authoritative") return "Beholder approved this request.";
  if (!diagnostic) {
    return request.authorizationSource === "remembered-grant"
      ? "A remembered approval was used."
      : "No Beholder decision was attached to this request.";
  }
  if (diagnostic.code === "worker-decision-unavailable") {
    return "Beholder could not obtain a decision from its Worker, so human review was required.";
  }
  if (diagnostic.code === "agent-identity-mismatch") {
    return "Beholder did not recognize the running SSH Agent. The model was not called.";
  }
  if (diagnostic.code === "binding-extension-rejected") {
    return "Beholder could not bind this request to the SSH Agent. The model was not called.";
  }
  if (diagnostic.code === "execution-context-ended") {
    return "The original execution ended or changed before Beholder could authorize it.";
  }
  if (diagnostic.code === "authority-signing-failed") {
    return "Beholder could not sign its automatic authorization.";
  }
  if (diagnostic.model_called === false) return "Beholder could not begin the model review.";
  if (diagnostic.code === "model-escalated") return "The model requested human review.";
  if (diagnostic.model_called === true) return "Beholder could not complete automatic authorization after the model review.";
  return "Beholder could not confirm an automatic decision.";
}

export function BeholderReviewLink({ request, showReason = true }: {
  request: RequestSummary;
  showReason?: boolean;
}) {
  return (
    <div className="mt-3 text-sm">
      {showReason ? <p className="text-secondary">{reviewReason(request)}</p> : null}
      <Link
        to="/requests/$requestId/review"
        params={{ requestId: request.requestId }}
        className="inline-flex min-h-10 items-center font-medium underline decoration-subtle underline-offset-4 hover:decoration-foreground"
      >
        View model review <span aria-hidden="true" className="ml-1">↗</span>
      </Link>
    </div>
  );
}
