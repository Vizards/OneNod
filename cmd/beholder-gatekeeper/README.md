# Beholder v32 runtime candidate

This module contains the experimental Beholder approval integration shipped
inside the authenticated native OneNod archive. Its presence does not enable
model authority or install a privileged service. Root service installation is
an attended local operation after immutable Release provenance verification.

The runtime supports multiple task directories and independent concurrent
executions. Each process retains all eligible same-task tool observations,
separately from short-lived exact-request authority. The model receives
overlapping candidates with their causal identity explicitly unresolved;
candidate count alone does not trigger human fallback. There is no trusted
host call-to-spawn event. Shared helpers, unrelated same-task candidates and
same-user session manipulation remain documented limitations. Process/task
conflicts and request replay still prevent authority.

The model receives ordered human messages, Agent explanations, current request
facts and explicit coverage information in one request, without API tools or
tool choice. Historical tool calls and results stay in local source evidence
and are excluded from both model variants. Capture coverage and model delivery
are recorded separately. Human history is preserved within a byte budget;
Agent and ambient messages reserve the remaining capacity before historical
tools, so unsent tools cannot displace delivered explanations. Other context
can have declared gaps. There is no generated history summary
or model-driven retrieval. Unsent tool history can contain material facts the
model will not assess; this is an explicit dogfooding limitation. Arbitrary task
text may contain sensitive information. No heuristic credential scanner is
used. Protocol-owned credentials and signing material remain isolated at their
sources. A model can misjudge authorization or injected content.

Benchmark plans are checked against the actual provider projection before
credential access. Opposite labels with identical projected inputs are rejected.
The archived R10 tool-output injection pair is therefore inapplicable to this
profile; its frozen cases and labels are not rewritten to manufacture a result.

The production confirmation JSON, provider routing, credential reference,
installed service configuration and experiment records remain machine-local.
The Gatekeeper requires the compiled confirmation fingerprint before acquiring
its model credential. Tests use dummy data; the optional
BEHOLDER_CONFIRMED_CONFIG test validates a local deployment confirmation.

Builds and tests require the pinned Go version in go.mod and macOS for kernel
process inspection. Source builds are for development verification and must
not replace a verified installed Release. Ordinary Codex messages remain
fail-open when Hook capture fails; that failure does not create an AI allow.
