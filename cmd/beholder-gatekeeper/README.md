# Beholder v30 runtime candidate

This module contains the experimental Beholder approval integration shipped
inside the authenticated native OneNod archive. Its presence does not enable
model authority or install a privileged service. Root service installation is
an attended local operation after immutable Release provenance verification.

The v30 candidate supports multiple task directories, follows kernel process
identity across child requests, keeps overlapping tool observations ambiguous,
and separates observation lifetime from short-lived exact-request authority.
There is no trusted host call-to-spawn event: kernel ancestry and one eligible
observation provide an inference. Shared helpers, overlapping executions and
same-user session manipulation remain documented limitations. Attribution
ambiguity falls back to human approval.

The model receives ordered human messages, source-labelled tool history,
request facts and explicit coverage information. Human history is preserved
within a byte budget; other context can have declared gaps. Arbitrary task
text may contain sensitive information. No heuristic credential scanner is
used. Protocol-owned credentials and signing material remain isolated at their
sources. A model can misjudge authorization or injected content.

The production confirmation JSON, provider routing, credential reference,
installed service configuration and experiment records remain machine-local.
The Gatekeeper requires the compiled confirmation fingerprint before acquiring
its model credential. Tests use dummy data; the optional
BEHOLDER_CONFIRMED_CONFIG test validates a local deployment confirmation.

Builds and tests require the pinned Go version in go.mod and macOS for kernel
process inspection. Source builds are for development verification and must
not replace a verified installed Release. Ordinary Codex messages remain
fail-open when Hook capture fails; that failure does not create an AI allow.
