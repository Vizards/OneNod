# Beholder v33 runtime candidate

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

The R16 production profile uses `deepseek-flash`. Its first request contains
only the pending operation and target, with no history, selected human goal or
generated progress summary. Six read-only tools expose the original request
and task snapshot: `read_request`, `query_context`, `search_context`, `read_call`,
`read_record` and `read_next`. Queries default to newest user/assistant messages;
explicit roles and kinds expose host messages and runtime records. Search hits
include original payloads. Call IDs are matched exactly without guessing aliases
or treating a still-running result as completion.

Each admission captures an immutable file prefix, including its original line
numbers. Query cursors bind both the source digest and the request identity.
Parallel calls and the two model variants share only immutable records, with
independent queries and continuation messages. Ordinary records are delivered
whole; oversized records use lossless Unicode paging. Invalid JSON lines are
retained as opaque runtime records with a parse diagnostic. The model selects
what to read and when to stop. Native tool results and the complete preceding
assistant message, including reasoning content, are returned in the next round.

The primary has a 30-second total budget, including admission and snapshot
collection, with no automatic retry or model fallback. There are at most 24
rounds, 32 calls per round, eight concurrent local reads, 128,000 payload
characters per page, a 256 MiB source snapshot and a 16 MiB provider request.
These are resource bounds; a limit or invalid provider response retains PWA
approval. A bare decision without any successful evidence read cannot authorize.
DSML text and malformed decision JSON are not repaired into API calls or allows.
The client/Core transport budgets leave room around this primary deadline.

Thinking-enabled runs afterward for observation, over the same snapshot and
initial input, with its own retrieval choices and a 180-second budget. At most
two observations run concurrently; saturation records a skipped observation
instead of queuing more retained snapshots or delaying primary authority.

Evidence stores the source prefix, original request, exact requests/responses,
tool results and local latency for every round. The viewer checks continuation
and replays reads against the recorded snapshot. These checks establish what
was delivered, not whether the model interpreted it correctly. Raw reasoning
stays in private local evidence; only aggregate telemetry enters summary logs.

The model can miss a constraint, choose an unhelpful search or stop too soon;
there is no complete-human-history delivery guarantee. Later appends are outside
this request's snapshot. Retrieved tool/runtime text can contain contamination
or sensitive information. No heuristic credential scanner is used. Protocol-owned
credentials and signing material remain isolated at their sources. These and
the existing attribution limitations are explicit dogfooding concessions.

Current-prompt matching accepts the exact Core text with separately stored
Codex image attachment wrappers removed. It recognizes complete text/image/text
content-item sequences, preserves all surrounding user text, and records this
projection in boundary evidence while retaining the original text there. This
matches text representations; image pixels are not interpreted by the current
text-only approval model. Core prompt recovery uses the same shared fixtures.

Compact-input R15 helpers remain for offline regression fixtures. They cannot
load as the v33 production profile, and a retrieval-configured model call cannot
silently fall back to the compact request path. Historical compact benchmarks
do not measure this retrieval profile; the new tests exercise its native loop,
parallel reads, snapshot isolation, failure fallback and evidence replay.

The production confirmation JSON, provider routing, credential reference,
installed service configuration and experiment records remain machine-local.
The Gatekeeper requires the compiled confirmation fingerprint before acquiring
its model credential. Tests use dummy data; the optional
BEHOLDER_CONFIRMED_CONFIG test validates a local deployment confirmation.

Builds and tests require the pinned Go version in go.mod and macOS for kernel
process inspection. Source builds are for development verification and must
not replace a verified installed Release. Ordinary Codex messages remain
fail-open when Hook capture fails; that failure does not create an AI allow.
