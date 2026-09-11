# Security Policy

## Supported versions

Only the latest published Release is supported. Development commits on `main`
are not supported distributions. `v0.x` releases are a Public Preview; review
the security model and complete an isolated deployment before placing real
credentials in the `Agent` Vault.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Vizards/OneNod/security/advisories/new).
Do not open a public issue containing exploit details, credentials, private
endpoints, personal data, or secret values.

If a report involves a credential that may be valid, revoke or rotate the
credential with its provider before sending diagnostic information. Reports
should include the affected commit, component, impact, reproduction steps, and
a proposed mitigation when available. Never include production secret values.

## Security boundary

The source code is public and is not a security boundary. A secure deployment
depends on an independently scoped 1Password Service Account, protected runtime
secrets, Passkey approval, a dedicated Cloudflare account, reviewed artifacts,
and production deployment authority unavailable to Agents. Anyone able to
deploy the Gateway or Executor is part of the trusted computing base.

### Optional Beholder authority

When a deployment explicitly enables `BEHOLDER_AUTHORITY_MODE=dogfood-v1`, a
root-controlled Beholder Core may authorize a requester operation without a
Passkey decision. The Core signs a short-lived authorization bound to the
requester device, evidence identity, and SHA-256 of the exact canonical request
body. The Gateway independently verifies the configured Ed25519 public key and
consumes each evidence identity once. A missing, expired, replayed, malformed,
or mismatched authorization creates an ordinary pending request for human
review; it never grants access.

The synchronous thinking-disabled decision is the only model result eligible
for this authority. Any comparison decision is observability-only. Setting the
mode to `human-only` disables model authority and preserves the Passkey approval
path. The root Core key and the Gateway deployment configuration are therefore
part of the trusted computing base whenever this optional mode is enabled.

Requester-reported Beholder diagnostics describe fallback stages and correlate
a local trace with a OneNod request. They are optional display metadata, never
authorization evidence. A diagnostic cannot create a Core binding, substitute
for its signature, or change the Gateway's human approval requirements.

The optional Beholder runtime is distributed inside the authenticated native archive;
the ordinary requester update does not install or enable its root service.
Enabling it requires a separate attended installation and a root-controlled
deployment confirmation. Its dogfooding limitations are explicit:

- Tool attribution combines kernel process lifetime with eligible Hook
  observations. The host does not provide a trusted call-to-spawn event, and
  same-user session data is not an independent authority. Since v32 each live
  execution retains its own immutable set of time-compatible observations from
  the same task, runtime and active transcript. Several observations may match
  one process, and one observation may match several processes. The model sees
  all candidates with the causal tool explicitly unresolved; candidate count
  alone does not prevent model review. An unrelated concurrent operation may
  therefore enter this captured context, and a model can confuse its relevance.
  This is a deliberate dogfooding concession, not proof of a call-to-spawn
  mapping. Existing process bindings cannot switch tasks; runtime/transcript
  identity conflicts and request replay still prevent authority.
- Working directory, command keywords and history length do not independently
  decide user authorization. The model receives source-labelled context and
  declared coverage gaps, including different task and execution directories.
- In v33 the model initially receives only the pending operation. It chooses
  original context through six read-only tools over one immutable request-time
  snapshot; no history is prefetched or summarized. Tools cannot open a new
  path, query another task or execute a command. Cursors bind the request and
  snapshot; parallel calls and model variants do not share mutable query state.
  The model may nevertheless miss a human constraint, choose poor search terms,
  misread provenance or stop prematurely. Complete history delivery is not
  guaranteed, and messages appended after admission are outside this snapshot.
  Tool/runtime records can now reach the model when it requests them, including
  injected text or incidental sensitive data in that history.
- Primary retrieval has bounded time, rounds, source and message sizes. Exceeding
  these bounds or receiving malformed provider output retains PWA approval.
  Thinking-enabled observation cannot change authority; it is skipped when its
  separate capacity is full. Per-round evidence and replay expose retrieval
  behavior but cannot prove that a model decision is correct.
- Final citations are diagnostic, not an independent authorization gate. Missing,
  malformed or unread references are recorded and surfaced by the evidence
  viewer without overriding an otherwise valid model decision. A returned page
  proves delivery of that page, not correct interpretation or complete reading.
- Arbitrary task text may contain sensitive information. It is sent to the
  configured model without heuristic credential scanning; protocol-owned
  credentials and signing material remain excluded at their sources.
- A model can misinterpret permission, incomplete context or injected content.
  Only a valid primary result can request an exact, short-lived Core signature;
  ambiguity, capacity limits and verification failures retain human approval.

These concessions are specific to the explicitly enabled dogfooding authority.
Ordinary message delivery remains available when Hook capture fails; capture
failure does not grant access to a requested credential or signature.
