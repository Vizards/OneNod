# Beholder handshake diagnostics

The native client and Core emit metadata-only `beholder-transport` records for
binding investigations. Observations do not change the two-second extension
deadline, nonce consumption, model authority, the
fallback diagnostic sent to the Gateway, or the human approval path. No new
wire fields, deployment confirmation, or diagnostic enablement flag is needed.
Installed runtimes acquire this behavior only through a verified Release.
The v33 retrieval profile separately expands the model and Core RPC budgets;
that change leaves the two-second binding extension deadline unchanged.

## Where records live

| Component | Destination |
| --- | --- |
| SSH/Git client adapter | `~/.onenod/logs/beholder-handshake.jsonl` |
| OneNod SSH Agent | Its configured standard error, normally `~/.onenod/logs/ssh-agent.error.log` |
| Beholder Core | Its configured standard error, normally `/Library/Application Support/Beholder/logs/core-diagnostics.jsonl` |

Client logs are appended to an owner-only regular file through checked directory
descriptors. Symlinks, hard-linked files and public paths are not used. A log
path failure prints a bounded notice and leaves the operation available.

Each process has a 256-event nonblocking queue. A slow sink cannot hold the
binding protocol waiting for log writes. Queue overflow and write failures are
counted in the next writable record's `dropped_events`; shutdown allows up to
50 ms to drain. Missing records may therefore mean unavailable evidence, not a
phase that never ran. These files follow the existing local log lifecycle;
this change does not add automatic rotation or remote telemetry.

## Correlation and timing

- `trace_id` is the existing requester trace that also appears in OneNod's
  request diagnostic. It is metadata, not an authorization capability.
- `component`, `connection_id`, and `sequence` identify a phase within one
  component's connection. IDs are generated independently in each component;
  do not equate a client's connection ID with the Agent's or Core's ID.
- A fallback opens a new connection with a new ID. Several connections can have
  the same trace, and old replies may arrive after a fallback has begun.
- Peer lookup, process capture and application identity resolution begin before
  the protocol supplies a trace. Select records by trace first, collect their
  connection IDs, then include earlier records with those same component-local
  IDs. `pid` and `peer_pid` provide additional local process context. They do not
  replace a trace or prove the identity of an uncorrelated concurrent request.
- `observed_at` is UTC wall time; finished phases have monotonic `elapsed_us`.
  `budget_ms` is the configured stage limit. `deadline_at`, when present, is the
  actual socket deadline; read and write phases can share the same deadline.
- `state` is `started` or `finished`. A start without a finish is unfinished or
  missing evidence. Success is never inferred from the absence of an error.

Useful phases:

| Component | Phases |
| --- | --- |
| Client | `agent-dial`, `diagnostic-write/read`, `binding-write/read`, `binding-fallback`, `diagnostic-fallback`, `diagnostic-omitted` |
| Agent | `application-identity`, `diagnostic-ack-write`, `core-binding-round-trip`, `core-dial`, `core-request-write`, `core-response-read`, `binding-ack-write`, `agent-protocol` |
| Core | `peer-pid`, `peer-process-capture`, `request-decode`, `consume-lock-wait`, `consume-lock-held`, `agent-executable-check`, `request-handler`, `response-write`, `core-request` |

Results distinguish `timeout`, `eof`, `truncated`, `broken-pipe`,
`connection-reset`, `closed`, `connection-refused`, `not-found`,
`permission-denied`, `short-write`, explicit `rejected`, and malformed responses.
Other I/O failures retain the fixed `io-error` category. Application identity
reports `verified` or `unverified`; an unverified result alone does not identify
the helper's internal failure. No raw error string is written.

## Interpreting a fallback

1. Resolve the OneNod request diagnostic to its trace in the Agent log. Find
   that trace in the client, Agent and Core logs, then expand component-local
   connection IDs to include stages that predate the trace.
2. A client's `binding-read: timeout` establishes that its socket wait expired.
   Compare the shared deadline with Core RPC, process capture, lock and file
   verification durations. Lease creation time is not the binding start time.
3. A Core `accepted: true` means it accepted the binding request. It does not
   mean the reply was written, received by the Agent, or accepted by the client.
   Existing `beholder-core-request` summaries now include
   `transport_connection_id`, `response_write_result`, and `handler_error_code`.
4. Check Core `response-write`, Agent `core-response-read` and
   `binding-ack-write`, then client `binding-read`. For example, Core acceptance
   followed by a successful Core write but an Agent `broken-pipe` ACK and a
   client timeout locates the lost reply without treating it as a rejection.
5. An ACK write reported as `ok` means the writer accepted the bytes, not proof
   that its peer consumed them. The peer's successful read supplies that next
   observation. Neither event substitutes for model or human authorization.

Trace-less attempts and dropped or absent records remain explicitly unresolved.
Do not guess an association from directory, timing proximity or shared PID.

## Data and validation

Records contain fixed phase/result labels, timestamps, durations, configured
deadlines, booleans, opaque correlation IDs and process IDs. They contain no
nonce, binding token, signed request, SSH frame, key, prompt, command, item
contents, filesystem path or raw error text. The in-memory observation attached
to a Core RPC is unexported and cannot change the serialized request.

Local Go tests use disposable Unix sockets and dummy bindings. They exercise a
real client proxy and SSH Agent with a deliberately delayed Core substitute,
concurrent fast and slow connections, late ACK write failure, explicit Core
rejection, actual Core lock contention, executable verification, response write
failure, private file handling, and a blocked log sink. They do not contact a
live Gateway, read credentials, sign data or call a model.
