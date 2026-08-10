# Daily Agent Use

## Pick the interface

Run `may preflight` when installed identity or Gateway compatibility is in
question. It is a shallow public check; requester enrollment or one approved
operation proves the private Executor path.

- Use `may catalog search` to locate item and field metadata without reading a
  value.
- For one field, prefer `may read op://Agent/<item>/<field>`.
- Use `may secret read` only when stable IDs or an expected item version are
  needed.
- Use `may item` for closed-schema creation, patching, or archival. Pass specs
  by stdin or a private file rather than argv.
- Use `may agent status` and `may agent refresh` after SSH Key items change.

These are stable command families, not a replacement for command-specific
help. Do not translate an arbitrary `op` command into a presumed `may`
equivalent.

## Handle results

Deliver returned values directly to the intended process without echoing or
persisting them. Catalog titles, IDs, versions, labels, and public keys are not
secret values, but they are private metadata.

Reconcile a mutation that times out or has an unknown outcome before retrying.
Report request IDs, status, expiry, relevant public fingerprint, and non-secret
error codes—not payload contents.

## Recover a revoked requester

Requester revocation is terminal for that enrolled device identity. Do not
delete, overwrite, export, or try to reuse its Keychain record. If the human
wants to enroll the same Mac again, use `may enroll --new-identity` and follow
its current help. It creates a new requester slot, retains the retired local
identity, and activates the new one only after normal PWA approval.

## Use opted-in SSH integrations normally

After the human enables an integration, use ordinary `ssh`, `scp`, and Git
commands. Each private-key signature becomes a Gateway request. Git commit/tag
signing uses the SSHSIG `git` namespace and is independent of Git transport
authentication.

Do not use agent forwarding for this path. A reused SSH connection also does
not prove that a new OneNod signature occurred; close multiplexed sessions when
testing a fresh approval.

One user command can legitimately create more than one approval: OpenSSH may
probe several offered identities, Git transport and commit signing are separate
signature paths, and a background fetch can authenticate independently. Do not
approve apparent duplicates by count alone. Correlate the local application,
requester, operation, and public fingerprint; use an exact per-Host public
`IdentityFile` with `IdentitiesOnly yes` when a Host should offer only one key.

OpenSSH and Git can collapse a remote OneNod failure into the generic text
`agent refused operation`; that text alone does not prove the human denied the
request. Inspect `~/.onenod/logs/ssh-agent.error.log` for the safe request
stage, request ID, and cause, then report only those non-secret diagnostics. If
it identifies a Gateway 5xx, preserve the request ID for a human operator to
correlate in Cloudflare Workers Logs. Do not switch to `op`, change Origins, or
blindly repeat an operation whose outcome is unknown.

If Lock mode is active, stop. It intentionally rejects requester operations
without notifying an approver; a human must leave Lock mode with a Passkey.

## When the Service Account quota is exhausted

If the human configured local quota fallback on this Mac, keep using the same
`may`, `ssh`, or Git command. An authenticated quota-exhaustion response from
the Gateway makes `may` request approval through the local 1Password app for
that exact read or signature. Do not invoke `op`, alter the Origin, or retry
through another tool.

This fallback can serve catalog metadata, one approved field value, or an
SSH/Git signature. Mutations remain unavailable until the remote Service
Account quota recovers. If the local 1Password app is locked, absent, or not
authorized, report both the remote quota condition and the local failure; do
not weaken the trigger or bypass OneNod.

If a PWA-approved request reached remote execution before the quota error was
known, Gateway Activity keeps that truthful remote failure even when the local
operation subsequently succeeds. Use `may`'s local-success diagnostic as the
result of that invocation; do not retry merely to change the Activity entry.
