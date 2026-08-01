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

## Use opted-in SSH integrations normally

After the human enables an integration, use ordinary `ssh`, `scp`, and Git
commands. Each private-key signature becomes a Gateway request. Git commit/tag
signing uses the SSHSIG `git` namespace and is independent of Git transport
authentication.

Do not use agent forwarding for this path. A reused SSH connection also does
not prove that a new OneNod signature occurred; close multiplexed sessions when
testing a fresh approval.

If Lock mode is active, stop. It intentionally rejects requester operations
without notifying an approver; a human must leave Lock mode with a Passkey.
