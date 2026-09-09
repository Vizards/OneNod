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

When an approver remembers a secret or SSH approval, treat it as authorization
for every task and session in the displayed application on that requester Mac.
It is never evidence that only the current Agent task was approved. Secret
grants cover one exact item field and version; SSH grants cover one exact key
and version. Do not assume another field, key, application, or requester is
authorized. If OneNod cannot verify the caller through the helper's live macOS
code-identity chain, that caller is intentionally limited to one-time approval;
do not try to obtain a duration grant by renaming a process or changing paths.

These are stable command families, not a replacement for command-specific
help. Do not translate an arbitrary `op` command into a presumed `may`
equivalent.

## Use configured shell plugins normally

After a human runs `may plugin enable` and confirms the displayed local
command-routing plan, both humans and Agents use the ordinary executable name,
such as `gh` or `wrangler`. Do not add `may plugin run --`, invoke `op plugin
run`, source 1Password's `plugins.sh`, or export a recovered credential into
the parent shell.

The enable and credential flows search only Agent Vault catalog metadata. Use
`--item` for an exact item ID or title, `--search` for a narrower catalog
query, and repeat `--field Name=<id-or-label>` only when automatic compatible
field selection needs disambiguation. Without either item option, `may` uses
the plugin platform name as its query. Multiple matching items or compatible
fields require an interactive terminal selection before the default-no routing
confirmation; a non-interactive Agent must not guess a choice.

The managed bare command calls the pinned official 1Password Shell Plugin
`NeedsAuth` rule first. Help, version, and other upstream-declared no-auth
commands run without a OneNod request. An authenticated command obtains the
bound exact fields through the normal verified-application approval path and
places the official Provisioner's environment only in the real child process.
Remembered authorization has the same application, item, field, version, and
expiry semantics as a direct `may` field read.

Use `may plugin status` and `may plugin doctor <command>` for non-secret local
diagnostics. `may plugin credential` changes only the selected non-secret item
and field references. `may plugin disable` removes only the exact managed
binding and entry; none of these commands delete or rewrite a 1Password item.
Enabling, changing, or disabling routing requires the human to review and
answer the default-no terminal confirmation. An Agent must not answer it.

A global binding applies when no directory binding matches. A directory scope
is anchored to the canonical current directory, applies recursively beneath
it, and the most-specific matching root wins. The real executable path is
pinned at enable time; changing PATH later does not silently retarget it.

Only calls whose PATH resolution reaches the managed bare command are covered.
Absolute executable paths, saved real targets, and project-local package
manager entrypoints such as `pnpm exec wrangler` can bypass the shim. Treat a
`doctor` bypass warning as a real support boundary, and do not claim that such
an invocation used OneNod. Removing an old local CLI login or ambient token is
a separate attended cutover after the OneNod-backed command succeeds.

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
