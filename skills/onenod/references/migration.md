# Credential Migration Router

Load this route only when the human explicitly asks to prepare credentials for
Agent use. The first-preview migration model is deliberately reversible:

1. the human selects and **copies** a batch into `Agent` with 1Password;
2. the original items remain in the human Vault as rollback sources;
3. the Agent refreshes OneNod, configures consumers, and performs verification;
4. the human removes old copies only later, outside this workflow, if desired.

Use a batch sized to the human's request; a single item is a valid batch. Do not
expand it for convenience or require a separate copy ceremony for every key in
an already selected batch. OneNod does not use `op item move`. The human controls
the Vault copy boundary; the Agent owns repeatable configuration and verification
afterward.

## Load references progressively

1. Always read [readiness and inventory](migration-readiness.md).
2. Load the relevant batch procedure:
   - [standard items](migration-standard-items.md) for Logins, Passwords, API
     credentials, and simple Secure Notes;
   - [SSH keys](migration-ssh-keys.md) for SSH authentication, Git transport,
     or Git signing; or
   - [special items](migration-special-items.md) for passkeys, OTP, Documents,
     attachments, linked items, unsupported algorithms, or recovery material.
3. Read [completion and rollback](migration-completion.md) before switching any
   consumer.

A mixed copy may contain many items, but classify the set first so unsupported
items are not mistaken for capabilities OneNod provides.

## Authority boundary

- Only the human copies items between Vaults.
- Use `op` only for human-explicit metadata inventory or administration, with
  desktop integration and an explicit account.
- Never reveal or export secret fields to perform migration.
- Never use the Executor Service Account as a Vault administrator.
- Do not delete source items as part of migration.
- Pause the affected copy or consumer on ambiguous duplicates, unsupported item
  types, unexpected count changes, or an unknown result. Reconcile metadata before
  retrying; continue independent, authorized checks where their inputs are known.
