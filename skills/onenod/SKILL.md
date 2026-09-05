---
name: onenod
description: Install, update, or operate OneNod for approval-backed 1Password access and SSH signing, including explicit credential migration.
---

# OneNod

Use this Skill for OneNod-specific workflow, authority, and safety decisions.
Use the installed `may` binary's help for flags, argument shapes, detected
state, and version-specific recovery instructions. Stable command-family names
are included here so an Agent can choose the correct entry point.

This distributed Skill serves installed-product operations. Editing OneNod source
or documentation does not itself authorize installing a development build,
changing the installed Skill, or running a production update.

Treat this Skill as the complete OneNod lifecycle entry point. Do not require a
project checkout, private maintainer documentation, or another 1Password Skill.
Before `may` exists, use the bootstrap guidance in the Setup reference; after
installation, let `may` own executable plans and version-specific mechanics.

## Route the task

Choose the reference for the requested operation; load another only when the task
crosses that boundary. Routine reads or SSH signing do not require repeating
setup, migration readiness, or a deployment ceremony:

| Route | Load when |
| --- | --- |
| [Common](references/common.md) | Explain trust boundaries, `may` versus `op`, Passkeys, Lock mode, or SSH semantics |
| [Setup](references/setup.md) | Deploy a Gateway, install or enroll a Mac, add a PWA, or opt into SSH/Git or local quota-fallback integration |
| [Update](references/update.md) | Reconcile the CLI, helper, Skill, Gateway, Executor, and PWA |
| [Migration](references/migration.md) | A human asks to copy a selected credential batch into `Agent` and cut consumers over |
| [Daily use](references/daily-use.md) | Use credentials, mutate items, sign over SSH, or troubleshoot a normal request |

For migration, load the router plus only the applicable leaf:
[readiness](references/migration-readiness.md),
[standard credentials](references/migration-standard-items.md),
[SSH keys](references/migration-ssh-keys.md),
[special items](references/migration-special-items.md), or
[completion](references/migration-completion.md).

## Non-negotiable boundaries

- Use the installed `may` requester for Agent work. `op` is reserved for a
  human-explicit 1Password administration or migration task described by this
  Skill; never route normal Agent access through `op` or another Skill.
- Outside an explicitly declared OneNod dogfooding stage, hand the terminal to
  the human from Wrangler account selection, browser OAuth when needed, or
  1Password unlock through the CLI's current-Mac Cloudflare revocation check.
- When the human explicitly declares OneNod dogfooding and authorizes an exact
  update in the current task, the Agent may drive that release-owned update
  through deployment confirmation and verification under the guardrails in
  [Update](references/update.md). This exception does not cover account
  selection, new OAuth, Passkeys, 1Password unlock, a changed Keychain helper,
  secret injection, manual rollback outside `may`'s built-in recovery, or an
  Origin/RP-ID change.
- Update or deployment authority never implies Wrangler revocation authority.
  In dogfooding, retain every existing Wrangler profile and answer the CLI's
  revocation prompt negatively unless the human separately and explicitly asks
  to revoke the exact current-Mac authority in the current task.
- Outside that narrow dogfooding exception, treat Passkeys, macOS security
  prompts, account selection, production deployment confirmation, revocation,
  and optional integration changes as human decisions.
- Do not expose a Service Account token, recovered field, private key,
  bootstrap capability, or secret-bearing payload through Agent-visible
  output or storage.
- Reconcile an unknown mutation result before retrying. A denial, revocation,
  timeout, or Lock-mode response is not a reason to switch tools or Origins.
  If the human opted into local quota fallback, `may` itself may request local
  1Password approval only when the Gateway returns its authenticated Service
  Account quota-exhaustion error; the Agent still does not invoke `op`.
