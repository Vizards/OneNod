---
name: onenod
description: Install, update, troubleshoot, or operate OneNod for Gateway deployment, Mac/PWA enrollment, approved 1Password reads and item changes, SSH/Git signing, shell plugins, quota fallback, and explicit credential migration. Excludes source-only development.
---

# OneNod

This is the self-contained entry point for the installed product; no source
checkout or private maintainer guide is required. The installed `may` help owns
flags, detected state, executable plans, and version-specific recovery. Reuse
known syntax; consult command-specific help when it is missing or uncertain.
The fixed requester is `~/.onenod/bin/may`.

## Route the task

Load the applicable reference, then only the leaves it selects:

| Task | Reference |
| --- | --- |
| Credential reads, item changes, SSH/Git signing, normal request failures | [Daily use](references/daily-use.md) |
| Enable or troubleshoot Shell Plugin command routing | [Shell plugins](references/shell-plugins.md) |
| First Gateway, Mac installation/enrollment, PWA, optional integrations | [Setup](references/setup.md) |
| Update CLI, helper, Skill, Gateway, Executor, or PWA | [Update](references/update.md) |
| Human-selected credential copy and consumer cutover | [Migration](references/migration.md) |
| Trust boundaries, remembered application approval, Passkeys, Lock mode | [Common](references/common.md) |

## Authority boundaries

- Normal Agent access uses `may` or the configured OneNod SSH Agent. Direct `op`
  is limited to human-explicit administration/migration under [Common](references/common.md).
  A missing, denied, locked, revoked, or unhealthy requester never authorizes a bypass.
- Do not expose recovered fields, private keys, Service Account tokens, bootstrap
  capabilities, or secret-bearing payloads through Agent-visible output or storage.
- Reconcile unknown mutation results before retrying. Local quota fallback is
  `may`-owned, opt-in, and limited to an authenticated Service Account quota error;
  it does not authorize switching tools or Origins.
- Installation, deployment, changed-helper, Passkey, account, and optional-integration
  decisions follow the human boundaries in [Setup](references/setup.md) and
  [Update](references/update.md). Only Update's exact, explicitly declared dogfooding
  exception permits Agent-driven deployment confirmation. It does not cover new
  OAuth, account selection, unlock, a changed helper, secret injection, manual
  rollback, or Origin/RP-ID changes. Update authority never implies Cloudflare
  revocation authority; retain profiles unless that exact revocation is separately
  requested by the human.
- Source/docs work changes the release-owned Skill source. It does not authorize
  altering the installed tree, installing a development build, or deploying an update.
