# First Gateway deployment

Read [Setup](setup.md) for scope and release provenance.

Start with the verified Release binary and `may operator init`. The CLI owns
the live prerequisite checks, defaults, plan, prompts, and exact commands.
Before its production confirmation, the human must have:

- a 1Password desktop session with authority to create Vaults and a Service
  Account in the intended regional account;
- a dedicated Cloudflare account, distinct from everyday Wrangler use, with a
  `workers.dev` subdomain;
- supported `op`, Node.js, and Wrangler installations; and
- a Passkey-capable Safari or Chrome session.

Workers Free is supported, but billing tier is not a security check. If
Wrangler exposes multiple accounts, the human selects the dedicated account.

Wrangler account selection, browser OAuth when needed, and 1Password unlock
begin the deployment ceremony. At that point, stop every same-user Agent
harness and let the human own the terminal. The CLI shows one non-secret production plan
and asks for one default-no deployment confirmation before creating Vaults, a
Service Account, Workers, Durable Objects, or Worker Secrets.

The CLI reuses an authenticated Wrangler profile when it already exposes the
dedicated account. If multiple eligible accounts are available, the human
selects the intended profile/account pair; a fresh browser OAuth remains an
option. A profile created by the CLI is cleaned up automatically after an
interrupted ceremony, while a reused human profile is never deleted on an
error. After a successful deployment, the normal default-yes current-Mac
revocation prompt covers every local profile that exposes the selected account.

The Gateway and Executor prompts offer cryptographically randomized Worker
names by default. Pressing Enter accepts those names. A Worker name explicitly
typed by the human is the complete final name and receives no automatic suffix.
The human should inspect the derived public `workers.dev` Origin in the plan.
Random naming only reduces predictable discovery; it is not an authentication
or authorization boundary.

The bootstrap URL carries a one-time secret in its fragment. The CLI opens it
directly rather than using the clipboard; the PWA removes the fragment before
its first request. After initial Passkey registration, the CLI removes the
bootstrap Worker Secret.

Before opening that URL, the CLI waits for the public workers.dev route to
report the exact deployed OneNod release. After the browser opens, leave the
operator terminal running: it polls the authoritative owner state and removes
the bootstrap Secret automatically, so the human does not return to press
Enter. A readiness or owner-registration timeout retains the Secret and stops;
it never redeploys or guesses that a page transition means success.

`OneNod Recovery` is human-only and stores the deployment record and material
needed for manual reconstruction. The Executor Service Account must not access
it. The first release does not attempt automatic rescue of an unknown
half-created deployment.

At the end, accept the CLI's default-yes offer to revoke the temporary
Cloudflare authority on this Mac unless the human deliberately retains it. A
skip is allowed but leaves the deployment authority retained. The Gateway can
be tested in that state, but the production-credential migration gate remains
unmet until the current Mac no longer has deployment authority for the
dedicated account. Run `may operator revoke-cloudflare` later to inspect the
receipt-bound account, show every matching local profile, and remove them only
after a default-no human confirmation; the command does not modify remote
Workers, Durable Objects, traffic, or 1Password data.

The current-Mac Cloudflare decision completes before the CLI offers local
runtime installation. A revocation error stops there; OneNod does not install a
requester first and then imply that deployment authority was removed.

