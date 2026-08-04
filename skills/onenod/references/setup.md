# Setup and Enrollment

OneNod separates a one-time remote deployment from repeatable local install and
enrollment. Do not give a requester Mac Cloudflare authority merely to install
or enroll it.

The [canonical project and Release source](https://github.com/Vizards/OneNod)
is the bootstrap location for a separately distributed copy of this Skill.
After obtaining the first `may` binary, let the binary own artifact
verification, installation, and update mechanics.

## Bootstrap the first `may`

When `may` is not installed, obtain the macOS archive for the detected machine
architecture from the canonical GitHub Release selected by the human. Stable is
the default; use an exact prerelease only when the human deliberately requests
that channel or version. Extract it in a private temporary directory, inspect
`may version`, and use that binary to start `may install` for an existing
Gateway or `may operator init` for a new deployment. Do not require Go, a
repository clone, private project documents, or another Skill.

The bootstrap download establishes the first executable trust root from the
human-selected canonical Release. Once running, `may` verifies the attributed
Release set before installing or deploying it; do not replace that path with a
locally built binary or an unverified third-party package.

Stable is the default release channel. A human who is deliberately testing a
candidate may select `beta` or `alpha` through the CLI's `--channel` option.
That selection is a risk ceiling: `beta` may consume beta or stable Releases,
while `alpha` may consume alpha, beta, or stable Releases. Moving to a higher
risk channel requires an explicit default-no confirmation and is persisted in
the applicable local or operator receipt. Do not infer prerelease consent from
the fact that the task is a test.

A stable binary released before channel support cannot discover the first
candidate. In that one bootstrap case, obtain `may` from the exact GitHub
prerelease selected by the human, then pass its canonical version with
`--version X.Y.Z-alpha.N` to setup. Exact version selection and `--channel` are
mutually exclusive. Once installed, the receipt carries the inferred channel
and normal update discovery applies.

## First Gateway deployment

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
begin the deployment ceremony. At that point, stop other same-user Agents and
let the human own the terminal. The CLI shows one non-secret production plan
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

## Install and enroll requester Macs

For each macOS user that will request operations:

1. use the verified binary's `may install` flow with the public Gateway Origin;
2. run the installed requester's `may preflight`;
3. start `may enroll` and approve it in the PWA; and
4. inspect `may agent status` after enrollment.

Use command-specific help for arguments. An additional Mac needs neither
Wrangler nor operator receipts. Installation and enrollment are separate so a
runtime can be prepared without creating requester authority.

Installation always places the verified CLI at `~/.onenod/bin/may` and creates
the user-level `~/.local/bin/may` link when that path is not occupied by
unrelated content. If `~/.local/bin` is not already on `PATH`, the CLI shows one
bounded `~/.zprofile` block and asks whether to add it. A decline does not fail
installation; use the absolute path until the human changes shell discovery.
Open a new login shell before diagnosing a newly added short command.

To add an approver browser or Home Screen PWA, open the public Origin and
authenticate with any registered Passkey. Another live PWA is not required.

## Optional OpenSSH and Git signing

Installation starts the fixed SSH Agent but does not change OpenSSH or Git.
The human can opt into SSH authentication, Git SSH signing, both, or neither
through `may configure ssh` and `may configure git-signing`.

Each apply flow shows current and proposed settings and asks a default-no
question. OneNod records only settings it owns and restores them only while
unchanged. Git integration uses SSH signatures; it does not take over
traditional GPG/OpenPGP signing.

Git apply owns only the four global Git values shown in its plan. Repository,
worktree, command, or system-scoped values are never rewritten. Run
`may configure git-signing status` inside the repository that will be used for
acceptance and review the reported effective scope; an intentional higher-scope
override must be resolved separately before treating the cutover as complete.

The global `IdentityAgent` cutover does not rewrite per-Host `IdentityFile` or
`IdentitiesOnly` selectors. `may configure ssh status` reports selectors found
in the main config and flags legacy-looking paths; `Include` files still need
separate review. For a Host that should select an `Agent` key, match the item by
public fingerprint, export its public key with `may ssh public-key export`, and
edit only that exact Host mapping. Never infer a mapping from an item title.

## Repeat by scope

| Work | Repeat |
| --- | --- |
| Cloudflare deployment and bootstrap | Once per Gateway |
| PWA registration and push subscription | Per browser/PWA installation |
| Local install, enrollment, and local update | Per macOS user on each requester Mac |
| Optional OpenSSH or Git signing integration | Per user and Mac that opts in |
| Human batch copy into `Agent` | Once per selected batch |
