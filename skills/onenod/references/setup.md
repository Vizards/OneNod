# Setup and Enrollment

OneNod separates a one-time remote deployment from repeatable local install and
enrollment. Do not give a requester Mac Cloudflare authority merely to install
or enroll it.

The [canonical project and Release source](https://github.com/Vizards/OneNod)
is the bootstrap location for a separately distributed copy of this Skill.
After obtaining the first `may` binary, let the binary own artifact
verification, installation, and update mechanics.

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

Cloudflare OAuth and 1Password unlock begin the deployment ceremony. At that
point, stop other same-user Agents and let the human own the terminal. The CLI
shows one non-secret production plan and asks for one default-no deployment
confirmation before creating Vaults, a Service Account, Workers, Durable
Objects, or Worker Secrets.

The bootstrap URL carries a one-time secret in its fragment. The CLI opens it
directly rather than using the clipboard; the PWA removes the fragment before
its first request. After initial Passkey registration, the CLI removes the
bootstrap Worker Secret.

`OneNod Recovery` is human-only and stores the deployment record and material
needed for manual reconstruction. The Executor Service Account must not access
it. The first release does not attempt automatic rescue of an unknown
half-created deployment.

At the end, accept the CLI's default-yes offer to revoke the temporary
Cloudflare authority on this Mac unless the human deliberately retains it. A
skip is allowed but leaves the deployment authority retained.

## Install and enroll requester Macs

For each macOS user that will request operations:

1. use the verified binary's `may install` flow with the public Gateway Origin;
2. run the installed requester's `may preflight`;
3. start `may enroll` and approve it in the PWA; and
4. inspect `may agent status` after enrollment.

Use command-specific help for arguments. An additional Mac needs neither
Wrangler nor operator receipts. Installation and enrollment are separate so a
runtime can be prepared without creating requester authority.

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

## Repeat by scope

| Work | Repeat |
| --- | --- |
| Cloudflare deployment and bootstrap | Once per Gateway |
| PWA registration and push subscription | Per browser/PWA installation |
| Local install, enrollment, and local update | Per macOS user on each requester Mac |
| Optional OpenSSH or Git signing integration | Per user and Mac that opts in |
| Human batch copy into `Agent` | Once per selected batch |
