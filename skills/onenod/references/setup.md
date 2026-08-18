# Setup and Enrollment

OneNod separates a one-time remote deployment from repeatable local install and
enrollment. Do not give a requester Mac Cloudflare authority merely to install
or enroll it.

The [canonical project and Release source](https://github.com/Vizards/OneNod)
is the bootstrap location for a separately distributed copy of this Skill.
After obtaining the first `may` binary, let the binary own artifact
verification, installation, and update mechanics.

## Bootstrap the first `may`

When `may` is not installed, obtain the macOS archive, `release-manifest.json`,
and `onenod-provenance.intoto.jsonl` from the canonical GitHub Release selected
by the human. Stable is the default; use an exact prerelease only when the human
deliberately requests that channel or version. Do not execute the downloaded
binary yet.

The first executable cannot authenticate itself. The Agent uses an independent GitHub
attestation verifier (normally `gh
attestation verify release-manifest.json --repo Vizards/OneNod --bundle
onenod-provenance.intoto.jsonl --signer-workflow
Vizards/OneNod/.github/workflows/release.yml --source-ref refs/heads/main
--deny-self-hosted-runners`) to
verify the manifest's GitHub build provenance. Then locate the exact
architecture-specific archive entry in that
verified manifest and compare its declared SHA-256 and byte size with the
downloaded archive. Reject a repository, workflow, source commit, artifact
name, digest, architecture, or version mismatch. After these read-only checks,
the Agent must output only the authenticated temporary `may` path, the attested
source digest and Release tag, and one exact `may install ...` or `may operator
init ...` command. It then exits without executing `may`. The human inspects
that non-secret summary, stops every same-user Agent harness, and runs the exact
command from a human-controlled terminal. Do not treat `may version`, a
filename, a Release page, or the archive's own `RELEASE.json` as independent
provenance.

Only after those checks, treat the downloaded bytes as one authenticated,
bounded artifact snapshot and extract it in a private temporary directory. The
CLI repeats a default-no first-execution ceremony summary before it can install
an initializer, helper, Skill, or local runtime. That prompt is a human gate,
not permission for the Agent that verified the artifact to remain running. Do
not require Go, a repository clone, private project documents, or another
Skill. Once the one-time Keychain
ceremony has pinned the exact official build, later updates are authenticated
by the installed `may` and stable helper; never replace that path with a locally
built binary or an unverified third-party package.

The first preview is not Developer ID signed or notarized. macOS may therefore
require the human to allow the first verified binary through Gatekeeper. Never
remove quarantine metadata, ad-hoc sign the downloaded binary, disable
Gatekeeper, or otherwise bypass that decision for the human.

Stable is the default release channel. A human who is deliberately testing a
candidate may select `beta` or `alpha` through the CLI's `--channel` option.
This is a release-discovery preference, not a code-execution trust boundary:
all official alpha, beta, and stable artifacts must pass the same provenance,
digest, and exact-build checks. `beta` may discover beta or stable Releases;
`alpha` may discover alpha, beta, or stable Releases. Broadening discovery to
include a prerelease requires an explicit default-no anti-accident confirmation
and is persisted in the applicable local or operator receipt. Do not infer
prerelease consent from the fact that the task is a test.

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
Notification permission and the OneNod push subscription are per installation
and optional; repeat **Enable notifications** in every browser or Home Screen
PWA where push is wanted.

The first requester exact-build bootstrap is an attended ceremony. Immediately
before a fresh Create-only credential write, `may enroll` displays a separate
default-no summary. Pause every same-user Agent harness and let the human run
that command and handle any Gatekeeper or Keychain dialogs; macOS may show one
or more, and their count is not the success condition. A server-proven active
requester reuse does not repeat this gate. The
helper creates a fresh random requester slot with Create-only semantics. It
never adopts an existing, precreated, or legacy Keychain item, and an old item
without the protocol-v3 signed transport envelope fails closed. If local
requester state already selects an identity, `may` reuses it only after a
signed read-only Gateway self-proof returns the same active device ID and
public-key fingerprint. A stable not-found response moves bootstrap to a new
random slot; mismatch or an unverifiable response stops. Use `may preflight`,
enrollment status, and `may agent status` as the final evidence. Do not delete
or rewrite an unexpected record just to make bootstrap continue.

## Optional local quota fallback

OneNod normally sends every request through the Gateway. On each requester Mac,
the human may additionally configure a local emergency path for the exact case
where the Gateway reports that its 1Password Service Account quota is
exhausted. This does not make local approval a substitute for an unreachable,
denied, locked, revoked, timed-out, or otherwise unhealthy Gateway.

This option requires the 1Password desktop app, signed in to the same account
that owns `Agent`. It does not require 1Password CLI. In **1Password Settings >
Developer**, the human must enable both **Integrate with 1Password SDKs** and
the **SSH Agent**, then make the `Agent` Vault available to that SSH Agent in:

```text
~/.config/1Password/ssh/agent.toml
```

Run `may configure local-fallback apply`. The guided flow asks for the
1Password account name shown in the desktop app or its account UUID, then
prints the exact entry to add without editing the human-owned file. It has this
shape:

```toml
[[ssh-keys]]
vault = "Agent"
account = "<1Password account name or UUID>"
```

Preserve unrelated entries. `agent.toml` officially supports Vault and account
names or IDs. After the human confirms the edit, `may` requests Desktop SDK
authorization, resolves exactly one `Agent` Vault in the selected account, and
immediately checks every available Agent SSH key against the native 1Password
SSH Agent by public fingerprint before saving the non-secret local binding. No
SDK client is kept across the human editing step, so an automatically locking
1Password app cannot invalidate an in-progress client while the CLI waits. If
the Vault has no SSH keys yet, `may` can verify only that the native Agent is
reachable; rerun the apply flow after adding keys.

The Desktop SDK authorization prompt covers the selected 1Password account;
OneNod's own code restricts reads to the resolved `Agent` Vault ID. This is a
separate, explicit trust choice. It helps only while a human can approve
1Password on that same Mac, so it does not replace remote PWA approval while
the human is away. Disable the OneNod path with `may configure local-fallback
restore`; that command deliberately leaves the user-owned `agent.toml` and
1Password settings unchanged.

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

OneNod does not own `gpg.ssh.allowedSignersFile` or the trust entries inside
that file. It is needed for local verification, not for creating a signature.
Preserve it when valid; if it points into a retired product directory, place a
verified copy of that public trust file at a vendor-neutral user path, update
the Git setting, and verify a known signed commit before removing the old path.

The global `IdentityAgent` cutover does not rewrite per-Host `IdentityFile` or
`IdentitiesOnly` selectors. `may configure ssh status` reports selectors found
in the main config and flags legacy-looking paths; `Include` files still need
separate review. For a Host that should select an `Agent` key, match the item by
public fingerprint, export its public key with `may ssh public-key export`, and
edit only that exact Host mapping. Never infer a mapping from an item title.

## Optional Shell Plugin command routing

After requester enrollment, a human may opt a supported command such as `gh`
or `wrangler` into OneNod with `may plugin enable`. The upstream executable
must already be installed. Choose an explicit `--scope global` or run from the
intended project root with `--scope directory`; use `--target` only when the
automatic real-executable discovery is not the intended binary.

Credential selection is metadata-only: use an exact `--item`, a narrower
`--search`, and optional repeatable `--field Name=<id-or-label>` mappings, or
complete the numbered item/field choices in an interactive terminal. The CLI
then displays the resolved executable, scope, item and field IDs, managed bare
command path, and no-local-secret guarantee before one default-no confirmation.
An Agent may prepare or inspect this plan but must not answer the confirmation.

Afterward, use the normal bare command. Do not source 1Password Shell Plugin
integration, add a `may plugin run` wrapper, or export a credential into the
parent shell. Run `may plugin doctor <command>` to verify PATH coverage and
bypass warnings. Bindings are local to one macOS user and Mac; repeat the
attended setup independently wherever routing is wanted.

## Repeat by scope

| Work | Repeat |
| --- | --- |
| Cloudflare deployment and bootstrap | Once per Gateway |
| PWA registration and push subscription | Per browser/PWA installation |
| Local install, enrollment, and local update | Per macOS user on each requester Mac |
| Optional OpenSSH or Git signing integration | Per user and Mac that opts in |
| Optional local quota fallback and `agent.toml` entry | Per user and Mac that opts in |
| Optional Shell Plugin command routing | Per user, Mac, command, and selected scope |
| Human batch copy into `Agent` | Once per selected batch |
