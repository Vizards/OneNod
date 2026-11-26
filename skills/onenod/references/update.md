# Full-Stack Update

OneNod releases the CLI, SSH Agent, signing adapter, Keychain helper, Gateway,
Executor, PWA, and Skill as one compatibility set. Use `may update check` to
compare the installed, deployed, and latest Release versions before mutation.

For a stable binary released before channel support, joining the first
human-selected candidate uses the [Bootstrap bridge](bootstrap.md), including
its independent provenance checks and attended setup. Do not pass unsupported
`update --version` or `--channel` flags to that older binary.

## Choose the update flow

- Use `may update` on each requester Mac when only local components are behind.
- Use `may operator update` on the operator Mac when Gateway, Executor, or PWA
  changes are required.
- Start a fresh Agent task after the managed Skill changes so the new Skill is
  loaded.

The read-only check does not need Wrangler, `op`, a Passkey, or the requester
private key. An available update is a normal successful result. Follow the
binary's reported plan for provenance, compatibility, revoked artifacts, or a
required bridge version rather than reconstructing an update from this Skill.

Stable installations only discover stable Releases. `beta` accepts beta and
stable Releases; `alpha` accepts alpha, beta, and stable Releases. The chosen
release-discovery preference is stored independently in each Mac's local
receipt and in the operator deployment receipt. All official alpha, beta, and
stable artifacts have the same code-execution trust requirements. Broadening
discovery to include a prerelease requires human confirmation. Narrowing it
never authorizes a version downgrade: when no compatible non-older Release
exists, the CLI leaves state unchanged and reports that it is waiting for one.
Use an explicit `--channel` only when the human has asked to join or leave a
prerelease channel.

When the human deliberately selects an exact immutable prerelease for
evaluation, pass that version to `may update --version`. `--version` and
`--channel` are mutually exclusive. An exact selection applies only to that
operation; the resulting receipt records the version's release channel, so
later unqualified updates follow that channel rather than remaining pinned.
Never substitute a locally built binary for a Release-path evaluation because
it does not exercise OneNod's provenance, installer, or deployment bundle.

## Local update

Local update verifies the attested Release into a bounded in-memory artifact
snapshot, stages it privately, authorizes the exact architecture-specific
`may` and `may-ssh-sign` identities through the stable Keychain helper, promotes
the files, restarts the SSH Agent, and commits only after the new `may` proves
possession of the one-time update capability. The previous version and a
non-secret transaction journal are retained until that commit. If a process
dies around commit, rerun `may update`; it reconciles authenticated helper
state before choosing keep-new or roll-back-old. Do not move links, delete the
journal, or improvise recovery commands.

Artifact descriptors and installed bytes come from the same authenticated
snapshot. Candidate executables travel as open file descriptors. The raw
32-byte commit capability travels only through an anonymous pipe; argv,
environment variables, JSON, the journal, and ordinary files never contain it.
The journal is commit-aware but non-secret, and an unauthenticated status leaves
the transaction uncertain rather than authorizing a destructive rollback.

A compatible Keychain helper remains byte-identical and ordinary local updates
do not request a macOS password. A changed helper is an exceptional trust-root
update: the CLI displays the exact plan and asks a separate default-no human
question. Before accepting it, pause every same-user Agent harness. The staged
exact Helper must prove its identity, direct parent, transaction, and anonymous
capability before Keychain releases requester data. macOS may show one or more
authorization dialogs during this one attended ceremony. Declining the helper
update leaves the installed trust root and local runtime unchanged; an Agent
must not answer, suppress, or bypass a prompt.

`may install` never upgrades an existing complete installation; use `may
update` so this security ceremony cannot be bypassed. During `may operator
update`, Cloudflare deployment confirmation authorizes only the remote change.
If the Helper changed, the CLI asks the separate default-no Helper question
only after the new Gateway has been verified. Declining leaves the remote
upgrade complete and the local update pending; finish later with the exact
`may update --version ...` command it prints.

Repeat local update on every requester Mac. Preserve unrelated Skill discovery
paths and stop if the CLI reports an unrecognized collision.

Local updates preserve machine-local Shell Plugin bindings and their managed
bare-command links. After an update that changes the pinned upstream plugin
definitions, `may plugin status` reports the configured versus current
revision. Review that difference and rerun the guided credential-binding flow
when needed; do not hand-edit `~/.onenod/plugins.json` or replace the managed
links.

Local updates preserve the non-secret local fallback binding and manual mode,
and do not rewrite the human-owned 1Password `agent.toml`. A rollback to an
older release that does not implement manual mode ignores its state file; a
later supporting release sees that state again. Check
`may configure local-fallback status` after switching releases. After changing 1Password
accounts, renaming or recreating `Agent`, or changing its SSH inventory, run
`may configure local-fallback status` and then rerun the guided apply flow as
needed.

## Deployment update

Remote update is another human-owned production ceremony. Before Cloudflare
OAuth, stop every same-user Agent harness and review the CLI's complete plan.
The plan is bound to the operator receipt's account, Worker names, Origin,
versions, promotion order, and rollback metadata. Origin and RP-ID changes are
not supported in the first release.

The human gives one default-no deployment confirmation. The CLI uploads without
traffic, checks exact versions, promotes them in release order, verifies the
result, and then offers default-yes revocation of this Mac's Cloudflare
authority. If Wrangler returns an unknown result, let the CLI reconcile the
recorded transaction before any retry.

### Move the Executor to the US

The Executor normally keeps one Durable Object and its write journal in the
location where that object was first created. Cloudflare cannot move an existing
object by changing a location hint. A US migration creates a separate object
restricted to the US jurisdiction, with western North America preferred. The
old object and its journal remain in place; their records are not copied.

This is a one-way, human-selected state boundary, not an ordinary update or an
automatic failover. Before opting in, stop remote item mutations from every
requester, reconcile every pending, executing, or unknown mutation, and verify
that none can resume during the change. Previously applied write identities in
the old journal are not replay fences in the new object. If those conditions
cannot be established, do not migrate without a separate journal migration.
After new writes occur on the new object, do not return to the old object
without reconciling both journals. Manual local fallback on each requester
prevents its new item mutations, but it is not a global Gateway lock.
If the migration fails, the updater does not automatically roll back across
this boundary. Keep writes stopped and reconcile or resume the recorded plan.

First install the verified Release containing this option on the operator Mac;
older installed versions do not recognize the new flags. Then review the exact
operator plan and use:

```sh
may operator update --version <verified-version> --executor-location us --acknowledge-executor-journal-boundary
```

The update records the selected location in the operator receipt and preserves
it on later updates. It verifies the uploaded Executor binding before promotion.
After deployment, confirm the actual object region using Cloudflare traces and
perform an approved read-only check before restoring remote use. A location
hint alone is best effort; the US jurisdiction is the placement boundary.

### Optional Beholder Worker

After the Gateway, Executor, PWA and this Mac are on the same verified Release,
the human can run `may operator beholder enable` in a local terminal. The plan
shows the account, private Worker, Gateway, Release, provider endpoint and model.
The human confirms that task context may be sent to the selected provider and
enters the provider key directly in Wrangler's hidden prompt. A separate
32-byte trace encryption key is generated locally. The Agent must not enter the
provider key or answer this deployment confirmation.

`may operator beholder status` reads the non-secret transaction status. If the
initial enable was interrupted, do not repeat secret writes or raw Wrangler
commands. In the attended terminal, `may operator beholder rollback` checks the
recorded Gateway versions and restores the prior binding state when the observed
traffic is known. It keeps the private Worker, its secrets and durable data; it
does not roll back a later Release or a Durable Object migration. An unknown
version or out-of-band change requires manual investigation.

Once enabled, `may operator update` also uploads and promotes the Beholder
Worker, preserves its provider and trace keys, checks the Gateway service
binding and verifies the exact Worker Release through the Gateway. Recovery
only resumes a recorded promotion sequence after checking the authoritative
traffic. Automatic rollback remains subject to the signed Release manifest.

On each requester Mac, the optional Beholder Core and context service are a
separate root-controlled installation. Updating OneNod alone does not install
those services or update their exact Agent pin. `may update check` warns when
the Core pin differs from this Mac's installed Agent. After every local Agent
version change, complete the attended Core/context-service installation from
the exact verified Release before relying on automatic approvals. Until then,
affected requests fall back to human approval.

### Explicit dogfooding exception

This exception applies only when the human explicitly says the current OneNod
work is dogfooding and authorizes the exact update target in the current task.
Do not infer dogfooding from a repository name, prerelease channel, test fixture,
or earlier experiment.

The Agent may complete `may update --version ...` and `may operator update
--version ...`, including entering the deployment confirmation, when all of the
following remain true:

- the selected immutable Release is the exact version the human authorized;
- the operator plan matches the receipt-bound Cloudflare account, Worker names,
  Origin, RP ID, channel, and expected current version;
- an existing authenticated Wrangler profile is selected automatically for the
  receipt-bound account, so no account selection or browser OAuth is needed;
- the Keychain helper is unchanged and no Passkey, macOS security prompt,
  1Password unlock, secret injection, manual rollback outside `may`'s built-in
  recovery, or scope expansion is requested.

At the post-deployment revocation prompt, answer **no** and preserve every
existing Wrangler profile. Never infer revocation permission from permission to
update or deploy. Revoke only when the human separately asks to revoke the exact
current-Mac Cloudflare authority in the current task; otherwise an unexpected
revocation path is a stopping condition.

After the first remote mutation, finish the CLI's built-in verification and
transaction reconciliation. If the result is unknown, do not retry or switch to
raw Wrangler commands; rerun only the same `may operator update --version ...`
reconciliation path. Stop for the human if any prerequisite or plan field
differs from the authorized plan.
