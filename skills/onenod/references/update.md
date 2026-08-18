# Full-Stack Update

OneNod releases the CLI, SSH Agent, signing adapter, Keychain helper, Gateway,
Executor, PWA, and Skill as one compatibility set. Use `may update check` to
compare the installed, deployed, and latest Release versions before mutation.

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

Local updates preserve the non-secret local quota-fallback binding and do not
rewrite the human-owned 1Password `agent.toml`. After changing 1Password
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
