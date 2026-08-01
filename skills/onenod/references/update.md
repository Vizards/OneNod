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

## Local update

Local update verifies the attributed Release, stages it privately, promotes it
atomically, restarts the SSH Agent, and retains the prior version for rollback.
A compatible Keychain helper remains byte-identical. A required helper change
is exceptional and can trigger a separate macOS security prompt.

Repeat local update on every requester Mac. Preserve unrelated Skill discovery
paths and stop if the CLI reports an unrecognized collision.

## Deployment update

Remote update is another human-owned production ceremony. Before Cloudflare
OAuth, stop other same-user Agents and review the CLI's complete plan. The plan
is bound to the operator receipt's account, Worker names, Origin, versions,
promotion order, and rollback metadata. Origin and RP-ID changes are not
supported in the first release.

The human gives one default-no deployment confirmation. The CLI uploads without
traffic, checks exact versions, promotes them in release order, verifies the
result, and then offers default-yes revocation of this Mac's Cloudflare
authority. If Wrangler returns an unknown result, let the CLI reconcile the
recorded transaction before any retry.
