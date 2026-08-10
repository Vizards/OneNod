# SSH Key Copy and Cutover

Use this route after the human copies a batch of supported Ed25519 or RSA SSH
Key items into `Agent`. Source items remain in their original Vault, so rollback
is a local routing change rather than another Vault mutation. Obtain all command
syntax from `may`.

## Inventory consumers

Before cutover, identify from public metadata:

- public fingerprint and algorithm;
- Git authentication, Git signing, host authentication, or peer-access roles;
- affected Macs and hosts;
- current SSH Agent, identity-file, environment, and Git-signing routing; and
- an independent recovery route for critical hosts.

Do not reveal private material or infer a role from an item title alone.

## Refresh and reconcile

On every requester Mac, run the fixed requester's preflight, run
`may agent refresh` after the selected SSH Key batch is copied or changed, and
inspect Agent status. The verified public inventory remains local until an
explicit refresh; normal identity listing does not contact 1Password merely
because time passed. Compare fingerprints with the human-selected batch.
Missing, duplicate, unsupported, or changed keys stop automatic cutover only
for the affected consumer.

OpenSSH authentication and Git commit/tag SSH signing are independent opt-ins.
Use the CLI's corresponding status and apply capabilities only for consumers
selected by the human. For Git signing, use the CLI's public-key export
operation for the selected item; private-key export is never permitted.

Treat socket cutover and public-key selector migration as separate steps.
`may configure ssh` owns only the effective `IdentityAgent`; existing
`IdentityFile`, `IdentitiesOnly`, and `Include` behavior remains active. Inspect
`may configure ssh status`, then use `ssh -G <host>` for every selected Host.
For a selector that still names an old product path, match the intended Agent
item by public fingerprint, export a new public-key file, and update only that
Host. Do not guess mappings or delete old public-key files before acceptance.

Each apply operation must display current and proposed settings and wait for the
human's default-no decision. Preserve unrelated Host blocks and Git values.
OneNod configures Git's SSH signature format, not traditional GPG/OpenPGP, and
must not enable agent forwarding.

After global Git setup, run `may configure git-signing status` from each real
repository used for acceptance. A repository or worktree value can override the
global signer; OneNod reports its effective scope but never removes that local
policy automatically.

## Agent-led acceptance

The Agent performs representative, dependency-aware checks:

- one fresh authentication or harmless command for each critical host class;
- Git fetch for each distinct transport identity;
- a disposable signed commit plus local or service verification for each
  distinct signing identity;
- both directions for peer-Mac access; and
- one remembered-approval path on a representative key when reuse is intended.

Do not require the human to inspect hundreds of equivalent keys one by one.
Every actual signature still follows normal PWA policy; public fingerprint
reconciliation, representative tests, and real consumer failures determine
where approvals are needed. Close stale multiplexed SSH sessions before
testing—a reused connection is not proof of a new OneNod signature.

## Rollback

Use the CLI's receipt-backed restore flow only while its owned settings still
match. Otherwise stop for human review rather than overwriting later edits.
Restore the previous SSH/Git routing and use the untouched source-Vault route.
Do not move, delete, regenerate, or export a private key to bypass failed
cutover. Repair OneNod with disposable data before retrying that consumer.
