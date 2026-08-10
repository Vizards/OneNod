# Common Knowledge and Authority

## Choose the authority

| Interface | Authority and purpose |
| --- | --- |
| Installed `may` | Origin-scoped requester in macOS Keychain; normal Agent secret and item operations |
| OneNod SSH Agent | Public-key inventory locally; approval-backed private-key signatures remotely |
| Keychain helper | Creates and uses the requester identity; has no network, Cloudflare, shell, or 1Password authority |
| Human `op` session | Explicit 1Password administration or migration inventory |
| Wrangler or Cloudflare Dashboard | Human-owned production deployment authority |

The initializer may use an unlocked human `op` session to create `Agent`,
`OneNod Recovery`, and a Service Account scoped to `Agent`. The Service Account
token is passed directly to the Executor Worker Secret and recovery record; it
is not an Agent credential.

## Keep direct 1Password administration explicit

OneNod does not depend on a second 1Password Skill. For normal Agent work,
never substitute `op` when `may` is missing, denied, locked, or unhealthy.

Use `op` directly only after the human explicitly requests an administrative or
migration action. Confirm the intended 1Password sign-in address, run from the
human's local graphical Mac session, set `OP_BIOMETRIC_UNLOCK_ENABLED=true`, and
pass the confirmed address through `--account`. Ask when the account is
ambiguous. An empty or locked `op` session reached over SSH is not evidence that
the desktop app has no accounts.

Keep direct administration metadata-only unless the reviewed OneNod ceremony
itself needs to provision a Service Account. Never reveal, export, or relay a
credential value through Agent-visible output.

## Trust flow

```text
Agent consumer
  -> may or the OneNod SSH Agent
  -> requester signature from the Keychain helper
  -> public Gateway and approval state
  -> human Passkey decision or remembered SSH authorization
  -> private Cloudflare Service Binding
  -> Executor and scoped 1Password Service Account
  -> Agent Vault
```

Both Workers, both Durable Objects, bundled WASM, the dedicated Cloudflare
account, the approver device, and the local OneNod runtime are in the trusted
computing base. A Service Binding does not protect against a malicious deployer
inside that Cloudflare account.

## SSH approval semantics

The SSH Agent exposes public identities from supported SSH Key items in
`Agent`; private keys remain in 1Password. The SSH Agent protocol carries the
key and signing payload, not a task statement or remote command. The displayed
local application is an advisory process observation, and the requester label
identifies the enrolled device key rather than a trusted Agent persona.

A remembered approval is bound to the requester, running SSH Agent instance,
local client scope, key fingerprint, and item version. Supported lifetimes are
until Lock mode, until Agent exit, or 4, 12, or 24 hours. Unknown local clients
do not receive duration choices. SSH authentication approves a signature, not
the command later executed on the remote host.

## Passkeys and Lock mode

Any registered Passkey may register another PWA installation. PWA viewing
sessions and push subscriptions are per installation. Losing every Passkey
requires rebuilding the Gateway in the first release.

Passkeys identify the OneNod owner, not a Mac or PWA installation. The label
shown under **Owner passkeys** is management metadata only; it does not rename
the WebAuthn account, bind a synced Passkey to one device, or rename the entry
inside a password manager. A password manager may derive that entry's title
from the actual `workers.dev` RP ID, including the user's Cloudflare account
subdomain. PWA installations and their push subscriptions are registered and
revoked separately from owner Passkeys.

Adding or revoking an owner Passkey requires fresh Passkey authentication, and
the Gateway refuses to revoke the last registered Passkey. To replace one,
register and successfully use the new Passkey before revoking the old one.

Lock mode rejects new and pending operations without push, removes unconsumed
encrypted payloads, and invalidates remembered SSH authority. Entering Lock
mode only removes authority and therefore does not require a Passkey; leaving
it expands authority again and requires a registered Passkey.

## Installed surfaces

One verified Release installs the CLI, SSH Agent, signing adapter, managed
Skill, and independently versioned Keychain helper under `~/.onenod`. The
stable SSH socket is `~/.onenod/agent.sock`. The Origin file is parsed as data,
not sourced as shell. The canonical executable remains
`~/.onenod/bin/may`; installation normally exposes the short `may` command
through the user-level `~/.local/bin` path after a new login shell. Use `may
version`, `may preflight`, and `may agent status` for installed-state questions;
obtain their current syntax from command-specific `--help`, which must not need
an Origin, requester credential, or network.
