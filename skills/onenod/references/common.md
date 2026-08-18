# Common Knowledge and Authority

## Choose the authority

| Interface | Authority and purpose |
| --- | --- |
| Installed `may` | Origin-scoped requester in macOS Keychain; normal Agent secret and item operations |
| OneNod SSH Agent | Public-key inventory locally; approval-backed private-key signatures remotely |
| Optional local fallback | `may`-owned Desktop SDK reads and native 1Password SSH Agent signatures, only for an authenticated Service Account quota-exhaustion response |
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
This remains true when local quota fallback is configured: `may` invokes the
official Desktop SDK or native 1Password SSH Agent itself, and the Agent never
changes commands or receives permission to call `op`.

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
  -> human Passkey decision or remembered application authorization
  -> private Cloudflare Service Binding
  -> Executor and scoped 1Password Service Account
  -> Agent Vault

Exact Service Account quota exhaustion, if the human opted in on this Mac
  -> may keeps the same requested item, field, version, key, and payload
  -> local 1Password Desktop SDK read or native SSH Agent signature
  -> human approval in the local 1Password app
```

Both Workers, both Durable Objects, bundled WASM, the dedicated Cloudflare
account, the approver device, and the local OneNod runtime are in the trusted
computing base. A Service Binding does not protect against a malicious deployer
inside that Cloudflare account.

The optional local branch is deliberately narrower than the normal path. It
supports metadata and field reads plus SSH/Git signatures; it never performs
item creation, patching, or archival. It does not activate for denial, Lock
mode, requester revocation, timeout, network failure, or generic 5xx errors.
The local 1Password app authorizes the SDK at account scope, while OneNod binds
its code path to the exact `Agent` Vault ID saved during setup.

## Application-scoped approval semantics

OneNod cannot reliably distinguish tasks or conversations inside Codex,
Claude Code, or another Agent harness. A remembered approval therefore applies
to the entire verified application on one enrolled requester Mac. Never
describe a duration choice as authorizing only the current task, conversation,
terminal command, or model invocation.

On macOS, the stable Keychain helper traces live process ancestry and asks
Security.framework to validate the running code. A verified Application scope
is derived from Apple trust class, Team ID, signing identifier, and designated
requirement—not from a process name, path, PID, Agent-brand list, or mutable
display label. SSH and Git requests additionally carry their accepted Unix
socket peer into the helper so the long-running OneNod SSH Agent cannot
self-report the caller. The display name comes from signed application metadata;
the cryptographic principal controls reuse.

Unsigned, invalid, unsupported, or unresolvable caller applications stop
ancestry inheritance and receive only one-time approval. Third-party ad-hoc
applications are also unverified. A verified scope additionally requires the
OneNod transport itself to match the exact hardened ad-hoc build authorized by
the stable Keychain helper. The official Release digest, architecture-specific
CDHash, designated requirement, and fixed role identifier are carried through
an authenticated update transaction; paths, ownership, permissions, process
names, and socket names are never substitutes for that identity. OneNod does
not require a paid Apple Developer ID for this per-build chain.

The first `may` cannot prove its own origin. Before it ever runs, bootstrap must
independently verify the canonical GitHub Release artifact attestation and
SHA-256, then pause every same-user Agent harness before the first execution.
Once the human completes that one-time ceremony, the helper-protected current
build becomes the trust root
for later updates. This protects requester secrecy and authorization integrity;
it does not prevent another same-user process from deleting files, killing the
Agent, presenting a social-engineering prompt, or otherwise causing denial of
service.

Fresh requester bootstrap is Create-only in a new random slot. An existing,
precreated, or legacy Keychain record is never adopted; a legacy record without
the signed protocol-v3 transport envelope fails closed. Before reusing any
selected local requester, `may` makes a signed read-only self request and
requires the Gateway's active device ID and public-key fingerprint to match
exactly. A stable not-found result creates a different random slot; a mismatch
or unverifiable response stops. Bootstrap and a changed helper are attended
ceremonies: pause every same-user Agent harness and let the human handle any
macOS dialogs. A byte-identical helper stays pinned across ordinary local
updates, which require no Keychain prompt.

A remembered secret approval is bound to the requester, application scope,
exact item, exact field, and item version. Its supported lifetimes are until
Lock mode or 4, 12, or 24 hours. Every task and session in that application can
read that field while the grant remains active. A changed item version requires
a new approval. Item mutations are never remembered.

Unknown local applications receive only one-time approval because no stable
application scope is available.

A verified command-line runtime can itself be the Application principal. For
example, a remembered grant shown for a signed Node runtime applies to every
local program using that same signed runtime on the requester Mac, not just the
Agent harness whose request happened to reveal it. The PWA shows the signer,
Team ID, and signing identifier so the human can recognize this wider scope.

The PWA **Access** tab lists every active remembered grant as one
item/field-or-key, application, and requester tuple. It shows the end condition
or time and lets the owner revoke each grant independently.

## SSH approval semantics

The SSH Agent exposes public identities from supported SSH Key items in
`Agent`; private keys remain in 1Password. The SSH Agent protocol carries the
key and signing payload, not a task statement or remote command. A verified
application identity describes the local signed application as a whole; the
requester label separately identifies the enrolled device key.

A remembered SSH approval is bound to the requester, whole application,
running SSH Agent instance, key fingerprint, and item version. Supported
lifetimes are until Lock mode, until SSH Agent exit, or 4, 12, or 24 hours.
Every choice ends early when the local SSH Agent restarts; the Agent-exit choice
has no earlier time deadline. None of these choices is scoped to a task or
conversation. SSH authentication approves a signature, not the command later
executed on the remote host.

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
encrypted payloads, and blocks remembered secret and SSH authority. Entering Lock
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

Optional Shell Plugin bindings are machine-local configuration, not another
installed runtime. Each managed bare command is a user-level symlink to the
same stable `may`; its binding stores only the pinned real executable path,
scope, upstream definition revision, item metadata, and field IDs. Credential
values are never written into that configuration.
