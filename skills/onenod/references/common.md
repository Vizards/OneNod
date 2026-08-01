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

Lock mode rejects new and pending operations without push, removes unconsumed
encrypted payloads, and invalidates remembered SSH authority. Leaving it
requires a registered Passkey.

## Installed surfaces

One verified Release installs the CLI, SSH Agent, signing adapter, managed
Skill, and independently versioned Keychain helper under `~/.onenod`. The
stable SSH socket is `~/.onenod/agent.sock`. The Origin file is parsed as data,
not sourced as shell. Use `may version`, `may preflight`, and `may agent status`
for installed-state questions; obtain their current syntax from `may help`.
