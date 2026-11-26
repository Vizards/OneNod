# Optional local fallback

Read [Setup](setup.md) for scope and release provenance.

OneNod normally sends every request through the Gateway. On each requester Mac,
the human may configure a local 1Password path. By default it activates
automatically only when the Gateway reports that its 1Password Service Account
quota is exhausted. A separate manual mode can be enabled for a Gateway or
Executor outage, but no failure automatically enables that mode.

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
OneNod's own code restricts reads to the resolved `Agent` Vault ID. 1Password
may remember SDK or SSH authorization, so a fresh prompt is not guaranteed for
each operation. This path needs local 1Password access on that same Mac; it is
not remote PWA approval. Local 1Password must itself be available and
authorized; its app, cache, or network dependencies can still prevent a local
operation during a 1Password outage.

## Manual local mode

Only enable this mode at the human's explicit request, after explaining its
scope. The mode stays active until manually disabled, including across ordinary
local restarts and updates:

```sh
may configure local-fallback status
may configure local-fallback enable
may configure local-fallback disable
```

The usual `may preflight` checks the Gateway and can fail during an outage;
that failure does not establish that the local path is healthy. The local
fallback status command does not require a working Gateway.

The enable command displays the selected account, requester and Gateway Origin,
and a default-no confirmation. The active mode is bound to that Origin and
requester; a different Origin or selected requester fails rather than silently
using the configured local Vault.
While enabled, new catalog, field/credential read, and SSH/Git signature
operations go straight to local 1Password without first trying the Gateway.
Item creation, patching and archival are unavailable. If the SSH identity cache
is missing, `may agent refresh` loads it through local 1Password on explicit
request. Do not automatically retry a previous operation with an unknown remote
outcome; reconcile it first.

Manual mode bypasses Gateway Lock mode, requester revocation, PWA/Beholder
approval and Gateway Activity. Its per-user state file is writable by other
processes running as the same macOS user, so it is an operational choice, not a
separate protection from those processes. Local 1Password authorization and
its own remembered-approval settings still apply. A release that predates manual
mode ignores the state file after rollback and uses its own Gateway behavior;
the state becomes active again if a supporting release is restored.

`disable` returns to the Gateway while preserving the configured quota fallback.
`may configure local-fallback restore` removes the manual state and the OneNod
binding, but deliberately leaves the user-owned `agent.toml` and 1Password
settings unchanged. If the local account or Vault binding changes, disable and
explicitly enable manual mode again for the new binding.

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

