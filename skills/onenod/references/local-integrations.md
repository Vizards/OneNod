# Optional local quota fallback

Read [Setup](setup.md) for scope and release provenance.

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

