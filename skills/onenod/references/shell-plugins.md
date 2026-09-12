# Shell Plugin command routing

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

## Use configured shell plugins normally

After a human runs `may plugin enable` and confirms the displayed local
command-routing plan, both humans and Agents use the ordinary executable name,
such as `gh` or `wrangler`. Do not add `may plugin run --`, invoke `op plugin
run`, source 1Password's `plugins.sh`, or export a recovered credential into
the parent shell.

The enable and credential flows search only Agent Vault catalog metadata. Use
`--item` for an exact item ID or title, `--search` for a narrower catalog
query, and repeat `--field Name=<id-or-label>` only when automatic compatible
field selection needs disambiguation. Without either item option, `may` uses
the plugin platform name as its query. Multiple matching items or compatible
fields require an interactive terminal selection before the default-no routing
confirmation; a non-interactive Agent must not guess a choice.

The managed bare command calls the pinned official 1Password Shell Plugin
`NeedsAuth` rule first. Help, version, and other upstream-declared no-auth
commands run without a OneNod request. An authenticated command obtains the
bound exact fields through the normal verified-application approval path and
places the official Provisioner's environment only in the real child process.
Remembered authorization has the same application, item, field, version, and
expiry semantics as a direct `may` field read.

Use `may plugin status` and `may plugin doctor <command>` for non-secret local
diagnostics. `may plugin credential` changes only the selected non-secret item
and field references. `may plugin disable` removes only the exact managed
binding and entry; none of these commands delete or rewrite a 1Password item.
Enabling, changing, or disabling routing requires the human to review and
answer the default-no terminal confirmation. An Agent must not answer it.

A global binding applies when no directory binding matches. A directory scope
is anchored to the canonical current directory, applies recursively beneath
it, and the most-specific matching root wins. The real executable path is
pinned at enable time; changing PATH later does not silently retarget it.

Only calls whose PATH resolution reaches the managed bare command are covered.
Absolute executable paths, saved real targets, and project-local package
manager entrypoints such as `pnpm exec wrangler` can bypass the shim. Treat a
`doctor` bypass warning as a real support boundary, and do not claim that such
an invocation used OneNod. Removing an old local CLI login or ambient token is
a separate attended cutover after the OneNod-backed command succeeds.

