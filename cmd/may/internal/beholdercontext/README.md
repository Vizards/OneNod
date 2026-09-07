# Managed Beholder context aliases

The immutable `may` release contains two managed, observation-only entrypoints:
`beholder-e1-context` supervises `beholder-e1-pretool-hook`. An attended managed
installer creates exact copies of the verified release binary at these basenames.
They return before normal requester initialization or pending-outcome delivery.
The existing SSH shim uses the same release-owned basename-dispatch mechanism.

The supervisor executes the fixed sibling worker, forwards stdin directly, discards
worker output and stops it after three seconds. Worker failures never become
policy decisions. Managed configuration must also normalize the outer shell
status and output, including failures before the Go entrypoint starts:

```toml
command = "'/Library/Application Support/Beholder/codex-hooks/beholder-e1-context' --core-socket '/Library/Application Support/Beholder/run/core.sock' >/dev/null 2>&1 || :; printf '{}\\n'; exit 0"
timeout = 5
```

Use this command for `UserPromptSubmit` and supported `PreToolUse` events. The
worker only relays event observations. The Core still verifies the exact
root-controlled worker path and digest, Codex process ancestry, and session,
prompt, turn and tool binding. Missing evidence leaves OneNod human approval in
place and cannot authorize a credential operation.

`scripts/release/verify-binary-version.mjs` runs the packaged binary acceptance
suite on both native macOS release runners. It copies the actual signed `may`
to both basenames and verifies identity, exact event delivery, status 2, crash,
deadline, malformed output, missing components and open stdin. A locally built
candidate is not installable: administrators must use the published immutable
GitHub Release after provenance and digest validation.

Managed activation belongs last in an attended installer, after verifying the
installed bytes and Core worker pin. Keep an independent disable path and restore
the prior disabled state if installation or startup fails. Private deployment
configuration, transcripts, authority keys and observations do not belong in a
release artifact.
