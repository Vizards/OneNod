# Working on OneNod source

This repository contains the Gateway, Executor, protocol, Go `may` CLI and
Keychain helper, release tooling, and the distributed `skills/onenod` skill.
Read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution/signing requirements and
[SECURITY.md](SECURITY.md) when a change affects trust boundaries.

## Scope and evidence

- Source development and documentation review do not require a live Gateway,
  production credentials, requester enrollment, or a release ceremony. Use dummy
  data and disposable fixtures for local validation.
- The distributed skill guides installation and product operations. Apply its
  human-controlled credential, helper, and deployment boundaries when the task
  actually performs those operations; do not repeat setup for a source-only edit.
- Treat the installed `may` help as the syntax authority for installed operations,
  and the checked-out implementation/tests as the authority for code changes.
  Do not confuse a working-tree build with a verified Release.
- Keep skills self-contained for users without this checkout. No private maintainer
  document, personal deployment target, machine state, or secret may become a
  dependency of the public skill.

## Relevant checks

Use the locked pnpm workspace and the affected package (`@onenod/gateway`,
`@onenod/executor`, or `@onenod/protocol`). There is no control-plane package or
production Container deployment in this tree; do not copy retired commands from
an older project guide.

- Skill/docs-only edits: `pnpm docs:check` plus review of referenced command names
  and authorization semantics. Do not run the runtime or reinstall it to validate
  prose. Check any new root instructions' relative links too.
- Runtime or CLI changes: run the relevant package or Go tests and type/vet checks.
  Broaden to the complete `pnpm check` and Go gates for cross-component changes;
  immutable releases retain their existing full CI and provenance checks.
- Release tooling changes: run affected `scripts/release/test` cases and the source
  contract checker; an artifact-generation test does not authorize a real release.

## Contribution and installation

Use a focused branch and PR, with commits signed by an existing configured signer.
Do not change the user's signing or credential setup to work around a failure.
Explain the final behavior and its validation; documentation edits need no model
pin, permission-mode change, or production release.

`skills/onenod` is the source for the release-owned installed copy under `~/.onenod`.
Change the source and let a reviewed Release distribute it. Do not hand-edit the
installed tree, replace its discovery symlink, or relax digest/receipt validation
just to make a documentation change active early.
