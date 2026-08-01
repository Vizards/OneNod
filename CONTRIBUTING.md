# Contributing

## Development setup

Requirements:

- Node.js 22.12 or newer
- pnpm 10.23.0
- Go 1.25.8 or newer

Install dependencies and run the complete local gate:

```sh
pnpm install --frozen-lockfile
pnpm check
go -C cmd/may test ./...
go -C cmd/may vet ./...
```

The executor build uses the pinned WASM source and Binaryen versions declared
in the workspace.

## Pull requests

- Create a focused branch and pull request; do not push directly to `main`.
- Sign every commit with a cryptographic signature GitHub can verify.
- Merge with squash or a merge commit; GitHub rebase-merges rewrite commits
  without preserving their signatures.
- Explain security-boundary changes and include tests for changed behavior.
- Keep UI text, CLI text and source comments in English.
- Do not commit credentials, rendered secret values, private endpoints,
  personal data, machine-specific deployment targets, local logs or runtime
  state.
- Use only dummy vaults and disposable credentials in development and tests.
- Do not add a dependency without checking its license and maintenance status.

By submitting a contribution, you confirm that you have the right to provide it
under Apache License 2.0. Contributions with additional or conflicting terms
are not accepted.

## Maintainer releases

Maintainers release only through the reviewed immutable GitHub Actions flow.
End users should install published artifacts rather than build a release from
source.
