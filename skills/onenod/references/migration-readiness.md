# Migration Readiness and Inventory

Complete these gates before the human copies production credentials into
`Agent`.

## Production isolation

Require:

1. Gateway, Executor, Passkey, and at least one requester have completed the
   normal setup acceptance with disposable data. Web Push is optional.
2. The installed CLI's read-only full-stack update check reports a supported
   Release and compatible remote deployment.
3. The operator receipt reports current-Mac Cloudflare authority revoked, or a
   later `may operator revoke-cloudflare` run has verified that no local
   Wrangler profile on the deploying Mac still exposes the dedicated account.
   The human confirms no other ordinary Agent Mac was authorized for that
   account.
4. The Executor Service Account can access only `Agent` with the intended
   `read_items` and `write_items` scope and cannot access `OneNod Recovery` or
   source human Vaults.
5. The human has an independent recovery path for critical hosts and services
   whose credentials will be copied.

If a Cloudflare or scope gate fails, do not place real credentials in `Agent`.

## Human 1Password boundary

Ask the human to identify the exact account, source Vaults, and destination
Vault `Agent`. When human-explicit metadata inventory is useful, run from a
local graphical Mac session:

```sh
OP_BIOMETRIC_UNLOCK_ENABLED=true \
  op item list --vault "<source-vault-id>" \
  --account "<confirmed-sign-in-address>" --format json
```

Do not use `--reveal`, export a Vault, or persist item inventory in a public
repository or chat. Titles, IDs, tags, and fingerprints are private metadata.

The human may instead select the batch entirely in the 1Password app. Do not
force CLI inventory when it adds no value.

## Classify the batch

| Class | Examples | Route |
| --- | --- | --- |
| Standard | Login, Password, API credential, simple Secure Note | `migration-standard-items.md` |
| SSH | Ed25519/RSA SSH Key used by Git or a host | `migration-ssh-keys.md` |
| Special/unsupported | Passkey, OTP, Document, attachment, linked graph, unsupported SSH algorithm, recovery/root identity | `migration-special-items.md` |

Identify consumer classes rather than demanding a per-item migration ledger:

- commands or services that need a secret field;
- OpenSSH/Git transport hosts;
- Git commit/tag signing;
- automation still using direct `op://<human-vault>/...` references; and
- recovery or break-glass credentials that should remain human-only.

## Confirm one batch boundary

Before copying, present a concise plan containing:

- account and source/destination Vault names;
- selected categories or item set;
- confirmation that the operation is **copy**, not move;
- unsupported/excluded item classes;
- configuration that the Agent will change afterward; and
- rollback through the untouched source Vault and previous local settings.

One confirmation may cover the whole named batch. Do not ask the human to
approve each item individually.
