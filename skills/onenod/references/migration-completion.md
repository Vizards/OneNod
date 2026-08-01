# Migration Completion and Rollback

Apply this to each configuration batch, not to each copied item.

## Batch state

```text
human selection confirmed
  -> source copies preserved
  -> copy into Agent completed
  -> public inventory reconciled
  -> human-selected local OpenSSH/Git-signing/secret consumers configured
  -> representative checks passed
  -> failures isolated or rolled back
  -> batch complete
```

Stop only the affected consumer on failure; do not repeat the entire copy or
delete duplicates blindly.

## Completion criteria

Confirm:

1. every intended category is visible through safe OneNod metadata;
2. the source-Vault copies remain available to the human;
3. the Recovery Vault and excluded credentials are unchanged;
4. the Service Account remains scoped only to `Agent`;
5. representative approved reads and each selected SSH-key consumer class work;
6. local references now use OneNod where intended; and
7. every failed consumer has its old configuration restored or a clear blocked
   record with no secret data.

When the first real credential enters a new deployment, tell the human that the
test-data safety classification has ended. From then on, treat logs,
screenshots, inventory, and troubleshooting as production-sensitive.

## Rollback

Rollback restores the previous local consumer configuration and uses the
untouched source-Vault item. It does not move an item out of `Agent`, restore
Recently Deleted data, or recreate private material.

The human may later remove redundant copies after a separate retention and
recovery review. That cleanup is not part of OneNod's first-preview migration
workflow.

## Close the session

- report only safe counts, consumer status, and stable error codes;
- retain no secret stdout, clipboard value, temp spec, Vault export, or shell
  variable;
- lock the human 1Password app if direct administration was used; and
- list unresolved consumers without attempting automatic secret rotation or
  destructive cleanup.
