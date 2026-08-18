# Standard Credential Copy

Use this route for a human-selected batch of ordinary Logins, Passwords, API
credentials, and simple Secure Notes.

## Human copy

The human copies the selected items into `Agent` using the 1Password app. Keep
the source items active and unchanged. Do not use `op item move`, `--reveal`,
Vault export, clipboard values, or temporary plaintext files.

If 1Password reports an interruption or unknown result, stop and compare
metadata in both Vaults before copying again. Do not create additional copies
blindly.

## Agent verification

After the human finishes:

1. run the fixed requester's public preflight;
2. search the OneNod catalog for expected titles/categories without reading
   values;
3. compare safe counts and identify missing or ambiguous duplicates;
4. exercise representative low-risk consumers through approved `may` reads;
5. verify several items from different categories and risk levels rather than
   requiring a human ceremony for every item; and
6. update Agent-controlled consumers to use the CLI's closed field-read or item
   interface, or the attended `may plugin enable` flow for an explicitly
   supported bare command, without exposing values. A bare `op://Agent`
   reference is not automatically consumed by arbitrary software.

The Agent owns this validation work. Ask for normal PWA approvals only when the
real consumer requires a sensitive operation; do not turn migration into a
manual per-item checklist.

## Cutover and rollback

Switch consumers in coherent batches. Record only non-secret failures and the
old/new reference location. If a consumer fails, restore its previous direct
1Password configuration or source-Vault reference. Because the source item was
not removed, rollback does not require reconstructing or moving the credential.

Do not delete the human-Vault copy during this workflow. Deduplication is a
later human data-management decision after OneNod has remained stable.
