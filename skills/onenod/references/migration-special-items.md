# Special and Unsupported Credentials

Copying an item into `Agent` does not create a OneNod capability. Classify these
before a bulk copy and exclude them unless the required workflow is already
implemented and tested.

| Item/use | First-preview handling |
| --- | --- |
| Passkey-bearing Login | Keep human-only. OneNod is not a WebAuthn authenticator for stored account passkeys. |
| OTP-bearing Login | Copy only if the supported field-read workflow meets the recipient, timing, and exposure requirements; test a disposable equivalent first. |
| Document or attachment | Keep human-only unless the reviewed protocol explicitly supports its bounded delivery. |
| Linked items | Treat as one dependency graph; do not infer that copied links or changed IDs remain valid. |
| ECDSA/DSA SSH key | Unsupported by the production signer; retain the source route or rotate to Ed25519/RSA. |
| Git commit/tag signing | Use the SSH migration route and verify Git's SSHSIG path, not only host authentication. |
| Account recovery, break-glass, primary human or Cloudflare recovery material | Keep outside `Agent` and preserve an independent human route. |
| Shared/team item | Confirm the copy is allowed and does not create an unintended Agent-visible shared credential. |

For a mixed Login containing both an Agent-needed credential and human-only
passkey/recovery fields, prefer a separate least-privilege upstream Agent
credential rather than copying the mixed identity wholesale.

Do not promise future support by copying an unsupported item now. Build and
verify a disposable end-to-end capability first, then reconsider the item in a
separate human-approved batch.
