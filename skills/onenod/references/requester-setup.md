# Install and enroll requester Macs

Read [Setup](setup.md) for scope and release provenance.

For each macOS user that will request operations:

1. use the verified binary's `may install` flow with the public Gateway Origin;
2. run the installed requester's `may preflight`;
3. start `may enroll` and approve it in the PWA; and
4. inspect `may agent status` after enrollment.

Use command-specific help for arguments. An additional Mac needs neither
Wrangler nor operator receipts. Installation and enrollment are separate so a
runtime can be prepared without creating requester authority.

Installation always places the verified CLI at `~/.onenod/bin/may` and creates
the user-level `~/.local/bin/may` link when that path is not occupied by
unrelated content. If `~/.local/bin` is not already on `PATH`, the CLI shows one
bounded `~/.zprofile` block and asks whether to add it. A decline does not fail
installation; use the absolute path until the human changes shell discovery.
Open a new login shell before diagnosing a newly added short command.

To add an approver browser or Home Screen PWA, open the public Origin and
authenticate with any registered Passkey. Another live PWA is not required.
Notification permission and the OneNod push subscription are per installation
and optional; repeat **Enable notifications** in every browser or Home Screen
PWA where push is wanted.

The first requester exact-build bootstrap is an attended ceremony. Immediately
before a fresh Create-only credential write, `may enroll` displays a separate
default-no summary. Pause every same-user Agent harness and let the human run
that command and handle any Gatekeeper or Keychain dialogs; macOS may show one
or more, and their count is not the success condition. A server-proven active
requester reuse does not repeat this gate. The
helper creates a fresh random requester slot with Create-only semantics. It
never adopts an existing, precreated, or legacy Keychain item, and an old item
without the protocol-v3 signed transport envelope fails closed. If local
requester state already selects an identity, `may` reuses it only after a
signed read-only Gateway self-proof returns the same active device ID and
public-key fingerprint. A stable not-found response moves bootstrap to a new
random slot; mismatch or an unverifiable response stops. Use `may preflight`,
enrollment status, and `may agent status` as the final evidence. Do not delete
or rewrite an unexpected record just to make bootstrap continue.

