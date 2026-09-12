# Setup and Enrollment

OneNod separates a one-time remote deployment from repeatable local install and
enrollment. Do not give a requester Mac Cloudflare authority merely to install
or enroll it.

The [canonical project and Release source](https://github.com/Vizards/OneNod)
is the bootstrap location for a separately distributed copy of this Skill.
After obtaining the first `may` binary, let the binary own artifact
verification, installation, and update mechanics.

## Choose the setup boundary

Load only the route needed for the requested installation or integration:

| Task | Reference |
| --- | --- |
| No installed `may`, or a pre-channel stable binary needs the human-selected first candidate | [Bootstrap](bootstrap.md) |
| Deploy the first Gateway with a verified Release | [Gateway deployment](gateway-setup.md) |
| Install/enroll a requester Mac, or add an approver browser/PWA | [Requester and PWA](requester-setup.md) |
| Opt into local quota fallback, OpenSSH, or Git signing | [Local integrations](local-integrations.md) |
| Opt a supported bare command into OneNod | [Shell plugins](shell-plugins.md) |

Fresh executable/helper/requester bootstrap, account selection, OAuth, Passkeys,
1Password unlock, and optional integration confirmations remain attended human
steps in the selected route. Prepare the authorized, non-secret work first.
Existing installed operations do not require repeating the first-use ceremony.

## Repeat by scope

| Work | Repeat |
| --- | --- |
| Cloudflare deployment and bootstrap | Once per Gateway |
| PWA registration and push subscription | Per browser/PWA installation |
| Local install, enrollment, and local update | Per macOS user on each requester Mac |
| Optional OpenSSH or Git signing integration | Per user and Mac that opts in |
| Optional local quota fallback and `agent.toml` entry | Per user and Mac that opts in |
| Optional Shell Plugin command routing | Per user, Mac, command, and selected scope |
| Human batch copy into `Agent` | Once per selected batch |
