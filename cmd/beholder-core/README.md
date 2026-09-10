# Beholder Core

This experimental v32 service binds Hook observations and actual requester
processes, assembles task evidence, and issues exact-request authority only
after a valid primary Gatekeeper decision. Kernel process inspection requires
macOS. Tests use disposable sockets, files and authority keys.

Each late-bound execution keeps its own PID/start-time identity and immutable
snapshot of all eligible observations from the same task, runtime and active
transcript. Observations are not consumed by the first requesting process.
Overlapping candidates remain explicit model context instead of a guessed
unique tool identity. Tool completion does not release a live execution;
kernel exit or cancellation does. Original binding failures and bounded
candidate diagnostics are retained for both direct and SSH requests.

The native OneNod Release includes the Core, Gatekeeper and evidence viewer.
The ordinary requester updater does not install or enable these services.
Root installation requires an attended local session after immutable Release
provenance verification. Source builds are for development verification only.

See the [security model](../../SECURITY.md#optional-beholder-authority) for
known attribution, context and model limitations. Production confirmation,
provider routing, credentials, service configuration and experiment records
remain outside the source tree. Ordinary Codex messages remain fail-open when
Hook capture fails; that failure never creates an AI allow.
