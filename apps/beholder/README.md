# Beholder Worker

This package contains the private model-review Worker. The Gateway authenticates
requesters before forwarding model rounds through a service binding. The Mac
retains the immutable context snapshot and returns only read-only pages requested
by the Worker. The primary review may request a Core authorization; the
thinking-enabled comparison is observational only.

The Worker encrypts review events in Durable Object storage with
`BEHOLDER_TRACE_KEY` and schedules deletion after seven days. A human session can
view events correlated with its request. The trace contains the provider's
actual output, including reasoning only when the provider returns it. Context
and output limits, an interrupted request, or an unavailable provider can leave
an incomplete trace and retain human approval.

`wrangler.jsonc` is a development configuration. `BEHOLDER_PROVIDER_URL` and
`BEHOLDER_MODEL` are placeholders; `BEHOLDER_PROVIDER_KEY` and the 32-byte
base64url `BEHOLDER_TRACE_KEY` must be supplied as secrets to a disposable local
environment. Do not put credentials or personal endpoints in the checkout.

Production installation is not yet wired into the verified deployment artifact
or `may operator update`. A production rollout also needs a human-confirmed
provider and secret setup, a versioned private Worker and Gateway binding,
upgrade/rollback reconciliation, and an attended root-controlled local context
service. That installer must confirm and create the fixed root-owned
`/Library/Application Support/Beholder/config/worker-context.json`, including
the exact trusted `may` path and digest, user home, and Gateway origin.
Gatekeeper does not accept those authority choices from user-controlled flags,
and starts its requester helper without inherited proxy or loader settings. Do
not deploy this development configuration as a substitute for that reviewed
release path.
