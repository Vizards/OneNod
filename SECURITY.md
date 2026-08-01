# Security Policy

## Supported versions

Only the latest published Release is supported. Development commits on `main`
are not supported distributions. `v0.x` releases are a Public Preview; review
the security model and complete an isolated deployment before placing real
credentials in the `Agent` Vault.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Vizards/OneNod/security/advisories/new).
Do not open a public issue containing exploit details, credentials, private
endpoints, personal data, or secret values.

If a report involves a credential that may be valid, revoke or rotate the
credential with its provider before sending diagnostic information. Reports
should include the affected commit, component, impact, reproduction steps, and
a proposed mitigation when available. Never include production secret values.

## Security boundary

The source code is public and is not a security boundary. A secure deployment
depends on an independently scoped 1Password Service Account, protected runtime
secrets, Passkey approval, a dedicated Cloudflare account, reviewed artifacts,
and production deployment authority unavailable to Agents. Anyone able to
deploy the Gateway or Executor is part of the trusted computing base.
