# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-04

First release.

### Added

- OpenID Connect provider built on OpenIddict 7.6 with Postgres-backed stores for applications,
  authorizations, scopes and tokens.
- Authorization code flow with mandatory proof key. The `plain` challenge method is neither accepted nor
  advertised in the discovery document.
- Refresh token families: every chain descended from one grant is tracked, carries an absolute lifetime
  that activity cannot extend, and records why it died.
- Reuse detection. A refresh token presented after it was exchanged revokes the entire family, the tokens
  behind it and the grant itself, and writes an audit entry naming the family.
- Client credentials grant for service-to-service tokens, deliberately without a refresh token.
- TOTP second factor with QR enrolment, ten single-use recovery codes, and exponential lockout backoff
  capped at an hour. Required by role, and enforced per session rather than per account.
- Consent screen for third-party clients, skipped for clients registered as first-party, with the
  approval protected by an antiforgery token.
- Signing key rotation without an outage: the configured certificates are ordered, the first signs, and
  all of them are published to the key set.
- Operator endpoints for listing an account's sessions, ending one or all of them, and querying the
  authentication trail. Behind a bearer token carrying the operator role.
- Data Protection key ring persisted to Postgres, so instances share key material.
- OpenTelemetry metrics and traces, including `keyward.refresh_reuse.total`, which is meant to read zero
  forever, and one span per grant type.
- 75 tests: 39 unit, 34 integration against a real Postgres in Testcontainers, and 2 conformance tests
  driving headless Chromium through the real login and consent forms.
- Offline dependency licence audit that fails the build on anything not permissively licensed.
- Docker Compose stack, .NET Aspire host, load measurement tool, k6 script, five architecture decision
  records and an operations runbook.

[1.0.0]: https://github.com/tunahanaliozturk/keyward/releases/tag/v1.0.0
