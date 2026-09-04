# Keyward

An OpenID Connect provider that treats a replayed refresh token as an incident rather than a bad request.

Built on OpenIddict and Postgres, with the authorization code flow verified by a real browser and every
security claim in this file backed by a test you can run.

[![ci](https://github.com/tunahanaliozturk/keyward/actions/workflows/ci.yml/badge.svg)](https://github.com/tunahanaliozturk/keyward/actions/workflows/ci.yml)

## Why this exists

Rotating refresh tokens is the standard advice, and on its own it protects nobody.

Follow the sequence. Somebody steals a refresh token. They present it. The server rotates: the stolen
token is marked spent, the thief gets a fresh one, and the thief is now the well-behaved-looking holder of
the chain. Nothing was detected. Nothing was prevented. The theft only becomes visible later, when the
real client presents the token the thief already spent, and at that moment the server cannot tell which of
the two is honest. It knows only that two parties hold what should be one chain.

Keyward records every chain descended from a single grant as a family. When a spent token is presented
again, the whole family dies: the replayed token, the token currently working, and the grant behind them.
Somebody gets logged out who did nothing wrong. That is the point.

## Quick start

```bash
docker compose up -d --build
curl -s http://localhost:5100/.well-known/openid-configuration | jq .
```

Or, with the .NET Aspire tooling, one command brings up Postgres, the provider and a telemetry dashboard:

```bash
dotnet run --project src/Keyward.AppHost
```

Either way the schema is applied and two accounts and three clients are registered:

| Account | Password | Notes |
|---|---|---|
| `user@keyward.local` | `ChangeMe!User1` | Ordinary account, no second factor required |
| `admin@keyward.local` | `ChangeMe!Admin1` | Holds the operator role, so a second factor is mandatory |

| Client | Type | Consent |
|---|---|---|
| `keyward-demo-spa` | Public, authorization code + PKCE | Explicit, so the consent screen is shown |
| `keyward-demo-portal` | Public, authorization code + PKCE | Implicit, registered as first-party |
| `keyward-demo-service` | Confidential, client credentials | Not applicable |

Seeding is off unless something turns it on, and `compose.yaml` turns it on deliberately. A seeder that
runs by default is a seeder that eventually creates a known account with a known password on a public
host.

## The demo worth watching

Get a token pair through the browser flow, then watch a replay take down a working session.
`Keyward.http` has the whole sequence ready to send; here it is in prose.

1. Sign in through `/connect/authorize`, exchange the code, and keep the refresh token. Call it **A**.
2. Refresh normally. You get a new pair, with refresh token **B**. A well-behaved client throws **A** away
   at this moment.
3. Present **A** again, as an attacker holding a stolen copy would.

```
400 invalid_grant
```

Unsurprising so far. Now present **B**, which was valid a second ago and belongs to the legitimate client:

```
400 invalid_grant
```

That is the part that distinguishes reuse detection from plain rotation. Both parties are now signed out,
and only one of them can sign back in. The audit trail says what happened:

```bash
curl -s "http://localhost:5100/admin/audit?type=RefreshReuseDetected" \
  -H "Authorization: Bearer $OPERATOR_TOKEN" | jq '.[0]'
```

```json
{
  "type": "RefreshReuseDetected",
  "detail": "An already-redeemed refresh token was presented; family 0198... was revoked after 1 rotations.",
  "userId": "0198...",
  "clientId": "keyward-demo-spa",
  "remoteAddress": "::1",
  "occurredAtUtc": "2026-03-01T12:04:11.482Z"
}
```

The counter `keyward.refresh_reuse.total` moves at the same moment. It should read zero forever, which is
what makes it worth paging on.

This is `RefreshTokenTests.Replaying_a_spent_refresh_token_kills_the_whole_family`, and it asserts all
four things: the replay fails, the newer token fails, the family row records the reason, and the audit
entry names the family.

## What is actually built here

OpenIddict handles the protocol: parsing, validation, serialisation, the specifications and the decade of
security review behind them. Reimplementing that would be a bad trade. What this repository adds is the
part that is genuinely its own.

**Refresh token families.** A row per chain, keyed on the authorization, carrying a rotation count, an
absolute lifetime that activity cannot extend, the reason it died, and a handle an operator can revoke by.
Revoking one does three things: marks the row, revokes every token OpenIddict holds for the grant, and
revokes the grant itself. Skipping the third is subtle and awful, because the next sign-in attaches to the
same authorization, lands on the dead family, and the account can sign in but never refresh again.

**Reuse detection that runs at the right moment.** OpenIddict stops dispatching handlers as soon as one
rejects the request, so a handler placed after the redemption check never runs on the requests it exists
for. The detector runs at the front of the pipeline instead, looks the presented token up in OpenIddict's
own store, and acts on a stored status of `redeemed` rather than on error text. It rejects nothing; the
request fails exactly as it always would.

**A second factor attached to the session, not the account.** Clearing TOTP writes a claim on the browser
session cookie. Someone given the operator role while signed in is challenged on their next authorize
request, because the cookie they are holding never cleared it. The claim travels into the access token, so
a downstream API can insist on it for a dangerous operation.

**Signing keys that rotate without an outage.** The configured certificates are an ordered list: the first
signs, all of them are published to JWKS. Rotating means prepending and waiting, so a token signed a second
before the rotation still verifies against a key set a relying party cached an hour ago.

**An operator surface.** List an account's sessions, end one, end all of them, and query the authentication
trail. It sits behind a bearer token carrying the operator role, not behind a cookie, because an admin
surface authenticated by cookie is reachable from any page the operator happens to have open.

## Claims and where they are checked

Every line here maps to a test.

| Claim | Checked by |
|---|---|
| The authorization code flow works for a person, in a real browser, through the real forms | `AuthorizationCodeConformanceTests` (Playwright, headless Chromium) |
| The resulting token verifies against the published key set with no call back to the issuer | Same suite, using `JsonWebTokenHandler` against `/.well-known/jwks` |
| A code observed on the redirect is worthless without the verifier | `A_code_taken_from_the_redirect_is_worthless_without_the_verifier` |
| Proof key is mandatory, and the `plain` method is neither accepted nor advertised | `The_plain_challenge_method_is_refused`, `An_authorization_request_without_a_challenge_is_refused` |
| Replaying a spent refresh token kills the whole family, including the working token | `Replaying_a_spent_refresh_token_kills_the_whole_family` |
| A new sign-in works after a family was revoked | `A_new_sign_in_works_after_a_family_was_revoked` |
| A chain stops at its absolute lifetime however often it was used | `A_family_stops_working_once_it_passes_its_absolute_lifetime` |
| Client credentials never issue a refresh token | `A_service_with_its_secret_gets_an_access_token_and_nothing_else` |
| An operator account cannot get a token until the second factor is cleared | `An_operator_account_is_sent_to_the_second_factor_before_any_token_is_issued` |
| Five wrong codes lock the step, and a correct one is refused while it is locked | `Repeated_wrong_codes_lock_the_step` |
| A recovery code works once and never again | `A_recovery_code_works_once_and_then_never_again` |
| A third-party client asks for consent, a first-party one does not, and a refusal reaches the client | `ConsentTests`, four cases |
| The tenant claim reaches the access token and never the identity token | `ClaimDestinationsTests`, plus an end-to-end assertion |
| A retired signing key stays published while the new one signs | `The_key_set_publishes_the_previous_signing_key_alongside_the_current_one` |
| The admin surface refuses anonymous callers and tokens without the operator role | `AdminEndpointTests` |

75 tests in total: 39 unit, 34 integration against a real Postgres in Testcontainers, and 2 conformance
tests driving headless Chromium. Nothing is faked out. In-memory stores enforce neither the unique
constraints nor the transaction semantics OpenIddict's Entity Framework stores rely on, so a suite that
swaps them out is testing a different program.

## Numbers

Token issuance, measured with `load/Keyward.LoadTests` against the Docker Compose stack on an Intel Core
Ultra 7 255H, 16 logical processors, 32 GB, Docker Desktop on Windows 11. The measurement includes
Docker Desktop's port forwarding, which is a real part of the latency and not a rounding error.

| Concurrency | Throughput | p50 | p95 | p99 |
|---|---|---|---|---|
| 8 | 646 tokens/s | 11.7 ms | 17.3 ms | 20.6 ms |
| 32 | 806 tokens/s | 37.0 ms | 64.8 ms | 83.5 ms |

Every token request is a database write plus a signature, so the shape is what you would expect: the
service saturates somewhere above 600 requests per second on this hardware, and past that point the extra
concurrency turns into queueing rather than throughput.

Reproduce it:

```bash
docker compose up -d --build
dotnet run --project load/Keyward.LoadTests -c Release -- http://localhost:5100 3000 32
```

There is also a k6 script at `load/token-endpoint.js` for anyone who wants arrival-rate scheduling. k6 is
an external tool and appears nowhere in the dependency tree.

## Layout

```
src/
  Keyward.Domain/     users, refresh token families, MFA, audit events
  Keyward.Data/       EF Core context, OpenIddict stores, migrations
  Keyward.Host/       OpenIddict configuration, endpoints, Razor pages
  Keyward.AppHost/    Aspire orchestration for local development
tests/
  Keyward.UnitTests/          pure logic, no I/O
  Keyward.IntegrationTests/   real Postgres, real sockets
  Keyward.ConformanceTests/   headless Chromium
  Keyward.TestSupport/        the shared harness
load/                 latency measurement, and a k6 script
tools/                the dependency licence audit
docs/adr/             the decisions worth writing down
docs/operations.md    configuration, alerts, and the runbook
```

## Running the tests

```bash
dotnet run --project tests/Keyward.UnitTests
dotnet run --project tests/Keyward.IntegrationTests    # needs a container runtime
dotnet run --project tests/Keyward.ConformanceTests    # installs Chromium on first run
```

## Licensing

MIT, and so is everything it depends on. `tools/Keyward.LicenseAudit` reads the licence terms of all 207
packages in the tree, at every depth, from the restored packages on disk, and fails the build on anything
that is not permissively licensed. It runs offline, so it works the same in CI and behind a proxy that
blocks nuget.org.

This is not a formality. It is why the provider is OpenIddict rather than Duende, whose licence asks for a
fee above a revenue threshold, and why the Aspire packages are pinned below 13.5, where they begin pulling
in a dependency with a maintenance-fee licence. Both would have arrived silently: the packages restore,
the code compiles, and nothing in the build mentions it.

## Reading further

- [ADR 1: OpenIddict rather than Duende IdentityServer](docs/adr/0001-openiddict-over-duende.md)
- [ADR 2: Refresh tokens live in families, and a replay kills the family](docs/adr/0002-refresh-token-families.md)
- [ADR 3: Signing keys rotate by prepending, and the old key stays published](docs/adr/0003-signing-key-rotation.md)
- [ADR 4: The second factor is a property of the session, not of the account](docs/adr/0004-mfa-is-a-property-of-the-session.md)
- [ADR 5: The consent screen re-posts the original request rather than deciding anything](docs/adr/0005-consent-reposts-the-original-request.md)
- [Operations](docs/operations.md), including configuration, alert thresholds, the key rotation
  procedure, and what to do when the reuse counter moves.

`docs/operations.md` also lists what this service does not do. There is no forgotten-password journey,
self-service enrolment lets a password holder enrol their own authenticator on an account that has none,
and the key ring assumes a single region. Those are stated rather than hidden because an identity provider
is the wrong place to discover a limitation by accident.
