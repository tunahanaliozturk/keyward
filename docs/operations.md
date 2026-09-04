# Running Keyward

Everything an operator needs that is not obvious from the code: what to configure, what to watch, and
what to do at three in the morning.

## Configuration

Only the connection string and the signing keys have no usable default. Everything else has one that is
safe.

| Setting | Default | Notes |
|---|---|---|
| `ConnectionStrings:keyward` | none | Postgres. The service will not start without it. |
| `Keyward:Signing:SigningCertificates` | none outside development | Ordered list. The first signs; all are published. See [ADR 3](adr/0003-signing-key-rotation.md). |
| `Keyward:Signing:EncryptionCertificates` | none outside development | Protects tokens the service issues to itself. |
| `Keyward:Tokens:AccessTokenLifetime` | 5 minutes | Relying parties validate locally, so this is the window in which a leaked token is useful. |
| `Keyward:Tokens:RefreshTokenLifetime` | 14 days | Per token, reset on each rotation. |
| `Keyward:Tokens:RefreshFamilyAbsoluteLifetime` | 30 days | Per chain, not reset. Everyone signs in again eventually. |
| `Keyward:Mfa:RequiredForRoles` | `["admin"]` | Empty means nobody is forced. |
| `Keyward:Mfa:LockoutThreshold` | 5 | Failures before the second-factor step locks. |
| `Keyward:Database:MigrateOnStartup` | `false` | Leave it false anywhere real. See below. |
| `Keyward:Seed:Enabled` | `false` | Creates demo accounts with known passwords. Development only. |
| `Keyward:AllowInsecureTransport` | `false` | Permits plain HTTP. Development and tests only. |

A certificate is supplied either as `Path` to a PKCS#12 file or as `Base64` for hosts that only offer
string configuration, with `Password` if the private key has one.

## Schema changes

`MigrateOnStartup` stays off in production. A rolling deploy runs two versions side by side for a minute
or two, and a migration racing itself across instances is a bad way to discover that. Apply the schema
deliberately:

```bash
dotnet ef migrations script --idempotent \
  --project src/Keyward.Data \
  --startup-project src/Keyward.Host \
  --output migration.sql
```

Read it, then apply it. The migration runs before the deploy, and every migration in this repository is
written so the previous version of the service keeps working against the new schema.

## What to watch

| Signal | Meaning |
|---|---|
| `keyward.refresh_reuse.total` | **Should be zero forever.** Any nonzero rate means a refresh token was presented twice. |
| `keyward.token_issuance.duration` | Histogram, tagged by `grant_type` and `outcome`. Watch p99 by grant type separately. |
| `keyward.mfa_challenge.total` | Tagged by outcome. A rising `Rejected` or `Locked` rate is either a broken client clock or somebody guessing. |
| `/health/live` | The process is up. |
| `/health/ready` | The database is reachable. |

Spans are named per grant: `connect.token.authorization_code`, `connect.token.refresh_token`,
`connect.token.client_credentials`, tagged with `keyward.client_id` and `keyward.outcome`.

Suggested alerts:

- `rate(keyward.refresh_reuse.total) > 0` pages immediately. This is a likely token theft.
- p99 of `keyward.token_issuance.duration` above 100 ms for five minutes.
- Any error rate on `/.well-known/jwks`. If relying parties cannot fetch keys, every API call in the
  estate starts failing a few minutes later.

## Runbook

### A refresh token was replayed

The alert fires when `keyward.refresh_reuse.total` moves. The service has already done the containment:
the whole chain descended from that grant is dead, including the token that was working. Both the
legitimate client and whoever else had a copy have to sign in again.

Establish what happened:

```http
GET /admin/audit?type=RefreshReuseDetected&limit=50
Authorization: Bearer <operator token>
```

Each entry names the family, the account, the client and the address the request came from. Then look at
what else that account has open:

```http
GET /admin/users/{userId}/sessions
Authorization: Bearer <operator token>
```

If the address on the audit entry is not one the user recognises, end everything for that account and have
the password changed:

```http
POST /admin/users/{userId}/sessions/revoke
Authorization: Bearer <operator token>
```

If the replay came from the client's own address and repeats on a schedule, it is a client bug rather than
a theft: something is holding a refresh token after exchanging it, or two instances of the client share
one token. The fix is in the client.

### Somebody reports a lost or stolen device

```http
POST /admin/users/{userId}/sessions/revoke
Authorization: Bearer <operator token>
```

Every refresh chain for the account ends. Access tokens already issued stay valid until they expire, which
is why that lifetime is five minutes. If the device also held an authenticator, remove the enrolment so the
account can enrol a new one, and reissue recovery codes.

### An account is locked out of the second factor

The lock is time-based and clears itself; the wait grows with each further failure, capped at an hour. If
it needs clearing sooner, the cause is usually clock drift on the phone rather than a wrong code, so check
that first. The verification window is one step either side of now, which is thirty seconds each way.

If the authenticator is gone entirely, the account uses a recovery code. If those are gone too, an
operator removes the enrolment row and the account enrols again on next sign-in.

### Rotating the signing key

Two deploys, in this order.

1. Generate a new certificate and prepend it to `Keyward:Signing:SigningCertificates`, keeping the current
   one in second place. Deploy. New tokens are signed with the new key; the previous key stays published,
   so tokens issued a moment ago still verify.
2. Wait at least twenty-four hours, which comfortably outlasts both the access token lifetime and any
   sensible key cache. Then remove the retired certificate and deploy again.

Do not skip step 2. A retired key that stays published stays usable by anyone who has the private half.

Check the result:

```bash
curl -s http://localhost:5100/.well-known/jwks | jq '.keys | length'
```

### The service will not start

If the log says signing certificates must be configured, that is the guard in
`KeywardHost.AddKeys` refusing to fall back to development keys outside development. Ephemeral keys are
regenerated on every start, so the fallback would silently invalidate every token in circulation on the
next restart. Configure the certificates.

If the log says the connection string is not configured, the service never got `ConnectionStrings:keyward`.

## Known limitations

- **Enrolment on first sign-in.** Someone holding only a password, for an account that has not yet
  enrolled an authenticator, can enrol their own. This is inherent to self-service enrolment. Where it
  matters, have an operator start enrolment and reserve the self-service flow for accounts already known
  to have an authenticator.
- **No account recovery flow.** There is no forgotten-password journey. Resetting a password is an
  operator action against the database, which is the honest state of things rather than a half-built
  email flow.
- **Single region.** The Data Protection key ring and the token store are one Postgres database. A
  multi-region deployment needs a plan for both, and this service does not have one.
