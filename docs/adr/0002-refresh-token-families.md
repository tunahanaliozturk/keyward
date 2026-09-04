# 2. Refresh tokens live in families, and a replay kills the family

Status: accepted

## Context

Refresh tokens are long-lived credentials held by clients that cannot keep a secret. Rotation is the
standard mitigation: every exchange issues a new refresh token and marks the old one spent.

Rotation on its own protects nobody. Consider the sequence. An attacker steals a refresh token. They
present it. The server rotates: the stolen token is marked spent, the attacker receives a fresh one, and
the attacker is now the legitimate-looking holder of the chain. Nothing has been detected and nothing has
been prevented. The theft becomes visible only later, when the real client presents the token the attacker
already spent.

At that moment the server sees a spent token being presented again. It cannot tell which of the two
parties is the honest one. It knows only that two parties hold what should be a single chain.

## Decision

Every chain of refresh tokens descended from one grant is recorded as a row in `refresh_token_families`,
keyed on OpenIddict's authorization id. When a spent refresh token is presented, the entire family is
revoked: not only the replayed token, but every token issued after it, including the one currently
working.

Revocation does three things, and all three are required:

1. Marks the family row revoked, with the reason and the moment, so an incident review has something to
   read.
2. Revokes every token OpenIddict holds for that authorization, so the tokens themselves stop working.
3. Revokes the authorization, so the next sign-in creates a new grant. Without this the account would sign
   in successfully and then be unable to refresh, forever, because it would attach to the dead family.

A family also carries an absolute expiry that activity does not extend. A sliding window alone means a
session used daily never ends.

## Consequences

Revoking a family logs out a session that was working a second ago. That is the intended behaviour and
the part that surprises people: the alternative is leaving an attacker holding a valid token because
signing someone out felt heavy-handed. Both parties sign in again, and only one of them can.

A broken client that retries with a token it already spent will be treated as a theft. This is why
OpenIddict's reuse leeway, a short grace period during which a spent token is still accepted, is set to
zero here. A grace period is exactly the window an attacker needs. The trade is deliberate: a client bug
that causes spurious sign-outs is loud and gets fixed, whereas a leeway window that lets a stolen token
through is silent.

`keyward.refresh_reuse.total` should read zero forever. Any nonzero rate is a security signal, and the
runbook in `docs/operations.md` treats it as one.

The proof is `RefreshTokenTests.Replaying_a_spent_refresh_token_kills_the_whole_family`, which rotates
once, replays the spent token, and asserts that the replay fails, that the currently valid token also
fails, and that the audit trail names the family.
