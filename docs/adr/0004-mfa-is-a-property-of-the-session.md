# 4. The second factor is a property of the session, not of the account

Status: accepted

## Context

A password check and a second-factor check happen at different moments, and something has to remember
that both happened. The obvious place is the account: a flag saying this user has cleared MFA. It is the
wrong place. A flag on an account is true for every session that account has open, including one started
last week on a machine that is no longer trusted.

There is a second question underneath it. Who has to use a second factor at all? Mandating it for every
account is a nuisance that people route around; mandating it for nobody is not a policy.

## Decision

Clearing the second factor writes a claim, `amr_mfa`, onto the browser session cookie. The authorize
endpoint reads that claim, not a column. A session that has not cleared MFA cannot be turned into a token
when the account's roles demand one, however many other sessions the account has.

Which accounts are obliged is decided by role, through `Keyward:Mfa:RequiredForRoles`, defaulting to
`admin`. Anyone who has enrolled voluntarily is challenged as well, whatever their roles: turning a second
factor on and then not being asked for it is the kind of surprise that ends in a support ticket.

The claim travels into the access token, so a downstream API can insist on it for a dangerous operation
rather than trusting that the identity provider felt strongly about it.

## Consequences

Someone given the operator role while signed in is challenged on their next authorize request, not on
their next sign-in. The cookie they hold never cleared MFA and never will, so the gate catches them.

The password step issues a session cookie before the second factor is cleared. That cookie grants nothing
on its own: the authorize endpoint refuses it, and the admin API is behind a bearer token. It exists so
that the enrolment and challenge pages have something to identify the user by.

There is a known limitation, and it is inherent to enrol-on-first-sign-in rather than specific to this
implementation. Someone holding only a password, for an account that has not yet enrolled, can enrol their
own authenticator. Any deployment where that matters should have enrolment initiated by an operator, with
this flow reserved for accounts already known to have an authenticator. `docs/operations.md` says so.

Lockout backs off exponentially rather than using a fixed window, capped at an hour. A six-digit code has
a million values; a fixed one-minute lockout after five attempts still lets someone work through a
meaningful fraction of them in a day.
