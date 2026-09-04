# 5. The consent screen re-posts the original request rather than deciding anything

Status: accepted

## Context

A consent screen sits in the middle of an authorize request. The user is asked whether a client may act on
their behalf, and the answer has to find its way back into a protocol exchange that was already in flight.

The tempting shortcut is to have the consent page finish the job: read the parameters, decide, and issue
the redirect itself. That means a second implementation of the protocol rules, in a Razor page, that has
to agree with the first one about redirect URI validation, response modes and error formats. The two
implementations agree on the day they are written.

## Decision

The authorize endpoint redirects to `/Account/Consent` with the original request as a return address. The
page renders that request as hidden form fields and posts it back to `/connect/authorize`, adding one
field: `submit.accept` or `submit.deny`. OpenIddict validates the whole request again on the way in.

The answer, once given, is stored as a permanent OpenIddict authorization, so the same client asking for
the same scopes is not asked twice.

Whether a client is asked at all is a property of its registration. A client registered with implicit
consent is not asked; anything else is. Asking a user whether their employer's own portal may read their
own name is a dialog people learn to click through without reading, which makes the one that matters less
likely to be read.

## Consequences

The consent form is a cross-site request forgery target, and OpenIddict does not defend it, because the
authorize endpoint is normally reached by redirect rather than by form post. Without a check, a page under
an attacker's control could silently approve a client they registered, using the victim's session cookie.
The form therefore carries an antiforgery token and the authorize endpoint validates it before honouring
an approval. Approval is the only decision that needs it: a denial that an attacker forges achieves
nothing except annoying somebody.

Every parameter has to survive the round trip unaltered. If one is dropped, OpenIddict rejects the request
on the way back in, which is the right failure: the same code that would have caught a malformed request
the first time catches it the second time.

Consent behaviour is covered by four tests in `ConsentTests`, including the one that asserts a first-party
client is never asked and the one that asserts a refusal reaches the client as `access_denied`.
