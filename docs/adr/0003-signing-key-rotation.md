# 3. Signing keys rotate by prepending, and the old key stays published

Status: accepted

## Context

Access tokens are signed, not encrypted, and relying parties verify them against the key set published at
`/.well-known/jwks`. That is the whole point: an API validates a token locally and never calls back to
this service.

It also means a key rotation is a coordination problem. A relying party caches the key set, often for
hours. A token signed a second before a rotation is still valid for its full lifetime afterwards. Swapping
the key and removing the old one at the same moment produces a window in which valid tokens are rejected
by parties that have not refreshed their cache, and in which tokens signed by a key nobody has yet fetched
are rejected too.

## Decision

`Keyward:Signing:SigningCertificates` is an ordered list. The first entry signs. Every entry is published
to the key set. Rotating means prepending the new certificate and leaving the previous one in place for a
grace window, then removing it.

The grace window has to outlast two things: the longest access token lifetime, and however often relying
parties refresh their key cache. Twenty-four hours covers both comfortably for a five-minute token, and is
the value the runbook uses.

Data Protection keys, which protect the reference-token payloads and the session cookie, are a separate
concern and live in the database via `IDataProtectionKeyContext`. On disk they work until there are two
instances, at which point each signs with its own key and rejects everything the other issued.

## Consequences

A rotation is two deploys, not one, and the second cannot be skipped: leaving a retired key published
means a stolen private key stays usable. The runbook states both steps and the wait between them.

Outside development the service refuses to start without configured certificates. The alternative, falling
back to ephemeral development keys, means every restart invalidates every token that was ever issued, and
does so quietly. Failing at startup with an explanation is better than a service that appears to work and
loses everyone's session on the next deploy.

The key set is asserted in `DiscoveryTests.The_key_set_publishes_the_previous_signing_key_alongside_the_current_one`,
which runs against a fixture configured the way a mid-rotation service looks: two signing certificates,
the newer one signing.
