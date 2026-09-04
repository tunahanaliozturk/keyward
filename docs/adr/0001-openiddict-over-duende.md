# 1. OpenIddict rather than Duende IdentityServer

Status: accepted

## Context

An identity provider needs an OAuth 2.0 and OpenID Connect engine. Writing one is not a reasonable
option: the specifications are long, the failure modes are subtle, and the difference between a correct
implementation and a plausible-looking one is invisible until somebody exploits it. The two mature
options in .NET are Duende IdentityServer and OpenIddict.

Duende is the better-resourced product. It has an admin UI ecosystem, commercial support, and a large
installed base. It is also commercially licensed above a revenue threshold, and its licence is checked at
runtime.

## Decision

OpenIddict 7.6, under Apache-2.0.

## Consequences

The deciding factor is not price. It is that this repository is meant to be cloned and run by somebody
who has never spoken to its author, and a dependency that asks for a licence key changes what "clone and
run" means. It would also fail the licence audit in `tools/Keyward.LicenseAudit`, which refuses anything
in the tree that is not permissively licensed, and carving out an exception for the single most important
dependency would make that gate decorative.

What is given up is real. Duende ships an administration story; OpenIddict does not, which is why
`src/Keyward.Host/Endpoints/AdminEndpoints.cs` exists at all. Duende's documentation is more approachable
for someone new to the protocol. OpenIddict's extensibility model, which this project leans on heavily for
refresh-token families, is a pipeline of ordered event handlers and takes longer to learn than a set of
interfaces.

What is gained, beyond the licence, is that the extensibility model is genuinely more granular. The reuse
detector in `RefreshTokenReuseDetector` inserts itself into the authentication pipeline at a chosen point
and reads OpenIddict's own token store, rather than working around the library from outside.

## Alternatives considered

**Duende IdentityServer 7.x.** Rejected on licensing, as above. If this were a commercial product with a
budget line for identity, the calculation would be different and probably the other way round.

**Keycloak or another external provider.** A reasonable choice for a real deployment and the wrong one
here, since the point of the project is the parts that are usually opaque: what happens when a refresh
token is replayed, and where the second factor sits in the flow.

**Hand-written.** No.
