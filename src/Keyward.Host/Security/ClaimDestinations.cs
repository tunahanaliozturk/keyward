using System.Security.Claims;
using OpenIddict.Abstractions;

namespace Keyward.Host.Security;

/// <summary>
/// Decides which token each claim is allowed into.
/// </summary>
/// <remarks>
/// Not a formality, and separated out because it is the piece most worth testing on its own. The identity
/// token goes to the browser and is readable by anything that can see it; the access token goes to an API.
/// Putting every claim in both is how an email address ends up in a front-end log, so a claim reaches the
/// identity token only when a scope was granted that asks for it.
/// </remarks>
public static class ClaimDestinations
{
    /// <summary>The claim carrying which tenant an account belongs to.</summary>
    public const string TenantClaim = "tenant_id";

    /// <summary>Marks a session as having completed a second factor.</summary>
    public const string MfaCompletedClaim = "amr_mfa";

    /// <summary>Lists the tokens a claim may appear in.</summary>
    /// <param name="claim">The claim, whose subject carries the granted scopes.</param>
    public static IEnumerable<string> For(Claim claim)
    {
        ArgumentNullException.ThrowIfNull(claim);

        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject?.HasScope(OpenIddictConstants.Scopes.Profile) is true)
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject?.HasScope(OpenIddictConstants.Scopes.Email) is true)
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            case OpenIddictConstants.Claims.Role:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject?.HasScope(OpenIddictConstants.Scopes.Roles) is true)
                {
                    yield return OpenIddictConstants.Destinations.IdentityToken;
                }

                yield break;

            case TenantClaim:
            case MfaCompletedClaim:
                // Authorisation input for downstream APIs. It has no business in a token the browser reads.
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;

            // OpenIddict keeps its own bookkeeping on the principal. Emitting it would leak internal state
            // into a token somebody else parses.
            case "AspNet.Identity.SecurityStamp":
                yield break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;
        }
    }
}
