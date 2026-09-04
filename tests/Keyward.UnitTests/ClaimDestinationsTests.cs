using System.Security.Claims;
using Keyward.Host.Security;
using OpenIddict.Abstractions;

namespace Keyward.UnitTests;

/// <summary>
/// Which token each claim is allowed into.
/// </summary>
/// <remarks>
/// This is the difference between an authorisation input and a piece of information handed to a browser.
/// A regression here does not break anything: tokens keep working, and a claim that should have stayed
/// server-side quietly starts appearing in a document any script on the page can read.
/// </remarks>
public sealed class ClaimDestinationsTests
{
    [Fact]
    public void The_tenant_claim_never_reaches_the_identity_token()
    {
        string[] destinations = [.. ClaimDestinations.For(
            ClaimWithScopes(ClaimDestinations.TenantClaim, "value", OpenIddictConstants.Scopes.Profile))];

        destinations.ShouldBe([OpenIddictConstants.Destinations.AccessToken]);
    }

    [Fact]
    public void The_multi_factor_marker_never_reaches_the_identity_token()
    {
        string[] destinations = [.. ClaimDestinations.For(
            ClaimWithScopes(ClaimDestinations.MfaCompletedClaim, "true", OpenIddictConstants.Scopes.Profile))];

        destinations.ShouldBe([OpenIddictConstants.Destinations.AccessToken]);
    }

    [Fact]
    public void The_email_claim_reaches_the_identity_token_only_when_the_email_scope_was_granted()
    {
        Claim withScope = ClaimWithScopes(
            OpenIddictConstants.Claims.Email,
            "someone@example.com",
            OpenIddictConstants.Scopes.Email);

        Claim withoutScope = ClaimWithScopes(
            OpenIddictConstants.Claims.Email,
            "someone@example.com",
            OpenIddictConstants.Scopes.Profile);

        ClaimDestinations.For(withScope).ShouldContain(OpenIddictConstants.Destinations.IdentityToken);
        ClaimDestinations.For(withoutScope).ShouldNotContain(OpenIddictConstants.Destinations.IdentityToken);
    }

    [Fact]
    public void The_role_claim_reaches_the_identity_token_only_when_the_roles_scope_was_granted()
    {
        Claim withScope = ClaimWithScopes(
            OpenIddictConstants.Claims.Role,
            "admin",
            OpenIddictConstants.Scopes.Roles);

        Claim withoutScope = ClaimWithScopes(
            OpenIddictConstants.Claims.Role,
            "admin",
            OpenIddictConstants.Scopes.Profile);

        ClaimDestinations.For(withScope).ShouldContain(OpenIddictConstants.Destinations.IdentityToken);
        ClaimDestinations.For(withoutScope).ShouldNotContain(OpenIddictConstants.Destinations.IdentityToken);
    }

    [Fact]
    public void The_security_stamp_is_emitted_nowhere()
    {
        Claim stamp = ClaimWithScopes(
            "AspNet.Identity.SecurityStamp",
            "abc",
            OpenIddictConstants.Scopes.Profile);

        ClaimDestinations.For(stamp).ShouldBeEmpty();
    }

    [Fact]
    public void An_unrecognised_claim_defaults_to_the_access_token_only()
    {
        string[] destinations = [.. ClaimDestinations.For(
            ClaimWithScopes("something_bespoke", "value", OpenIddictConstants.Scopes.Profile))];

        destinations.ShouldBe([OpenIddictConstants.Destinations.AccessToken]);
    }

    /// <summary>
    /// Builds a claim the way the authorize endpoint does.
    /// </summary>
    /// <remarks>
    /// Through OpenIddict's own <c>SetClaim</c> rather than <c>new Claim(...)</c>, because the destination
    /// policy reads the granted scopes off <see cref="Claim.Subject"/> and only that path attaches one. A
    /// hand-built claim has a null subject, which would make every one of these tests pass for the wrong
    /// reason by reporting that no scope was granted.
    /// </remarks>
    private static Claim ClaimWithScopes(string type, string value, params string[] scopes)
    {
        var identity = new ClaimsIdentity("test");
        identity.SetScopes(scopes);
        identity.SetClaim(type, value);

        return identity.FindFirst(type)!;
    }
}
