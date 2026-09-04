using Keyward.TestSupport;

namespace Keyward.IntegrationTests;

/// <summary>
/// Machine-to-machine tokens.
/// </summary>
/// <remarks>
/// The interesting assertion is the absence of a refresh token. A service holding its own credentials can
/// ask for another access token whenever it likes, so a refresh token would be a second long-lived secret
/// to store, rotate and lose, in exchange for nothing.
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class ClientCredentialsTests(KeywardFixture fixture)
{
    [Fact]
    public async Task A_service_with_its_secret_gets_an_access_token_and_nothing_else()
    {
        using var flow = new AuthFlow(fixture);

        TokenResponse tokens = await flow.ClientCredentialsAsync();

        tokens.Succeeded.ShouldBeTrue();
        tokens.RefreshToken.ShouldBeNull();
        tokens.IdentityToken.ShouldBeNull();

        JwtReader.ReadClaim(tokens.AccessToken!, "sub").ShouldBe(KeywardFixture.ServiceClientId);
    }

    [Fact]
    public async Task The_wrong_secret_gets_nothing()
    {
        using var flow = new AuthFlow(fixture);

        TokenResponse tokens = await flow.PostTokenAsync(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = KeywardFixture.ServiceClientId,
            ["client_secret"] = "not-the-secret",
            ["scope"] = "api",
        });

        tokens.Succeeded.ShouldBeFalse();
        tokens.Error.ShouldBe("invalid_client");
    }

    [Fact]
    public async Task A_scope_the_client_was_not_granted_is_refused()
    {
        using var flow = new AuthFlow(fixture);

        // The scope exists and this client was simply never granted it, which is a different failure from
        // asking for something that does not exist at all.
        TokenResponse tokens = await flow.ClientCredentialsAsync("api reports");

        tokens.Succeeded.ShouldBeFalse();
        tokens.ErrorDescription.ShouldNotBeNull();
        tokens.ErrorDescription!.ShouldContain("scope");
    }

    [Fact]
    public async Task A_public_client_cannot_use_the_client_credentials_grant()
    {
        using var flow = new AuthFlow(fixture);

        // A public client has no secret to prove anything with. Letting one through here would mean anyone
        // who knows the client id can mint tokens.
        TokenResponse tokens = await flow.PostTokenAsync(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = KeywardFixture.InteractiveClientId,
            ["scope"] = "api",
        });

        tokens.Succeeded.ShouldBeFalse();
        tokens.Error.ShouldNotBeNull();
    }
}
