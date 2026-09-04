using System.Text.Json;
using System.Text.RegularExpressions;
using Keyward.Host.Security;
using Keyward.TestSupport;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Playwright;

namespace Keyward.ConformanceTests;

/// <summary>
/// The authorization code flow, driven through a real browser and verified the way a relying party would.
/// </summary>
/// <remarks>
/// <para>
/// Two claims are being backed up here. The first is that the interactive flow works for a person, not
/// merely for a client that knows which fields to post: a browser starts at the client's redirect, fills
/// the login form that is actually rendered, answers the consent screen that is actually shown, and
/// follows the redirect back.
/// </para>
/// <para>
/// The second is that the token it ends up with is verifiable by somebody who has never spoken to this
/// service. The signature is checked against the published key set, with no shared secret and no call back
/// to the issuer, which is the entire premise of handing a JWT to a third-party API.
/// </para>
/// </remarks>
/// <param name="fixture">The running provider.</param>
/// <param name="browsers">The browser.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class AuthorizationCodeConformanceTests(KeywardFixture fixture, BrowserFixture browsers)
{
    // Playwright translates this into a JavaScript regular expression, so only the flags that exist in
    // both languages survive the trip. IgnoreCase does; CultureInvariant does not.
    private static readonly Regex CallbackPattern = new(
        "^http://localhost:5199/callback",
        RegexOptions.IgnoreCase,
        TimeSpan.FromSeconds(2));

    [Fact]
    public async Task A_browser_completes_the_flow_and_the_token_verifies_against_the_published_keys()
    {
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string landed = await DriveAsync(AuthFlow.AuthorizeUrl(
            KeywardFixture.InteractiveClientId,
            challenge,
            scope: "openid email profile roles offline_access api"));

        string? code = AuthFlow.ReadParameter(landed, "code");
        code.ShouldNotBeNull();

        // The client's own state parameter comes back untouched. Losing it is how a client ends up unable
        // to tell its own request apart from one somebody else started in the user's browser.
        AuthFlow.ReadParameter(landed, "state").ShouldBe("state-value");

        using var flow = new AuthFlow(fixture);
        TokenResponse tokens = await flow.ExchangeCodeAsync(code, verifier);

        tokens.Succeeded.ShouldBeTrue();
        tokens.RefreshToken.ShouldNotBeNull();
        tokens.IdentityToken.ShouldNotBeNull();

        TokenValidationResult result = await ValidateAsync(tokens.AccessToken!);

        result.IsValid.ShouldBeTrue();

        result.Claims[ClaimDestinations.TenantClaim].ToString().ShouldNotBeNullOrWhiteSpace();
        result.Claims["sub"].ToString().ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task A_code_taken_from_the_redirect_is_worthless_without_the_verifier()
    {
        (_, string challenge) = AuthFlow.CreatePkcePair();
        (string otherVerifier, _) = AuthFlow.CreatePkcePair();

        string landed = await DriveAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge, scope: "openid email"));

        string? code = AuthFlow.ReadParameter(landed, "code");
        code.ShouldNotBeNull();

        using var flow = new AuthFlow(fixture);

        // This is the attack proof key exists to stop: the code was observed on the redirect, and it buys
        // the observer nothing because they never saw the verifier.
        TokenResponse tokens = await flow.ExchangeCodeAsync(code, otherVerifier);

        tokens.Succeeded.ShouldBeFalse();
        tokens.Error.ShouldBe("invalid_grant");
    }

    /// <summary>Walks a browser through the flow and returns the address it was finally sent to.</summary>
    /// <param name="authorizeUrl">The authorize request, relative to the provider.</param>
    private async Task<string> DriveAsync(string authorizeUrl)
    {
        await using IBrowserContext context = await browsers.Browser.NewContextAsync(new BrowserNewContextOptions
        {
            BaseURL = fixture.BaseAddress.ToString(),
        });

        IPage page = await context.NewPageAsync();

        // The client application is not running, so nothing answers its redirect address. Rather than
        // stubbing it, the test waits for the request the browser makes to it: that request carries the
        // authorization code, which is the only thing the flow was after. Whether a page loads afterwards
        // is the client application's business, and it is not part of this service.
        Task<IRequest> callback = page.WaitForRequestAsync(
            CallbackPattern,
            new PageWaitForRequestOptions { Timeout = 30_000 });

        await page.GotoAsync(authorizeUrl);

        await page.FillAsync("input[name='Input.Email']", KeywardFixture.UserEmail);
        await page.FillAsync("input[name='Input.Password']", KeywardFixture.UserPassword);
        await page.ClickAsync("button[type='submit']");

        await page.WaitForLoadStateAsync(LoadState.Load);

        if (page.Url.Contains("/Account/Consent", StringComparison.OrdinalIgnoreCase))
        {
            await page.ClickAsync("button[name='submit.accept']");
        }

        IRequest request = await callback;

        return request.Url;
    }

    /// <summary>Verifies a token the way a relying party would: against the published key set.</summary>
    /// <param name="token">The access token.</param>
    private async Task<TokenValidationResult> ValidateAsync(string token)
    {
        using HttpClient client = fixture.CreateClient();

        string keys = await client.GetStringAsync("/.well-known/jwks");

        using JsonDocument discovery = JsonDocument.Parse(
            await client.GetStringAsync("/.well-known/openid-configuration"));

        string issuer = discovery.RootElement.GetProperty("issuer").GetString()!;

        return await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
        {
            IssuerSigningKeys = JsonWebKeySet.Create(keys).GetSigningKeys(),
            ValidIssuer = issuer,
            ValidateAudience = false,
            ValidateLifetime = true,
        });
    }
}
