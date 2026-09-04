using System.Net;
using System.Text.Json;
using Keyward.Host.Security;
using Keyward.TestSupport;

namespace Keyward.IntegrationTests;

/// <summary>
/// The interactive grant, including the ways it is supposed to fail.
/// </summary>
/// <remarks>
/// Proof key is the reason this grant is safe for a client that cannot keep a secret, so the negative
/// cases carry as much weight as the happy path. A code intercepted on the redirect is worthless without
/// the verifier, and only if the server actually insists on one.
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class AuthorizationCodeTests(KeywardFixture fixture)
{
    [Fact]
    public async Task A_full_sign_in_produces_tokens_carrying_the_tenant_and_roles()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        code.ShouldNotBeNull();

        TokenResponse tokens = await flow.ExchangeCodeAsync(code, verifier);

        tokens.Succeeded.ShouldBeTrue();
        tokens.RefreshToken.ShouldNotBeNull();
        tokens.IdentityToken.ShouldNotBeNull();

        // The tenant claim is the one downstream services authorize on, and it belongs in the access token
        // only. An identity token is handed to a browser.
        JwtReader.ReadClaim(tokens.AccessToken!, ClaimDestinations.TenantClaim).ShouldNotBeNullOrWhiteSpace();
        JwtReader.ReadClaim(tokens.IdentityToken!, ClaimDestinations.TenantClaim).ShouldBeNull();

        JwtReader.ReadClaims(tokens.AccessToken!, "role").ShouldContain("user");
        JwtReader.ReadClaim(tokens.IdentityToken!, "sub").ShouldNotBeNullOrWhiteSpace();
    }

    [Fact]
    public async Task A_code_cannot_be_exchanged_with_the_wrong_verifier()
    {
        using var flow = new AuthFlow(fixture);
        (_, string challenge) = AuthFlow.CreatePkcePair();
        (string otherVerifier, _) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        code.ShouldNotBeNull();

        TokenResponse tokens = await flow.ExchangeCodeAsync(code, otherVerifier);

        tokens.Succeeded.ShouldBeFalse();
        tokens.Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task A_code_cannot_be_exchanged_twice()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        code.ShouldNotBeNull();

        (await flow.ExchangeCodeAsync(code, verifier)).Succeeded.ShouldBeTrue();

        TokenResponse replay = await flow.ExchangeCodeAsync(code, verifier);

        replay.Succeeded.ShouldBeFalse();
        replay.Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task The_plain_challenge_method_is_refused()
    {
        (string verifier, _) = AuthFlow.CreatePkcePair();

        // The plain method sends the verifier itself as the challenge, which protects against nothing once
        // the authorize request has been seen. A server that quietly accepts it turns proof key into
        // decoration. The request is refused outright rather than redirected: a malformed authorize request
        // is not something to hand back to a client as if it were a normal protocol outcome.
        (HttpStatusCode status, string body) = await AuthorizeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, verifier, challengeMethod: "plain"));

        status.ShouldBe(HttpStatusCode.BadRequest);
        body.ShouldContain("invalid_request");
    }

    [Fact]
    public async Task An_authorization_request_without_a_challenge_is_refused()
    {
        (HttpStatusCode status, string body) = await AuthorizeAsync(
            "/connect/authorize"
            + $"?client_id={KeywardFixture.InteractiveClientId}"
            + "&response_type=code"
            + $"&redirect_uri={Uri.EscapeDataString(KeywardFixture.RedirectUri)}"
            + "&scope=openid");

        // Proof key is mandatory, not merely supported, so a request that omits it never gets as far as a
        // login form.
        status.ShouldBe(HttpStatusCode.BadRequest);
        body.ShouldContain("invalid_request");
    }

    private async Task<(HttpStatusCode Status, string Body)> AuthorizeAsync(string url)
    {
        using HttpClient client = fixture.CreateClient();
        using HttpResponseMessage response = await client.GetAsync(url);

        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_wrong_password_does_not_reveal_whether_the_account_exists()
    {
        using HttpClient client = fixture.CreateClient();

        string missing = await AttemptAsync(client, "nobody@keyward.local", "whatever-is-wrong");
        string wrong = await AttemptAsync(client, KeywardFixture.UserEmail, "definitely-not-it");

        missing.ShouldBe(wrong);
    }

    [Fact]
    public async Task The_user_info_endpoint_answers_a_bearer_token()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        TokenResponse tokens = await flow.ExchangeCodeAsync(code!, verifier);

        using HttpClient client = fixture.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/connect/userinfo");
        request.Headers.Authorization = new("Bearer", tokens.AccessToken);

        using HttpResponseMessage response = await client.SendAsync(request);
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        document.RootElement.GetProperty("email").GetString().ShouldBe(KeywardFixture.UserEmail);
    }

    [Fact]
    public async Task The_user_info_endpoint_refuses_an_anonymous_caller()
    {
        using HttpClient client = fixture.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/connect/userinfo");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    private static async Task<string> AttemptAsync(HttpClient client, string email, string password)
    {
        using HttpResponseMessage page = await client.GetAsync("/Account/Login");
        string html = await page.Content.ReadAsStringAsync();

        string token = System.Text.RegularExpressions.Regex.Match(
            html,
            "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase,
            TimeSpan.FromSeconds(2)).Groups[1].Value;

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
            ["__RequestVerificationToken"] = token,
        });

        using HttpResponseMessage response = await client.PostAsync("/Account/Login", content);
        string body = await response.Content.ReadAsStringAsync();

        int start = body.IndexOf("<p class=\"error\">", StringComparison.Ordinal);
        start.ShouldBeGreaterThan(-1);

        return body[start..body.IndexOf("</p>", start, StringComparison.Ordinal)];
    }
}
