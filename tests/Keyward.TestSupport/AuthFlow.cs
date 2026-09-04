using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Keyward.Host.Security;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;

namespace Keyward.TestSupport;

/// <summary>What the token endpoint returned.</summary>
/// <param name="StatusCode">HTTP status.</param>
/// <param name="Body">The parsed response.</param>
public sealed record TokenResponse(HttpStatusCode StatusCode, JsonElement Body)
{
    /// <summary>The access token, if one was issued.</summary>
    public string? AccessToken => Read("access_token");

    /// <summary>The refresh token, if one was issued.</summary>
    public string? RefreshToken => Read("refresh_token");

    /// <summary>The identity token, if one was issued.</summary>
    public string? IdentityToken => Read("id_token");

    /// <summary>The error code, if the request failed.</summary>
    public string? Error => Read("error");

    /// <summary>The human-readable reason, if the server gave one.</summary>
    public string? ErrorDescription => Read("error_description");

    /// <summary>True when tokens came back.</summary>
    public bool Succeeded => StatusCode is HttpStatusCode.OK && AccessToken is not null;

    private string? Read(string name) =>
        Body.ValueKind is JsonValueKind.Object && Body.TryGetProperty(name, out JsonElement value)
            ? value.GetString()
            : null;
}

/// <summary>
/// Drives the interactive flow the way a client would, over plain HTTP.
/// </summary>
/// <remarks>
/// <para>
/// The redirect chain is walked one hop at a time rather than by letting the handler follow it, because
/// where the user is sent is most of what these tests are asserting. A flow that ends in a token is not
/// evidence of much if the second factor was skipped along the way.
/// </para>
/// <para>
/// Forms are filled by reading the page, exactly as a browser would, including the antiforgery token. The
/// conformance suite does the same thing through a real browser; this exists so the rest of the suite can
/// reach a refresh token without paying for a browser every time.
/// </para>
/// </remarks>
/// <param name="fixture">The running provider.</param>
public sealed class AuthFlow(KeywardFixture fixture) : IDisposable
{
    private const int MaxHops = 12;

    private static readonly Regex AntiforgeryPattern = new(
        "<input[^>]*name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex ManualKeyPattern = new(
        "Enter this key by hand: <code>([A-Z2-7]+)</code>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex BackupCodePattern = new(
        "<span>([A-Z2-9-]{6,})</span>",
        RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex ContinuePattern = new(
        "<a href=\"([^\"]+)\"><button type=\"button\">Continue</button></a>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    private static readonly Regex ProtectedSecretPattern = new(
        "<input[^>]*name=\"ProtectedSecret\"[^>]*value=\"([^\"]*)\"",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    /// <summary>The client, which keeps the session cookie between calls.</summary>
    public HttpClient Client { get; } = fixture.CreateClient();

    /// <summary>The base32 secret enrolled during the flow, when one was.</summary>
    public string? EnrolledSecret { get; private set; }

    /// <summary>The recovery codes shown at enrolment, when the flow enrolled an authenticator.</summary>
    public IReadOnlyList<string> BackupCodes { get; private set; } = [];

    /// <summary>Whether the consent screen was shown.</summary>
    public bool ConsentShown { get; private set; }

    /// <summary>Where the flow finally sent the browser, including any error parameters.</summary>
    public string? FinalRedirect { get; private set; }

    /// <summary>A PKCE verifier and the challenge derived from it.</summary>
    public static (string Verifier, string Challenge) CreatePkcePair()
    {
        string verifier = Base64UrlTextEncoder.Encode(RandomNumberGenerator.GetBytes(32));

        string challenge = Base64UrlTextEncoder.Encode(
            SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

        return (verifier, challenge);
    }

    /// <summary>Builds an authorization request.</summary>
    /// <param name="clientId">Which client is asking.</param>
    /// <param name="challenge">The PKCE challenge.</param>
    /// <param name="scope">Requested scopes.</param>
    /// <param name="challengeMethod">The PKCE method, so a downgrade can be attempted deliberately.</param>
    public static string AuthorizeUrl(
        string clientId,
        string challenge,
        string scope = "openid email profile roles offline_access api",
        string challengeMethod = "S256") =>
        QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["client_id"] = clientId,
            ["response_type"] = "code",
            ["redirect_uri"] = KeywardFixture.RedirectUri,
            ["scope"] = scope,
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = challengeMethod,
            ["state"] = "state-value",
            ["nonce"] = "nonce-value",
        });

    /// <summary>
    /// Walks the flow from the authorize request to the authorization code.
    /// </summary>
    /// <param name="authorizeUrl">Where to start.</param>
    /// <param name="email">Who signs in.</param>
    /// <param name="password">Their password.</param>
    /// <param name="totpSecret">A secret to answer the second-factor challenge with, if one is expected.</param>
    /// <param name="approveConsent">Whether to approve the consent screen when it appears.</param>
    /// <returns>The code, or null when the flow ended somewhere other than the client's redirect.</returns>
    public async Task<string?> GetAuthorizationCodeAsync(
        string authorizeUrl,
        string email,
        string password,
        string? totpSecret = null,
        bool approveConsent = true)
    {
        string current = authorizeUrl;

        for (int hop = 0; hop < MaxHops; hop++)
        {
            // The client's redirect address belongs to an application that is not running here, so the walk
            // stops at it rather than trying to fetch it. Whatever it carries is the outcome of the flow.
            if (current.StartsWith(KeywardFixture.RedirectUri, StringComparison.Ordinal))
            {
                FinalRedirect = current;
                return ReadParameter(current, "code");
            }

            using HttpResponseMessage response = await Client.GetAsync(current);

            if (response.StatusCode is HttpStatusCode.Found or HttpStatusCode.Redirect)
            {
                current = response.Headers.Location!.ToString();
                continue;
            }

            if (response.StatusCode is not HttpStatusCode.OK)
            {
                return null;
            }

            string html = await response.Content.ReadAsStringAsync();
            string? next = await SubmitAsync(current, html, email, password, totpSecret, approveConsent);

            if (next is null)
            {
                return null;
            }

            current = next;
        }

        throw new UnreachableException("The redirect chain did not settle.");
    }

    /// <summary>Exchanges an authorization code for tokens.</summary>
    /// <param name="code">The code.</param>
    /// <param name="verifier">The PKCE verifier matching the challenge that was sent.</param>
    /// <param name="clientId">Which client.</param>
    public Task<TokenResponse> ExchangeCodeAsync(
        string code,
        string verifier,
        string clientId = KeywardFixture.InteractiveClientId) =>
        PostTokenAsync(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = clientId,
            ["code"] = code,
            ["code_verifier"] = verifier,
            ["redirect_uri"] = KeywardFixture.RedirectUri,
        });

    /// <summary>Exchanges a refresh token for a new pair.</summary>
    /// <param name="refreshToken">The token.</param>
    /// <param name="clientId">Which client.</param>
    public Task<TokenResponse> RefreshAsync(
        string refreshToken,
        string clientId = KeywardFixture.InteractiveClientId) =>
        PostTokenAsync(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = clientId,
            ["refresh_token"] = refreshToken,
        });

    /// <summary>Asks for a machine-to-machine token.</summary>
    /// <param name="scope">Requested scopes.</param>
    public Task<TokenResponse> ClientCredentialsAsync(string scope = "api") =>
        PostTokenAsync(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = KeywardFixture.ServiceClientId,
            ["client_secret"] = KeywardFixture.ServiceClientSecret,
            ["scope"] = scope,
        });

    /// <summary>Posts an arbitrary token request, for the cases that are meant to fail.</summary>
    /// <param name="form">The form fields.</param>
    public async Task<TokenResponse> PostTokenAsync(IDictionary<string, string> form)
    {
        using var content = new FormUrlEncodedContent(form);
        using HttpResponseMessage response = await Client.PostAsync("/connect/token", content);

        string body = await response.Content.ReadAsStringAsync();

        JsonElement parsed = string.IsNullOrWhiteSpace(body)
            ? default
            : JsonDocument.Parse(body).RootElement.Clone();

        return new TokenResponse(response.StatusCode, parsed);
    }

    /// <inheritdoc />
    public void Dispose() => Client.Dispose();

    /// <summary>Reads one query parameter off a redirect.</summary>
    /// <param name="location">The redirect address.</param>
    /// <param name="name">Parameter name.</param>
    public static string? ReadParameter(string location, string name) =>
        QueryHelpers.ParseQuery(new Uri(location).Query).TryGetValue(name, out StringValues value)
            ? value.ToString()
            : null;

    private static string RequireToken(string html) =>
        AntiforgeryPattern.Match(html) is { Success: true } match
            ? match.Groups[1].Value
            : throw new InvalidOperationException("The page did not carry an antiforgery token.");

    private async Task<string?> SubmitAsync(
        string current,
        string html,
        string email,
        string password,
        string? totpSecret,
        bool approveConsent)
    {
        string path = new Uri(fixture.BaseAddress, current).AbsolutePath;

        return path switch
        {
            "/Account/Login" => (await PostFormAsync(current, html, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Input.Email"] = email,
                ["Input.Password"] = password,
            })).Location,

            "/Account/Mfa" => (await PostFormAsync(current, html, new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["Code"] = totpSecret is null
                    ? "000000"
                    : TotpVerifier.Compute(totpSecret, DateTimeOffset.UtcNow),
            })).Location,

            "/Account/Enrol" => await EnrolAsync(current, html),

            "/Account/Consent" => approveConsent
                ? await ApproveConsentAsync(current, html)
                : await DenyConsentAsync(current, html),

            _ => null,
        };
    }

    /// <summary>
    /// Sets up an authenticator, then walks past the page that shows the recovery codes.
    /// </summary>
    /// <remarks>
    /// Enrolment is the one step that ends in a page rather than a redirect: the recovery codes are shown
    /// once, on the response to the post, and are gone as soon as it is left. The flow reads them here for
    /// the tests that need to spend one, then follows the continue link back into the authorize request.
    /// </remarks>
    private async Task<string?> EnrolAsync(string current, string html)
    {
        if (ManualKeyPattern.Match(html) is not { Success: true } key
            || ProtectedSecretPattern.Match(html) is not { Success: true } secret)
        {
            return null;
        }

        EnrolledSecret = key.Groups[1].Value;

        (HttpStatusCode status, string? location, string body) = await PostFormAsync(
            current,
            html,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ProtectedSecret"] = WebUtility.HtmlDecode(secret.Groups[1].Value),
                ["Code"] = TotpVerifier.Compute(EnrolledSecret, DateTimeOffset.UtcNow),
            });

        if (location is not null)
        {
            return location;
        }

        if (status is not HttpStatusCode.OK)
        {
            return null;
        }

        BackupCodes =
        [
            .. BackupCodePattern.Matches(body).Select(match => WebUtility.HtmlDecode(match.Groups[1].Value)),
        ];

        return ContinuePattern.Match(body) is { Success: true } link
            ? WebUtility.HtmlDecode(link.Groups[1].Value)
            : null;
    }

    private async Task<string?> ApproveConsentAsync(string current, string html)
    {
        ConsentShown = true;

        // The consent page posts the original authorize request back, so every hidden field on it has to
        // travel unchanged. Anything dropped here would be caught by OpenIddict re-validating the request.
        Dictionary<string, string> form = ReadHiddenFields(html);
        form["submit.accept"] = "yes";

        return (await PostToAsync("/connect/authorize", form)).Location;
    }

    private async Task<string?> DenyConsentAsync(string current, string html)
    {
        ConsentShown = true;

        Dictionary<string, string> form = ReadHiddenFields(html);
        form["submit.deny"] = "yes";

        return (await PostToAsync("/connect/authorize", form)).Location;
    }

    private static Dictionary<string, string> ReadHiddenFields(string html)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (Match match in Regex.Matches(
            html,
            "<input[^>]*type=\"hidden\"[^>]*name=\"([^\"]+)\"[^>]*value=\"([^\"]*)\"",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2)))
        {
            fields[WebUtility.HtmlDecode(match.Groups[1].Value)] =
                WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        foreach (Match match in Regex.Matches(
            html,
            "<input[^>]*name=\"([^\"]+)\"[^>]*type=\"hidden\"[^>]*value=\"([^\"]*)\"",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(2)))
        {
            fields[WebUtility.HtmlDecode(match.Groups[1].Value)] =
                WebUtility.HtmlDecode(match.Groups[2].Value);
        }

        return fields;
    }

    private Task<(HttpStatusCode Status, string? Location, string Body)> PostFormAsync(
        string current,
        string html,
        Dictionary<string, string> fields)
    {
        foreach (KeyValuePair<string, string> hidden in ReadHiddenFields(html))
        {
            fields.TryAdd(hidden.Key, hidden.Value);
        }

        fields["__RequestVerificationToken"] = RequireToken(html);

        return PostToAsync(current, fields);
    }

    private async Task<(HttpStatusCode Status, string? Location, string Body)> PostToAsync(
        string url,
        Dictionary<string, string> fields)
    {
        using var content = new FormUrlEncodedContent(fields);
        using HttpResponseMessage response = await Client.PostAsync(url, content);

        string? location = response.StatusCode is HttpStatusCode.Found or HttpStatusCode.Redirect
            ? response.Headers.Location!.ToString()
            : null;

        return (response.StatusCode, location, await response.Content.ReadAsStringAsync());
    }
}
