using System.Net;
using System.Text.Json;
using Keyward.TestSupport;

namespace Keyward.IntegrationTests;

/// <summary>
/// The two documents every relying party reads before it trusts anything.
/// </summary>
/// <remarks>
/// A client library builds its entire configuration out of the discovery document, so a missing field does
/// not produce a helpful error: it produces a client that silently skips a check. These assertions are the
/// shape of the contract, not a formality.
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class DiscoveryTests(KeywardFixture fixture)
{
    [Fact]
    public async Task The_discovery_document_advertises_the_endpoints_and_grants_this_service_supports()
    {
        using HttpClient client = fixture.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/.well-known/openid-configuration");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement root = document.RootElement;

        root.GetProperty("issuer").GetString().ShouldNotBeNullOrWhiteSpace();
        root.GetProperty("authorization_endpoint").GetString().ShouldEndWith("/connect/authorize");
        root.GetProperty("token_endpoint").GetString().ShouldEndWith("/connect/token");
        root.GetProperty("jwks_uri").GetString().ShouldNotBeNullOrWhiteSpace();

        Values(root, "grant_types_supported").ShouldBe(
            ["authorization_code", "refresh_token", "client_credentials"],
            ignoreOrder: true);

        // The point of the whole PKCE story: a client library reads this and knows the plain method is not
        // on the table.
        Values(root, "code_challenge_methods_supported").ShouldBe(["S256"]);
    }

    [Fact]
    public async Task The_key_set_publishes_the_previous_signing_key_alongside_the_current_one()
    {
        using HttpClient client = fixture.CreateClient();

        using HttpResponseMessage response = await client.GetAsync("/.well-known/jwks");
        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement keys = document.RootElement.GetProperty("keys");

        // Two keys, because the fixture is configured the way a rotation leaves a service: the new key
        // signs and the old one is still published. A relying party that cached the old key an hour ago
        // keeps working until it refreshes.
        keys.GetArrayLength().ShouldBe(2);

        foreach (JsonElement key in keys.EnumerateArray())
        {
            key.GetProperty("kty").GetString().ShouldBe("RSA");
            key.GetProperty("kid").GetString().ShouldNotBeNullOrWhiteSpace();
            key.TryGetProperty("d", out _).ShouldBeFalse();
        }
    }

    [Fact]
    public async Task Health_checks_report_the_database()
    {
        using HttpClient client = fixture.CreateClient();

        using HttpResponseMessage live = await client.GetAsync("/health/live");
        using HttpResponseMessage ready = await client.GetAsync("/health/ready");

        live.StatusCode.ShouldBe(HttpStatusCode.OK);
        ready.StatusCode.ShouldBe(HttpStatusCode.OK);
    }

    private static string[] Values(JsonElement root, string property) =>
        [.. root.GetProperty(property).EnumerateArray().Select(value => value.GetString()!)];
}
