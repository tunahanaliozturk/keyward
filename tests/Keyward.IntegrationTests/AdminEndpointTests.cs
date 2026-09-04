using System.Net;
using System.Text.Json;
using Keyward.Data;
using Keyward.Domain;
using Keyward.TestSupport;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Keyward.IntegrationTests;

/// <summary>
/// The endpoints an operator uses when a laptop goes missing.
/// </summary>
/// <remarks>
/// Two things are being tested. That the endpoints do what they say, and that they are unreachable without
/// a bearer token carrying the operator role. An administrative surface that trusts a browser session is
/// reachable from any page the operator happens to have open in the same browser.
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class AdminEndpointTests(KeywardFixture fixture)
{
    [Fact]
    public async Task An_anonymous_caller_gets_nowhere()
    {
        using HttpClient client = fixture.CreateClient();

        using HttpResponseMessage response = await client.GetAsync($"/admin/users/{Guid.NewGuid()}/sessions");

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task A_token_without_the_operator_role_is_refused()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        TokenResponse tokens = await flow.ExchangeCodeAsync(code!, verifier);

        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Get,
            $"/admin/users/{Guid.NewGuid()}/sessions",
            tokens.AccessToken!);

        response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task An_operator_can_see_a_session_and_end_it()
    {
        (string userToken, Guid userId) = await SignInOrdinaryUserAsync();
        string operatorToken = await SignInOperatorAsync();

        using HttpResponseMessage listed = await SendAsync(
            HttpMethod.Get,
            $"/admin/users/{userId}/sessions",
            operatorToken);

        listed.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument document = JsonDocument.Parse(await listed.Content.ReadAsStringAsync());
        JsonElement sessions = document.RootElement;

        sessions.GetArrayLength().ShouldBeGreaterThan(0);

        JsonElement active = sessions
            .EnumerateArray()
            .First(session => session.GetProperty("status").GetString() == nameof(FamilyStatus.Active));

        Guid familyId = active.GetProperty("id").GetGuid();

        using HttpResponseMessage revoked = await SendAsync(
            HttpMethod.Post,
            $"/admin/sessions/{familyId}/revoke",
            operatorToken);

        revoked.StatusCode.ShouldBe(HttpStatusCode.NoContent);

        await using AsyncServiceScope scope = fixture.Services.CreateAsyncScope();
        KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        RefreshTokenFamily family = await dbContext.RefreshTokenFamilies
            .AsNoTracking()
            .FirstAsync(candidate => candidate.Id == familyId);

        family.Status.ShouldBe(FamilyStatus.Revoked);
        family.RevocationReason.ShouldBe(FamilyRevocationReason.RevokedByOperator);

        _ = userToken;
    }

    [Fact]
    public async Task Revoking_every_session_for_an_account_stops_its_refresh_tokens()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        TokenResponse tokens = await flow.ExchangeCodeAsync(code!, verifier);
        tokens.RefreshToken.ShouldNotBeNull();

        Guid userId = Guid.Parse(JwtReader.ReadClaim(tokens.AccessToken!, "sub")!);
        string operatorToken = await SignInOperatorAsync();

        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Post,
            $"/admin/users/{userId}/sessions/revoke",
            operatorToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        // The refresh token was valid a moment ago. This is what a support call about a stolen laptop is
        // supposed to accomplish.
        TokenResponse refused = await flow.RefreshAsync(tokens.RefreshToken!);

        refused.Succeeded.ShouldBeFalse();
        refused.Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task The_audit_trail_can_be_read_and_filtered()
    {
        string operatorToken = await SignInOperatorAsync();

        using HttpResponseMessage response = await SendAsync(
            HttpMethod.Get,
            $"/admin/audit?type={AuthEventType.LoginSucceeded}&limit=5",
            operatorToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);

        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement entries = document.RootElement;

        entries.GetArrayLength().ShouldBeInRange(1, 5);

        foreach (JsonElement entry in entries.EnumerateArray())
        {
            entry.GetProperty("type").GetString().ShouldBe(nameof(AuthEventType.LoginSucceeded));
        }
    }

    private async Task<(string Token, Guid UserId)> SignInOrdinaryUserAsync()
    {
        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        TokenResponse tokens = await flow.ExchangeCodeAsync(code!, verifier);
        tokens.Succeeded.ShouldBeTrue();

        return (tokens.AccessToken!, Guid.Parse(JwtReader.ReadClaim(tokens.AccessToken!, "sub")!));
    }

    private async Task<string> SignInOperatorAsync()
    {
        await using (AsyncServiceScope scope = fixture.Services.CreateAsyncScope())
        {
            KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            User account = await dbContext.Users.FirstAsync(user => user.Email == KeywardFixture.AdminEmail);
            account.ClearFailedMfaAttempts();

            await dbContext.MfaSecrets.Where(secret => secret.UserId == account.Id).ExecuteDeleteAsync();
            await dbContext.MfaBackupCodes.Where(code => code.UserId == account.Id).ExecuteDeleteAsync();
            await dbContext.SaveChangesAsync();
        }

        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.AdminEmail,
            KeywardFixture.AdminPassword);

        TokenResponse tokens = await flow.ExchangeCodeAsync(code!, verifier);
        tokens.Succeeded.ShouldBeTrue();

        return tokens.AccessToken!;
    }

    private async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, string token)
    {
        using HttpClient client = fixture.CreateClient();
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new("Bearer", token);

        return await client.SendAsync(request);
    }
}
