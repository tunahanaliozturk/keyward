using Keyward.Data;
using Keyward.Host.Seeding;
using Keyward.TestSupport;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace Keyward.IntegrationTests;

/// <summary>
/// Who gets asked, and what happens when they say no.
/// </summary>
/// <remarks>
/// A consent screen shown for a company's own portal is a dialog people learn to click through without
/// reading, which makes the one that matters less likely to be read. So the decision is a property of the
/// client registration, and the tests hold both sides of it.
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class ConsentTests(KeywardFixture fixture)
{
    [Fact]
    public async Task A_third_party_client_asks_before_it_is_allowed_anything()
    {
        await ForgetConsentAsync();

        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge, scope: "openid email"),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        flow.ConsentShown.ShouldBeTrue();
        code.ShouldNotBeNull();

        (await flow.ExchangeCodeAsync(code, verifier)).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public async Task Refusing_consent_sends_the_client_away_with_access_denied()
    {
        await ForgetConsentAsync();

        using var flow = new AuthFlow(fixture);
        (_, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(
                KeywardFixture.InteractiveClientId,
                challenge,
                scope: "openid email profile roles"),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword,
            approveConsent: false);

        flow.ConsentShown.ShouldBeTrue();
        code.ShouldBeNull();

        flow.FinalRedirect.ShouldNotBeNull();
        AuthFlow.ReadParameter(flow.FinalRedirect, "error").ShouldBe("access_denied");
    }

    [Fact]
    public async Task A_first_party_client_is_not_asked()
    {
        await ForgetConsentAsync();

        using var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(DatabaseInitializer.DemoFirstPartyClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        flow.ConsentShown.ShouldBeFalse();
        code.ShouldNotBeNull();

        TokenResponse tokens = await flow.ExchangeCodeAsync(
            code,
            verifier,
            DatabaseInitializer.DemoFirstPartyClientId);

        tokens.Succeeded.ShouldBeTrue();
    }

    [Fact]
    public async Task Consent_is_remembered_so_the_same_client_is_not_asked_twice()
    {
        await ForgetConsentAsync();

        using var first = new AuthFlow(fixture);
        (string firstVerifier, string firstChallenge) = AuthFlow.CreatePkcePair();

        string url = AuthFlow.AuthorizeUrl(
            KeywardFixture.InteractiveClientId,
            firstChallenge,
            scope: "openid profile");

        string? code = await first.GetAuthorizationCodeAsync(
            url,
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        first.ConsentShown.ShouldBeTrue();
        (await first.ExchangeCodeAsync(code!, firstVerifier)).Succeeded.ShouldBeTrue();

        using var second = new AuthFlow(fixture);
        (string secondVerifier, string secondChallenge) = AuthFlow.CreatePkcePair();

        string? repeat = await second.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, secondChallenge, scope: "openid profile"),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        // The answer was stored as a permanent authorization the first time round.
        second.ConsentShown.ShouldBeFalse();
        repeat.ShouldNotBeNull();

        (await second.ExchangeCodeAsync(repeat, secondVerifier)).Succeeded.ShouldBeTrue();
    }

    /// <summary>
    /// Puts the account back to having agreed to nothing.
    /// </summary>
    /// <remarks>
    /// Consent is remembered as a permanent authorization, which is the behaviour one of these tests
    /// asserts and the reason the others have to start from a clean slate. Without this, whichever test
    /// happened to run first would grant consent and every test after it would see a client that is never
    /// asked, and pass or fail depending on the order.
    /// </remarks>
    private async Task ForgetConsentAsync()
    {
        await using AsyncServiceScope scope = fixture.Services.CreateAsyncScope();

        KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();
        IOpenIddictAuthorizationManager authorizations =
            scope.ServiceProvider.GetRequiredService<IOpenIddictAuthorizationManager>();

        Guid userId = await dbContext.Users
            .Where(user => user.Email == KeywardFixture.UserEmail)
            .Select(user => user.Id)
            .FirstAsync(TestContext.Current.CancellationToken);

        await foreach (object authorization in authorizations.FindBySubjectAsync(
            userId.ToString(),
            TestContext.Current.CancellationToken))
        {
            await authorizations.TryRevokeAsync(authorization, TestContext.Current.CancellationToken);
        }
    }
}
