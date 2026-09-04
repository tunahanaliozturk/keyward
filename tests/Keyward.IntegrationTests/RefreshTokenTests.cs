using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Keyward.TestSupport;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Keyward.IntegrationTests;

/// <summary>
/// Rotation, and the part that makes rotation worth anything.
/// </summary>
/// <remarks>
/// <para>
/// Rotating a refresh token on every use is easy and, on its own, protects nobody. A thief who steals one
/// simply spends it, receives a fresh one, and carries on; the rotation happened, the theft did not stop.
/// The theft only becomes visible when the legitimate client later presents the token the thief already
/// spent, and it only becomes harmless if that moment kills the token the thief is holding as well.
/// </para>
/// <para>
/// That is the assertion in <see cref="Replaying_a_spent_refresh_token_kills_the_whole_family"/>, and it is
/// the one test in this repository worth reading first.
/// </para>
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class RefreshTokenTests(KeywardFixture fixture)
{
    [Fact]
    public async Task A_refresh_returns_a_different_token_every_time()
    {
        using var flow = new AuthFlow(fixture);
        TokenResponse first = await SignInAsync(flow);

        TokenResponse second = await flow.RefreshAsync(first.RefreshToken!);

        second.Succeeded.ShouldBeTrue();
        second.RefreshToken.ShouldNotBe(first.RefreshToken);

        TokenResponse third = await flow.RefreshAsync(second.RefreshToken!);

        third.Succeeded.ShouldBeTrue();
        third.RefreshToken.ShouldNotBe(second.RefreshToken);
    }

    [Fact]
    public async Task Replaying_a_spent_refresh_token_kills_the_whole_family()
    {
        using var flow = new AuthFlow(fixture);
        TokenResponse issued = await SignInAsync(flow);

        string spent = issued.RefreshToken!;

        // A normal rotation. The client now holds `current` and has thrown `spent` away, exactly as it
        // should.
        TokenResponse rotated = await flow.RefreshAsync(spent);
        rotated.Succeeded.ShouldBeTrue();

        string current = rotated.RefreshToken!;

        // Somebody presents the token that was already exchanged. There is no way to tell from here whether
        // this is the thief or the victim, and it does not matter: one of the two holders is not supposed
        // to have it.
        TokenResponse replay = await flow.RefreshAsync(spent);

        replay.Succeeded.ShouldBeFalse();
        replay.Error.ShouldBe("invalid_grant");

        // The part that distinguishes reuse detection from plain rotation. The token that was still
        // perfectly valid a moment ago is dead too, because whoever is holding it cannot be trusted.
        TokenResponse afterwards = await flow.RefreshAsync(current);

        afterwards.Succeeded.ShouldBeFalse();
        afterwards.Error.ShouldBe("invalid_grant");

        await using AsyncServiceScope scope = fixture.Services.CreateAsyncScope();
        KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        RefreshTokenFamily family = await dbContext.RefreshTokenFamilies
            .AsNoTracking()
            .Where(candidate => candidate.RevocationReason == FamilyRevocationReason.TokenReuseDetected)
            .OrderByDescending(candidate => candidate.RevokedAtUtc)
            .FirstAsync();

        family.Status.ShouldBe(FamilyStatus.Revoked);
        family.RotationCount.ShouldBeGreaterThan(0);

        // An incident review starts from the audit trail, so the trail has to say what happened and to
        // which chain, not merely that something was refused.
        AuthEvent entry = await dbContext.AuthEvents
            .AsNoTracking()
            .Where(candidate => candidate.Type == AuthEventType.RefreshReuseDetected)
            .OrderByDescending(candidate => candidate.OccurredAtUtc)
            .FirstAsync();

        entry.Detail.ShouldContain(family.Id.ToString());
        entry.UserId.ShouldBe(family.UserId);
        entry.ClientId.ShouldBe(KeywardFixture.InteractiveClientId);
    }

    [Fact]
    public async Task A_new_sign_in_works_after_a_family_was_revoked()
    {
        using var flow = new AuthFlow(fixture);
        TokenResponse issued = await SignInAsync(flow);

        TokenResponse rotated = await flow.RefreshAsync(issued.RefreshToken!);
        await flow.RefreshAsync(issued.RefreshToken!);

        (await flow.RefreshAsync(rotated.RefreshToken!)).Succeeded.ShouldBeFalse();

        // Revoking a family also ends the grant it belonged to. Without that, the next sign-in would attach
        // to the same authorization, land on the same dead family, and the account would appear to sign in
        // successfully while never being able to refresh again.
        using var second = new AuthFlow(fixture);
        TokenResponse fresh = await SignInAsync(second);

        fresh.Succeeded.ShouldBeTrue();
        (await second.RefreshAsync(fresh.RefreshToken!)).Succeeded.ShouldBeTrue();
    }

    [Fact]
    public async Task A_revoked_family_refuses_the_grant_and_says_why()
    {
        using var flow = new AuthFlow(fixture);
        TokenResponse issued = await SignInAsync(flow);

        await using (AsyncServiceScope scope = fixture.Services.CreateAsyncScope())
        {
            KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            RefreshTokenFamilyService families =
                scope.ServiceProvider.GetRequiredService<RefreshTokenFamilyService>();

            Guid familyId = await dbContext.RefreshTokenFamilies
                .Where(candidate => candidate.Status == FamilyStatus.Active)
                .OrderByDescending(candidate => candidate.CreatedAtUtc)
                .Select(candidate => candidate.Id)
                .FirstAsync();

            // Through the service rather than by editing the row, because revoking a family is three things
            // and only one of them lives on the entity.
            (await families.RevokeByOperatorAsync(familyId, TestContext.Current.CancellationToken))
                .ShouldBeTrue();

            await dbContext.SaveChangesAsync();
        }

        TokenResponse refused = await flow.RefreshAsync(issued.RefreshToken!);

        refused.Succeeded.ShouldBeFalse();
        refused.Error.ShouldBe("invalid_grant");
    }

    [Fact]
    public async Task A_family_stops_working_once_it_passes_its_absolute_lifetime()
    {
        using var flow = new AuthFlow(fixture);
        TokenResponse issued = await SignInAsync(flow);

        await using (AsyncServiceScope scope = fixture.Services.CreateAsyncScope())
        {
            KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

            // Moving the expiry backwards is the only honest way to test a thirty-day rule in a test that
            // has to finish. It exercises the real comparison against the real clock.
            Guid familyId = await dbContext.RefreshTokenFamilies
                .Where(candidate => candidate.Status == FamilyStatus.Active)
                .OrderByDescending(candidate => candidate.CreatedAtUtc)
                .Select(candidate => candidate.Id)
                .FirstAsync();

            await dbContext.RefreshTokenFamilies
                .Where(candidate => candidate.Id == familyId)
                .ExecuteUpdateAsync(setters => setters.SetProperty(
                    candidate => candidate.AbsoluteExpiryUtc,
                    DateTimeOffset.UtcNow.AddMinutes(-1)));
        }

        TokenResponse refused = await flow.RefreshAsync(issued.RefreshToken!);

        refused.Succeeded.ShouldBeFalse();
        refused.Error.ShouldBe("invalid_grant");

        await using AsyncServiceScope check = fixture.Services.CreateAsyncScope();
        KeywardDbContext database = check.ServiceProvider.GetRequiredService<KeywardDbContext>();

        bool recorded = await database.RefreshTokenFamilies
            .AnyAsync(candidate =>
                candidate.RevocationReason == FamilyRevocationReason.AbsoluteLifetimeReached);

        recorded.ShouldBeTrue();
    }

    private static async Task<TokenResponse> SignInAsync(AuthFlow flow)
    {
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.UserEmail,
            KeywardFixture.UserPassword);

        code.ShouldNotBeNull();

        TokenResponse tokens = await flow.ExchangeCodeAsync(code, verifier);
        tokens.Succeeded.ShouldBeTrue();
        tokens.RefreshToken.ShouldNotBeNull();

        return tokens;
    }
}
