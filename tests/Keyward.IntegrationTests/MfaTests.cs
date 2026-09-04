using System.Net;
using System.Text.RegularExpressions;
using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Keyward.TestSupport;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Keyward.IntegrationTests;

/// <summary>
/// The second factor, and the evidence that it is enforced rather than merely offered.
/// </summary>
/// <remarks>
/// <para>
/// The account used here holds the operator role, which is what makes a second factor mandatory. That is
/// the policy worth having: a password alone is a nuisance to mandate for a low-value account and nowhere
/// near enough for someone who can change what other people are allowed to do.
/// </para>
/// <para>
/// Each test resets the enrolment it depends on rather than relying on the order the others ran in. A
/// suite that only passes in one sequence is a suite that will fail on the day somebody adds a test.
/// </para>
/// </remarks>
/// <param name="fixture">The running provider.</param>
[Collection(KeywardTestGroup.Name)]
public sealed class MfaTests(KeywardFixture fixture)
{
    private static readonly Regex AntiforgeryPattern = new(
        "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        TimeSpan.FromSeconds(2));

    [Fact]
    public async Task An_operator_account_is_sent_to_the_second_factor_before_any_token_is_issued()
    {
        await ResetAccountAsync(removeAuthenticator: false);

        using HttpClient client = fixture.CreateClient();
        await SignInWithPasswordAsync(client, KeywardFixture.AdminEmail, KeywardFixture.AdminPassword);

        (_, string challenge) = AuthFlow.CreatePkcePair();

        using HttpResponseMessage response = await client.GetAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge));

        // A password got as far as a session cookie and no further. The authorize endpoint refuses to turn
        // that session into a token until a second factor has been cleared in this session.
        response.StatusCode.ShouldBe(HttpStatusCode.Found);

        string location = response.Headers.Location!.ToString();
        location.ShouldSatisfyAllConditions(
            () => location.ShouldStartWith("/Account/"),
            () => location.ShouldNotStartWith(KeywardFixture.RedirectUri));
    }

    [Fact]
    public async Task Enrolling_lets_the_flow_finish_and_marks_the_token()
    {
        Enrolment enrolment = await EnrolAsync();

        enrolment.Secret.ShouldNotBeNullOrWhiteSpace();
        enrolment.BackupCodes.Count.ShouldBe(10);
        enrolment.Code.ShouldNotBeNull();

        TokenResponse tokens = await enrolment.Flow.ExchangeCodeAsync(enrolment.Code, enrolment.Verifier);

        tokens.Succeeded.ShouldBeTrue();

        // Downstream services get to know that a second factor was used, which is the point of carrying the
        // marker at all: an API can insist on it for a dangerous operation.
        JwtReader.ReadClaim(tokens.AccessToken!, ClaimDestinations.MfaCompletedClaim).ShouldBe("true");

        enrolment.Flow.Dispose();
    }

    [Fact]
    public async Task A_wrong_code_is_refused_and_the_right_one_is_not()
    {
        Enrolment enrolment = await EnrolAsync();
        enrolment.Flow.Dispose();

        using HttpClient client = fixture.CreateClient();
        await SignInWithPasswordAsync(client, KeywardFixture.AdminEmail, KeywardFixture.AdminPassword);

        (await SubmitCodeAsync(client, "111111")).Body.ShouldContain("not valid");

        (HttpStatusCode status, _) = await SubmitCodeAsync(
            client,
            TotpVerifier.Compute(enrolment.Secret, DateTimeOffset.UtcNow));

        status.ShouldBe(HttpStatusCode.Found);
    }

    [Fact]
    public async Task Repeated_wrong_codes_lock_the_step()
    {
        Enrolment enrolment = await EnrolAsync();
        enrolment.Flow.Dispose();

        using HttpClient client = fixture.CreateClient();
        await SignInWithPasswordAsync(client, KeywardFixture.AdminEmail, KeywardFixture.AdminPassword);

        string last = string.Empty;

        for (int attempt = 0; attempt < 6; attempt++)
        {
            last = (await SubmitCodeAsync(client, "222222")).Body;
        }

        // Five wrong guesses at a six-digit code is already generous. After that the step stops answering
        // at all, and the wait grows with every further attempt.
        last.ShouldContain("Too many attempts");

        // A correct code is refused too while the lock stands. Otherwise the lock protects nothing: an
        // attacker guessing codes simply keeps going until one lands.
        (await SubmitCodeAsync(client, TotpVerifier.Compute(enrolment.Secret, DateTimeOffset.UtcNow)))
            .Body.ShouldContain("Too many attempts");
    }

    [Fact]
    public async Task A_recovery_code_works_once_and_then_never_again()
    {
        Enrolment enrolment = await EnrolAsync();
        enrolment.Flow.Dispose();

        string recovery = enrolment.BackupCodes[0];

        using HttpClient first = fixture.CreateClient();
        await SignInWithPasswordAsync(first, KeywardFixture.AdminEmail, KeywardFixture.AdminPassword);

        (await SubmitCodeAsync(first, recovery)).Status.ShouldBe(HttpStatusCode.Found);

        using HttpClient second = fixture.CreateClient();
        await SignInWithPasswordAsync(second, KeywardFixture.AdminEmail, KeywardFixture.AdminPassword);

        // Spent means spent. A recovery code read off a photograph of a screen is worth nothing once it has
        // been used, which is the only thing that makes writing them down acceptable advice.
        (await SubmitCodeAsync(second, recovery)).Body.ShouldContain("not valid");
    }

    /// <summary>Puts the operator account back to having no authenticator and no lockout.</summary>
    /// <param name="removeAuthenticator">Whether to drop the enrolment as well as the lockout.</param>
    private async Task ResetAccountAsync(bool removeAuthenticator)
    {
        await using AsyncServiceScope scope = fixture.Services.CreateAsyncScope();
        KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        User account = await dbContext.Users.FirstAsync(user => user.Email == KeywardFixture.AdminEmail);

        account.ClearFailedMfaAttempts();
        await dbContext.SaveChangesAsync();

        if (!removeAuthenticator)
        {
            return;
        }

        await dbContext.MfaSecrets.Where(secret => secret.UserId == account.Id).ExecuteDeleteAsync();
        await dbContext.MfaBackupCodes.Where(code => code.UserId == account.Id).ExecuteDeleteAsync();
    }

    private async Task<Enrolment> EnrolAsync()
    {
        await ResetAccountAsync(removeAuthenticator: true);

        var flow = new AuthFlow(fixture);
        (string verifier, string challenge) = AuthFlow.CreatePkcePair();

        string? code = await flow.GetAuthorizationCodeAsync(
            AuthFlow.AuthorizeUrl(KeywardFixture.InteractiveClientId, challenge),
            KeywardFixture.AdminEmail,
            KeywardFixture.AdminPassword);

        flow.EnrolledSecret.ShouldNotBeNull();

        return new Enrolment(flow, flow.EnrolledSecret, flow.BackupCodes, code, verifier);
    }

    private static async Task SignInWithPasswordAsync(HttpClient client, string email, string password)
    {
        using HttpResponseMessage page = await client.GetAsync("/Account/Login");
        string html = await page.Content.ReadAsStringAsync();

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Input.Email"] = email,
            ["Input.Password"] = password,
            ["__RequestVerificationToken"] = AntiforgeryPattern.Match(html).Groups[1].Value,
        });

        using HttpResponseMessage response = await client.PostAsync("/Account/Login", content);

        response.StatusCode.ShouldBe(HttpStatusCode.Found);
    }

    private static async Task<(HttpStatusCode Status, string Body)> SubmitCodeAsync(
        HttpClient client,
        string code)
    {
        using HttpResponseMessage page = await client.GetAsync("/Account/Mfa");
        string html = await page.Content.ReadAsStringAsync();

        using var content = new FormUrlEncodedContent(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["Code"] = code,
            ["__RequestVerificationToken"] = AntiforgeryPattern.Match(html).Groups[1].Value,
        });

        using HttpResponseMessage response = await client.PostAsync("/Account/Mfa", content);

        return (response.StatusCode, await response.Content.ReadAsStringAsync());
    }

    private sealed record Enrolment(
        AuthFlow Flow,
        string Secret,
        IReadOnlyList<string> BackupCodes,
        string? Code,
        string Verifier);
}
