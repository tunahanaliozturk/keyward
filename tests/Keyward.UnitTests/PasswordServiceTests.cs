using System.Security.Cryptography;
using Keyward.Domain;
using Keyward.Host.Security;

namespace Keyward.UnitTests;

/// <summary>Password hashing, including the upgrade path most implementations forget.</summary>
public sealed class PasswordServiceTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private readonly PasswordService _passwords = new();

    [Fact]
    public void The_same_password_hashes_differently_every_time()
    {
        User user = Register();

        string first = _passwords.Hash(user, "correct horse battery staple");
        string second = _passwords.Hash(user, "correct horse battery staple");

        // Per-password salt. Identical hashes would mean two accounts sharing a password are visibly
        // identical in a stolen table.
        first.ShouldNotBe(second);
    }

    [Fact]
    public void A_correct_password_verifies()
    {
        User user = Register();
        user.SetPasswordHash(_passwords.Hash(user, "correct horse battery staple"));

        _passwords.Verify(user, "correct horse battery staple")
            .ShouldBe(PasswordService.VerificationOutcome.Succeeded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("wrong")]
    [InlineData("Correct Horse Battery Staple")]
    public void Anything_else_does_not(string attempt)
    {
        User user = Register();
        user.SetPasswordHash(_passwords.Hash(user, "correct horse battery staple"));

        _passwords.Verify(user, attempt).ShouldBe(PasswordService.VerificationOutcome.Failed);
    }

    [Fact]
    public void A_hash_in_an_older_format_verifies_but_asks_to_be_replaced()
    {
        User user = Register();
        user.SetPasswordHash(LegacyV2Hash("correct horse battery staple"));

        // The whole point of the rehash signal: the stored hash is still correct, so the user gets in, and
        // the caller is told to write a stronger one while it has the plain password in hand. Without this,
        // accounts stay on whatever iteration count was current the day they were created.
        _passwords.Verify(user, "correct horse battery staple")
            .ShouldBe(PasswordService.VerificationOutcome.SucceededNeedsRehash);
    }

    /// <summary>
    /// Builds a hash in version 2 of the ASP.NET Core format: PBKDF2 with HMAC-SHA1 and 1000 iterations.
    /// </summary>
    /// <remarks>
    /// Written out by hand rather than fetched from a fixture because the layout is the point. A leading
    /// zero byte marks the format, then a sixteen-byte salt, then a thirty-two byte subkey.
    /// </remarks>
    private static string LegacyV2Hash(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);

        byte[] subkey = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations: 1000,
            HashAlgorithmName.SHA1,
            outputLength: 32);

        byte[] stored = new byte[1 + salt.Length + subkey.Length];
        salt.CopyTo(stored, 1);
        subkey.CopyTo(stored, 1 + salt.Length);

        return Convert.ToBase64String(stored);
    }

    private static User Register() =>
        User.Register("someone@example.com", "placeholder", Guid.CreateVersion7(Now), ["user"], Now);
}
