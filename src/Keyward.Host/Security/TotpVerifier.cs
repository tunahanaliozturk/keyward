using OtpNet;

namespace Keyward.Host.Security;

/// <summary>
/// The RFC 6238 check, on its own so it can be tested without a database.
/// </summary>
/// <remarks>
/// The arithmetic itself comes from Otp.NET. What lives here is the policy around it: how much clock drift
/// is forgiven, and how a code that a person typed is normalised before it is compared.
/// </remarks>
public static class TotpVerifier
{
    /// <summary>How long one code is valid for, before the tolerance window is applied.</summary>
    public static TimeSpan Step { get; } = TimeSpan.FromSeconds(30);

    /// <summary>Checks a code against a secret.</summary>
    /// <param name="base32Secret">The shared secret, base32 encoded.</param>
    /// <param name="code">What the user typed. Spaces and dashes are ignored.</param>
    /// <param name="now">Current time.</param>
    /// <param name="windowSteps">How many steps either side of now are forgiven.</param>
    public static bool Verify(string base32Secret, string? code, DateTimeOffset now, int windowSteps)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base32Secret);

        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        var totp = new Totp(Base32Encoding.ToBytes(base32Secret));

        return totp.VerifyTotp(
            now.UtcDateTime,
            Normalise(code),
            out _,
            new VerificationWindow(previous: windowSteps, future: windowSteps));
    }

    /// <summary>Produces the code that a correctly configured authenticator would be showing.</summary>
    /// <param name="base32Secret">The shared secret, base32 encoded.</param>
    /// <param name="at">The moment to compute for.</param>
    public static string Compute(string base32Secret, DateTimeOffset at)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base32Secret);

        return new Totp(Base32Encoding.ToBytes(base32Secret)).ComputeTotp(at.UtcDateTime);
    }

    private static string Normalise(string code) =>
        code.Trim()
            .Replace(" ", string.Empty, StringComparison.Ordinal)
            .Replace("-", string.Empty, StringComparison.Ordinal);
}
