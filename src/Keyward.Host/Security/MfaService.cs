using System.Security.Cryptography;
using System.Text;
using Keyward.Data;
using Keyward.Domain;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OtpNet;
using QRCoder;

namespace Keyward.Host.Security;

/// <summary>What a second-factor check concluded.</summary>
public enum MfaOutcome
{
    /// <summary>The code was accepted.</summary>
    Verified = 0,

    /// <summary>The code was wrong.</summary>
    Rejected = 1,

    /// <summary>The step is locked after too many failures, and the code was not even checked.</summary>
    Locked = 2,

    /// <summary>A backup code was accepted and is now spent.</summary>
    BackupCodeAccepted = 3,

    /// <summary>The account has no authenticator enrolled.</summary>
    NotEnrolled = 4,
}

/// <summary>What a user needs to finish enrolling.</summary>
/// <param name="Secret">The base32 secret, for someone typing it in by hand.</param>
/// <param name="QrCodePng">A QR image of the provisioning URI.</param>
/// <param name="ProtectedSecret">The encrypted secret, to hold until a code proves enrolment worked.</param>
public sealed record MfaEnrolment(string Secret, byte[] QrCodePng, string ProtectedSecret);

/// <summary>
/// TOTP enrolment and verification, and the recovery codes for when the phone is gone.
/// </summary>
/// <remarks>
/// <para>
/// The arithmetic is RFC 6238 and comes from a library rather than from here. HMAC-based one-time
/// passwords are simple enough to look easy and specific enough to get subtly wrong, and a subtly wrong
/// implementation accepts codes it should not.
/// </para>
/// <para>
/// Enrolment is only recorded once the user has produced a working code. Storing the secret when the QR is
/// displayed would lock people out of their own accounts every time someone closed the tab.
/// </para>
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="protector">Encrypts secrets at rest.</param>
/// <param name="options">Policy.</param>
/// <param name="timeProvider">Clock.</param>
public sealed class MfaService(
    KeywardDbContext dbContext,
    IDataProtectionProvider protector,
    IOptions<MfaOptions> options,
    TimeProvider timeProvider)
{
    private const int SecretBytes = 20;
    private const int BackupCodeBytes = 10;

    private readonly IDataProtector _protector =
        protector.CreateProtector("Keyward.Mfa.TotpSecret.v1");

    private readonly MfaOptions _options = options.Value;

    /// <summary>Whether the account has an authenticator.</summary>
    /// <param name="userId">The account.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task<bool> IsEnrolledAsync(Guid userId, CancellationToken cancellationToken) =>
        dbContext.MfaSecrets.AnyAsync(secret => secret.UserId == userId, cancellationToken);

    /// <summary>Whether this account is obliged to use a second factor.</summary>
    /// <param name="user">The account.</param>
    public bool IsRequiredFor(User user)
    {
        ArgumentNullException.ThrowIfNull(user);

        return user.Roles.Any(role =>
            _options.RequiredForRoles.Contains(role, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>Produces a secret and a QR code, without recording anything yet.</summary>
    /// <param name="email">Shown in the authenticator so a user can tell accounts apart.</param>
    public MfaEnrolment BeginEnrolment(string email)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);

        byte[] secret = RandomNumberGenerator.GetBytes(SecretBytes);
        string base32 = Base32Encoding.ToString(secret);

        string uri = new OtpUri(OtpType.Totp, base32, email, _options.Issuer).ToString();

        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        using var png = new PngByteQRCode(data);

        return new MfaEnrolment(base32, png.GetGraphic(6), _protector.Protect(base32));
    }

    /// <summary>
    /// Records enrolment, but only if the user can already produce a valid code.
    /// </summary>
    /// <param name="user">The account.</param>
    /// <param name="protectedSecret">The encrypted secret from <see cref="BeginEnrolment"/>.</param>
    /// <param name="code">What the authenticator is showing.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The backup codes, shown once, or null if the code was wrong.</returns>
    public async Task<IReadOnlyList<string>?> CompleteEnrolmentAsync(
        User user,
        string protectedSecret,
        string code,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);

        string base32 = _protector.Unprotect(protectedSecret);

        if (!VerifyCode(base32, code))
        {
            return null;
        }

        dbContext.MfaSecrets.Add(MfaSecret.Enrol(user.Id, protectedSecret, timeProvider.GetUtcNow()));

        return await ReplaceBackupCodesAsync(user.Id, cancellationToken);
    }

    /// <summary>
    /// Checks a second factor, accepting either an authenticator code or an unspent backup code.
    /// </summary>
    /// <param name="user">The account.</param>
    /// <param name="code">What was typed.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<MfaOutcome> VerifyAsync(User user, string code, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(user);

        DateTimeOffset now = timeProvider.GetUtcNow();

        // Checked before anything else, so a locked step costs an attacker a database read and tells them
        // nothing about whether the code was right.
        if (user.IsMfaLocked(now))
        {
            return MfaOutcome.Locked;
        }

        MfaSecret? secret = await dbContext.MfaSecrets
            .FirstOrDefaultAsync(entry => entry.UserId == user.Id, cancellationToken);

        if (secret is null)
        {
            return MfaOutcome.NotEnrolled;
        }

        if (VerifyCode(_protector.Unprotect(secret.ProtectedSecret), code))
        {
            user.ClearFailedMfaAttempts();
            return MfaOutcome.Verified;
        }

        if (await TryConsumeBackupCodeAsync(user.Id, code, now, cancellationToken))
        {
            user.ClearFailedMfaAttempts();
            return MfaOutcome.BackupCodeAccepted;
        }

        user.RecordFailedMfaAttempt(_options.LockoutThreshold, now);

        return user.IsMfaLocked(now) ? MfaOutcome.Locked : MfaOutcome.Rejected;
    }

    /// <summary>Throws away every existing backup code and issues a fresh set.</summary>
    /// <param name="userId">The account.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IReadOnlyList<string>> ReplaceBackupCodesAsync(
        Guid userId,
        CancellationToken cancellationToken)
    {
        await dbContext.MfaBackupCodes
            .Where(existing => existing.UserId == userId)
            .ExecuteDeleteAsync(cancellationToken);

        DateTimeOffset now = timeProvider.GetUtcNow();
        List<string> issued = [];

        for (int index = 0; index < _options.BackupCodeCount; index++)
        {
            string code = FormatBackupCode(RandomNumberGenerator.GetBytes(BackupCodeBytes));
            issued.Add(code);
            dbContext.MfaBackupCodes.Add(MfaBackupCode.Issue(userId, HashBackupCode(code), now));
        }

        return issued;
    }

    private bool VerifyCode(string base32Secret, string code) =>
        TotpVerifier.Verify(
            base32Secret,
            code,
            timeProvider.GetUtcNow(),
            _options.VerificationWindowSteps);

    private async Task<bool> TryConsumeBackupCodeAsync(
        Guid userId,
        string code,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(code))
        {
            return false;
        }

        string hash = HashBackupCode(code);

        // Matched on the hash rather than by loading every code and comparing, so the query does the work
        // and no plaintext code is ever held next to the stored set.
        MfaBackupCode? match = await dbContext.MfaBackupCodes
            .FirstOrDefaultAsync(
                candidate => candidate.UserId == userId
                    && candidate.CodeHash == hash
                    && candidate.ConsumedAtUtc == null,
                cancellationToken);

        return match is not null && match.Consume(now);
    }

    /// <summary>
    /// Hashes a backup code.
    /// </summary>
    /// <remarks>
    /// A plain SHA-256 rather than a password hash, and that is a deliberate difference. A backup code is
    /// eighty bits of randomness this service generated, not something a person chose, so there is nothing
    /// for a dictionary to guess and no reason to pay a work factor on every attempt. Password hashing is
    /// slow because passwords are weak.
    /// </remarks>
    /// <param name="code">The code as typed.</param>
    private static string HashBackupCode(string code)
    {
        string normalised = code.Trim().Replace("-", string.Empty, StringComparison.Ordinal).ToUpperInvariant();

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(normalised)));
    }

    private static string FormatBackupCode(byte[] entropy)
    {
        // Crockford-ish base32 without the characters people misread, then grouped, because these get
        // written down on paper and typed back in months later.
        const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        var builder = new StringBuilder(BackupCodeBytes + 1);

        for (int index = 0; index < entropy.Length; index++)
        {
            if (index == entropy.Length / 2)
            {
                builder.Append('-');
            }

            builder.Append(Alphabet[entropy[index] % Alphabet.Length]);
        }

        return builder.ToString();
    }
}
