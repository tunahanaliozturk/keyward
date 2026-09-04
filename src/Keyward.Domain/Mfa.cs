namespace Keyward.Domain;

/// <summary>
/// A user's TOTP secret, encrypted at rest.
/// </summary>
/// <remarks>
/// The secret is a bearer credential: anyone holding it can generate valid codes forever, which makes it
/// worth as much as the password. It is encrypted with Data Protection rather than hashed, because
/// verification has to reproduce the code rather than compare a digest, and it is shown exactly once, at
/// enrolment. There is no path in this service that displays it again.
/// </remarks>
public sealed class MfaSecret
{
    private MfaSecret() => ProtectedSecret = null!;

    /// <summary>Which account.</summary>
    public Guid UserId { get; private set; }

    /// <summary>The base32 TOTP secret, encrypted.</summary>
    public string ProtectedSecret { get; private set; }

    /// <summary>When enrolment completed. Enrolment is only complete once a code has been verified.</summary>
    public DateTimeOffset EnrolledAtUtc { get; private set; }

    /// <summary>Records a completed enrolment.</summary>
    /// <param name="userId">Which account.</param>
    /// <param name="protectedSecret">The secret, already encrypted.</param>
    /// <param name="now">Current time.</param>
    public static MfaSecret Enrol(Guid userId, string protectedSecret, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedSecret);

        return new MfaSecret
        {
            UserId = userId,
            ProtectedSecret = protectedSecret,
            EnrolledAtUtc = now,
        };
    }
}

/// <summary>
/// One single-use code for getting in when the authenticator is gone.
/// </summary>
/// <remarks>
/// Stored as a hash, because a backup code is a credential and a table of them in plaintext is a table of
/// passwords. Each is usable once: consuming one marks it, so a code read off a screenshot that has already
/// been used is worth nothing.
/// </remarks>
public sealed class MfaBackupCode
{
    private MfaBackupCode() => CodeHash = null!;

    /// <summary>Identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>Which account.</summary>
    public Guid UserId { get; private set; }

    /// <summary>Hash of the code. The code itself is shown once and never stored.</summary>
    public string CodeHash { get; private set; }

    /// <summary>When it was issued.</summary>
    public DateTimeOffset CreatedAtUtc { get; private set; }

    /// <summary>When it was spent. Null while it is still usable.</summary>
    public DateTimeOffset? ConsumedAtUtc { get; private set; }

    /// <summary>True while the code can still be redeemed.</summary>
    public bool IsUsable => ConsumedAtUtc is null;

    /// <summary>Issues a code.</summary>
    /// <param name="userId">Which account.</param>
    /// <param name="codeHash">Hash of the code.</param>
    /// <param name="now">Current time.</param>
    public static MfaBackupCode Issue(Guid userId, string codeHash, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(codeHash);

        return new MfaBackupCode
        {
            Id = Guid.CreateVersion7(now),
            UserId = userId,
            CodeHash = codeHash,
            CreatedAtUtc = now,
        };
    }

    /// <summary>Spends the code. Returns false if it was already spent.</summary>
    /// <param name="now">Current time.</param>
    public bool Consume(DateTimeOffset now)
    {
        if (ConsumedAtUtc is not null)
        {
            return false;
        }

        ConsumedAtUtc = now;
        return true;
    }
}
