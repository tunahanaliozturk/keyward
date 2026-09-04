namespace Keyward.Domain;

/// <summary>Whether an account may sign in at all.</summary>
public enum UserStatus
{
    /// <summary>Normal.</summary>
    Active = 0,

    /// <summary>Suspended by an administrator. Credentials are still correct; sign-in is refused anyway.</summary>
    Disabled = 1,
}

/// <summary>
/// Someone who can sign in.
/// </summary>
/// <remarks>
/// The password is never here in any form a reader could use. It arrives as a hash produced by the
/// framework's <c>PasswordHasher</c>, which is PBKDF2 with a versioned format and a constant-time
/// comparison. Hand-rolling that is one of the few places where writing it yourself is reliably the wrong
/// answer, and the failure modes are well enough documented that there is no excuse for meeting them again.
/// </remarks>
public sealed class User
{
    private readonly List<string> _roles = [];

    private User()
    {
        Email = null!;
        PasswordHash = null!;
    }

    /// <summary>Stable identifier. Becomes the <c>sub</c> claim.</summary>
    public Guid Id { get; private set; }

    /// <summary>Sign-in identifier, stored lower-cased so a lookup is an ordinary index seek.</summary>
    public string Email { get; private set; }

    /// <summary>PBKDF2 hash in the framework's versioned format. Never logged, never returned.</summary>
    public string PasswordHash { get; private set; }

    /// <summary>Which tenant this account belongs to. Becomes the <c>tenant_id</c> claim.</summary>
    public Guid TenantId { get; private set; }

    /// <summary>Roles, which decide both authorisation downstream and whether MFA is required here.</summary>
    public IReadOnlyList<string> Roles => _roles;

    /// <summary>Account state.</summary>
    public UserStatus Status { get; private set; }

    /// <summary>When the account was created.</summary>
    public DateTimeOffset CreatedAtUtc { get; private set; }

    /// <summary>
    /// Consecutive failed multi-factor attempts.
    /// </summary>
    /// <remarks>
    /// Counted separately from password failures on purpose. Someone who has proved the password and is
    /// failing the second factor is a different situation from someone guessing passwords, and conflating
    /// the two lets an attacker with a stolen password lock the real owner out by failing MFA.
    /// </remarks>
    public int FailedMfaAttempts { get; private set; }

    /// <summary>When the multi-factor step stops being refused. Null when it is not locked.</summary>
    public DateTimeOffset? MfaLockedUntilUtc { get; private set; }

    /// <summary>Registers an account.</summary>
    /// <param name="email">Sign-in identifier.</param>
    /// <param name="passwordHash">Already hashed. This type never sees a password.</param>
    /// <param name="tenantId">Owning tenant.</param>
    /// <param name="roles">Roles to grant.</param>
    /// <param name="now">Current time.</param>
    public static User Register(
        string email,
        string passwordHash,
        Guid tenantId,
        IEnumerable<string> roles,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);
        ArgumentNullException.ThrowIfNull(roles);

        var user = new User
        {
            Id = Guid.CreateVersion7(now),
            Email = email.Trim().ToLowerInvariant(),
            PasswordHash = passwordHash,
            TenantId = tenantId,
            Status = UserStatus.Active,
            CreatedAtUtc = now,
        };

        foreach (string role in roles)
        {
            if (!string.IsNullOrWhiteSpace(role))
            {
                user._roles.Add(role.Trim());
            }
        }

        return user;
    }

    /// <summary>True when the account may sign in.</summary>
    public bool CanSignIn => Status is UserStatus.Active;

    /// <summary>True when the multi-factor step is currently refusing attempts.</summary>
    /// <param name="now">Current time.</param>
    public bool IsMfaLocked(DateTimeOffset now) => MfaLockedUntilUtc is { } until && until > now;

    /// <summary>Replaces the password hash.</summary>
    /// <param name="passwordHash">Already hashed.</param>
    public void SetPasswordHash(string passwordHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(passwordHash);
        PasswordHash = passwordHash;
    }

    /// <summary>
    /// Records a failed multi-factor attempt and locks the step once there have been too many.
    /// </summary>
    /// <remarks>
    /// The lock grows with each further failure rather than being a fixed window, so an attacker who has
    /// the password and is guessing six digits runs out of time long before they run out of guesses. A
    /// six-digit code has a million values; a fixed one-minute lockout after five tries would still let
    /// someone work through a meaningful fraction of them in a day.
    /// </remarks>
    /// <param name="threshold">Attempts allowed before the step locks.</param>
    /// <param name="now">Current time.</param>
    public void RecordFailedMfaAttempt(int threshold, DateTimeOffset now)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 1);

        FailedMfaAttempts++;

        if (FailedMfaAttempts < threshold)
        {
            return;
        }

        int over = FailedMfaAttempts - threshold;
        double seconds = Math.Min(60d * Math.Pow(2, over), TimeSpan.FromHours(1).TotalSeconds);

        MfaLockedUntilUtc = now.AddSeconds(seconds);
    }

    /// <summary>Clears the failure count after a successful multi-factor step.</summary>
    public void ClearFailedMfaAttempts()
    {
        FailedMfaAttempts = 0;
        MfaLockedUntilUtc = null;
    }

    /// <summary>Suspends the account.</summary>
    public void Disable() => Status = UserStatus.Disabled;
}
