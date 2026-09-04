using Keyward.Domain;
using Microsoft.AspNetCore.Identity;

namespace Keyward.Host.Security;

/// <summary>
/// Hashing and checking passwords.
/// </summary>
/// <remarks>
/// <para>
/// A thin wrapper over the framework's <see cref="PasswordHasher{TUser}"/>, and thin on purpose. That type
/// is PBKDF2 with a per-password salt, a versioned format that can be upgraded in place, and a
/// constant-time comparison. Every one of those is something a hand-written version gets wrong at least
/// once, and getting it wrong is silent.
/// </para>
/// <para>
/// The rehash path matters as much as the hash. When the framework raises its iteration count, an existing
/// user's stored hash is still in the old format; verification reports that, and the new hash is written
/// on the next successful sign-in. Without it, accounts stay on whatever was current the day they were
/// created, forever.
/// </para>
/// </remarks>
public sealed class PasswordService
{
    private readonly PasswordHasher<User> _hasher = new();

    /// <summary>What checking a password concluded.</summary>
    public enum VerificationOutcome
    {
        /// <summary>Wrong.</summary>
        Failed = 0,

        /// <summary>Correct.</summary>
        Succeeded = 1,

        /// <summary>Correct, but stored in an older format that should be replaced.</summary>
        SucceededNeedsRehash = 2,
    }

    /// <summary>Hashes a password for storage.</summary>
    /// <param name="user">The account it belongs to.</param>
    /// <param name="password">The plain password. Not retained.</param>
    public string Hash(User user, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        return _hasher.HashPassword(user, password);
    }

    /// <summary>Checks a password against a stored hash.</summary>
    /// <param name="user">The account, whose stored hash is compared against.</param>
    /// <param name="password">The supplied password.</param>
    public VerificationOutcome Verify(User user, string password)
    {
        ArgumentNullException.ThrowIfNull(user);

        if (string.IsNullOrEmpty(password))
        {
            return VerificationOutcome.Failed;
        }

        return _hasher.VerifyHashedPassword(user, user.PasswordHash, password) switch
        {
            PasswordVerificationResult.Success => VerificationOutcome.Succeeded,
            PasswordVerificationResult.SuccessRehashNeeded => VerificationOutcome.SucceededNeedsRehash,
            _ => VerificationOutcome.Failed,
        };
    }
}
