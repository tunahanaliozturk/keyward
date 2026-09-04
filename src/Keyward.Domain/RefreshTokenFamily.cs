namespace Keyward.Domain;

/// <summary>Whether a family's tokens are still worth anything.</summary>
public enum FamilyStatus
{
    /// <summary>The newest token in the family can still be exchanged.</summary>
    Active = 0,

    /// <summary>Every token in the family is dead, including ones issued after the one that caused it.</summary>
    Revoked = 1,
}

/// <summary>Why a family stopped being usable.</summary>
public enum FamilyRevocationReason
{
    /// <summary>Not revoked.</summary>
    None = 0,

    /// <summary>
    /// A refresh token that had already been exchanged was presented again.
    /// </summary>
    /// <remarks>
    /// The only situation the whole mechanism exists for. A correctly behaving client never does this: it
    /// throws away a refresh token the moment it trades it in. So a replay means either a copy of the
    /// token is somewhere it should not be, or the client is broken, and there is no way to tell which
    /// from here. Revoking everything is the answer to both.
    /// </remarks>
    TokenReuseDetected = 1,

    /// <summary>The family outlived its absolute lifetime, regardless of how recently it was used.</summary>
    AbsoluteLifetimeReached = 2,

    /// <summary>Someone revoked it deliberately.</summary>
    RevokedByOperator = 3,

    /// <summary>The account was suspended or its password changed.</summary>
    UserCredentialsChanged = 4,
}

/// <summary>
/// One chain of refresh tokens, from a single sign-in through every rotation that followed.
/// </summary>
/// <remarks>
/// <para>
/// Rotation on its own does not protect a stolen refresh token: the thief simply uses it, gets a fresh one,
/// and carries on. What catches them is that the legitimate client eventually presents the token the thief
/// already spent. At that moment there are two holders of one chain, there is no way to tell which is
/// which, and the only safe move is to kill the whole chain and make both sign in again.
/// </para>
/// <para>
/// Revoking a family therefore takes a working session down as collateral. That is not a flaw in the
/// design, it is the design: the alternative is leaving an attacker with a valid token because logging
/// someone out felt rude.
/// </para>
/// <para>
/// The grouping is OpenIddict's authorization, which already ties every token from one grant together.
/// This row adds what OpenIddict does not keep: an absolute lifetime that a sliding window cannot extend,
/// a rotation count, why the family died, and a handle an operator can revoke by.
/// </para>
/// </remarks>
public sealed class RefreshTokenFamily
{
    private RefreshTokenFamily()
    {
        AuthorizationId = null!;
        ClientId = null!;
    }

    /// <summary>Identifier an operator can revoke by.</summary>
    public Guid Id { get; private set; }

    /// <summary>OpenIddict's authorization id. Every token in the chain carries it.</summary>
    public string AuthorizationId { get; private set; }

    /// <summary>Whose session this is.</summary>
    public Guid UserId { get; private set; }

    /// <summary>Which client the session belongs to.</summary>
    public string ClientId { get; private set; }

    /// <summary>Current state.</summary>
    public FamilyStatus Status { get; private set; }

    /// <summary>Why it was revoked.</summary>
    public FamilyRevocationReason RevocationReason { get; private set; }

    /// <summary>When it was revoked.</summary>
    public DateTimeOffset? RevokedAtUtc { get; private set; }

    /// <summary>When the original sign-in happened.</summary>
    public DateTimeOffset CreatedAtUtc { get; private set; }

    /// <summary>When the family was last exchanged for a new token.</summary>
    public DateTimeOffset LastRotatedAtUtc { get; private set; }

    /// <summary>
    /// The hard stop.
    /// </summary>
    /// <remarks>
    /// A sliding window alone means a session that is used daily never ends, so a token stolen from an
    /// active user is good indefinitely. This bound is not extended by activity: at some point the user
    /// signs in again, whoever they are.
    /// </remarks>
    public DateTimeOffset AbsoluteExpiryUtc { get; private set; }

    /// <summary>How many times the family has been rotated.</summary>
    public int RotationCount { get; private set; }

    /// <summary>Starts a family at sign-in.</summary>
    /// <param name="authorizationId">OpenIddict's authorization id.</param>
    /// <param name="userId">Whose session.</param>
    /// <param name="clientId">Which client.</param>
    /// <param name="absoluteLifetime">How long the family may live, however active it is.</param>
    /// <param name="now">Current time.</param>
    public static RefreshTokenFamily Start(
        string authorizationId,
        Guid userId,
        string clientId,
        TimeSpan absoluteLifetime,
        DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authorizationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(absoluteLifetime, TimeSpan.Zero);

        return new RefreshTokenFamily
        {
            Id = Guid.CreateVersion7(now),
            AuthorizationId = authorizationId,
            UserId = userId,
            ClientId = clientId,
            Status = FamilyStatus.Active,
            RevocationReason = FamilyRevocationReason.None,
            CreatedAtUtc = now,
            LastRotatedAtUtc = now,
            AbsoluteExpiryUtc = now + absoluteLifetime,
        };
    }

    /// <summary>True when the family may still be exchanged.</summary>
    /// <param name="now">Current time.</param>
    public bool IsUsable(DateTimeOffset now) =>
        Status is FamilyStatus.Active && now < AbsoluteExpiryUtc;

    /// <summary>Records a rotation.</summary>
    /// <param name="now">Current time.</param>
    public void RecordRotation(DateTimeOffset now)
    {
        RotationCount++;
        LastRotatedAtUtc = now;
    }

    /// <summary>
    /// Kills the family.
    /// </summary>
    /// <remarks>
    /// Deliberately idempotent, and deliberately keeps the first reason rather than the latest. If a reuse
    /// revoked a family and an operator then revokes it again, the interesting fact is still that a token
    /// was replayed.
    /// </remarks>
    /// <param name="reason">Why.</param>
    /// <param name="now">Current time.</param>
    /// <returns>True if this call is what revoked it.</returns>
    public bool Revoke(FamilyRevocationReason reason, DateTimeOffset now)
    {
        if (Status is FamilyStatus.Revoked)
        {
            return false;
        }

        Status = FamilyStatus.Revoked;
        RevocationReason = reason;
        RevokedAtUtc = now;
        return true;
    }
}
