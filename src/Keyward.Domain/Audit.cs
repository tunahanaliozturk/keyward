namespace Keyward.Domain;

/// <summary>Things worth being able to reconstruct after an incident.</summary>
public enum AuthEventType
{
    /// <summary>Credentials accepted.</summary>
    LoginSucceeded = 0,

    /// <summary>Credentials rejected.</summary>
    LoginFailed = 1,

    /// <summary>A second factor was accepted.</summary>
    MfaSucceeded = 2,

    /// <summary>A second factor was rejected.</summary>
    MfaFailed = 3,

    /// <summary>The second factor was refused without being checked, because the step is locked.</summary>
    MfaLocked = 4,

    /// <summary>A backup code was spent.</summary>
    BackupCodeUsed = 5,

    /// <summary>A user enrolled an authenticator.</summary>
    MfaEnrolled = 6,

    /// <summary>Tokens were issued.</summary>
    TokensIssued = 7,

    /// <summary>A refresh token was exchanged for a new one.</summary>
    TokenRefreshed = 8,

    /// <summary>A token was revoked through the revocation endpoint.</summary>
    TokenRevoked = 9,

    /// <summary>
    /// An already-redeemed refresh token was presented, and the whole family was revoked because of it.
    /// </summary>
    /// <remarks>
    /// The one event here that always means something went wrong somewhere else. A correctly behaving
    /// client never replays a redeemed token, so this is either a stolen token or a client bug, and both
    /// are worth waking someone for.
    /// </remarks>
    RefreshReuseDetected = 10,

    /// <summary>An operator revoked a family by hand.</summary>
    FamilyRevokedByOperator = 11,

    /// <summary>A consent screen was answered.</summary>
    ConsentGranted = 12,
}

/// <summary>
/// One line in the authentication trail.
/// </summary>
/// <remarks>
/// Append-only and never pruned. Everything else in this database is operational state with a retention
/// policy; this is the record of who got in and who did not, and the question it answers is always asked
/// about a date in the past.
/// </remarks>
public sealed class AuthEvent
{
    private AuthEvent()
    {
        Detail = null!;
    }

    /// <summary>Identifier.</summary>
    public Guid Id { get; private set; }

    /// <summary>What happened.</summary>
    public AuthEventType Type { get; private set; }

    /// <summary>Which account, when one was identified.</summary>
    public Guid? UserId { get; private set; }

    /// <summary>Which OAuth client, when the event came through one.</summary>
    public string? ClientId { get; private set; }

    /// <summary>
    /// A short description.
    /// </summary>
    /// <remarks>
    /// Never contains a credential, a token value, a TOTP code or a backup code. An audit trail that
    /// records secrets is a second copy of the thing it exists to protect.
    /// </remarks>
    public string Detail { get; private set; }

    /// <summary>Where the request came from, for correlating a burst of failures.</summary>
    public string? RemoteAddress { get; private set; }

    /// <summary>Ties the entry to a trace.</summary>
    public string? TraceId { get; private set; }

    /// <summary>When it happened.</summary>
    public DateTimeOffset OccurredAtUtc { get; private set; }

    /// <summary>Records an event.</summary>
    /// <param name="type">What happened.</param>
    /// <param name="detail">Short description, containing no secrets.</param>
    /// <param name="now">Current time.</param>
    /// <param name="userId">Which account, if known.</param>
    /// <param name="clientId">Which client, if known.</param>
    /// <param name="remoteAddress">Caller address, if known.</param>
    /// <param name="traceId">Correlation id, if known.</param>
    public static AuthEvent Record(
        AuthEventType type,
        string detail,
        DateTimeOffset now,
        Guid? userId = null,
        string? clientId = null,
        string? remoteAddress = null,
        string? traceId = null) =>
        new()
        {
            Id = Guid.CreateVersion7(now),
            Type = type,
            Detail = detail is { Length: > 512 } ? detail[..512] : detail,
            UserId = userId,
            ClientId = clientId,
            RemoteAddress = remoteAddress,
            TraceId = traceId,
            OccurredAtUtc = now,
        };
}
