using System.Diagnostics;
using Keyward.Data;
using Keyward.Domain;

namespace Keyward.Host.Security;

/// <summary>
/// Writes the authentication trail.
/// </summary>
/// <remarks>
/// <para>
/// Every entry is staged on the caller's own unit of work and committed with whatever else that request
/// changed. An audit row saved in its own transaction can survive a business change that rolled back, or
/// be lost when one succeeded, and either way the trail stops matching what happened.
/// </para>
/// <para>
/// Nothing passed to <c>Detail</c> may contain a credential, a token, a one-time code or a backup code.
/// An audit trail that records secrets is a second, longer-lived copy of the thing it exists to protect,
/// and it is the copy nobody thinks to rotate.
/// </para>
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="accessor">Where the request came from.</param>
/// <param name="timeProvider">Clock.</param>
public sealed class AuditWriter(
    KeywardDbContext dbContext,
    IHttpContextAccessor accessor,
    TimeProvider timeProvider)
{
    /// <summary>Stages an audit entry. It lands when the caller saves.</summary>
    /// <param name="type">What happened.</param>
    /// <param name="detail">Short description, containing no secrets.</param>
    /// <param name="userId">Which account, if known.</param>
    /// <param name="clientId">Which client, if known.</param>
    public void Write(AuthEventType type, string detail, Guid? userId = null, string? clientId = null)
    {
        dbContext.AuthEvents.Add(AuthEvent.Record(
            type,
            detail,
            timeProvider.GetUtcNow(),
            userId,
            clientId,
            accessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
            Activity.Current?.Id ?? accessor.HttpContext?.TraceIdentifier));
    }

    /// <summary>Stages an entry and saves immediately, for paths that have nothing else to commit.</summary>
    /// <param name="type">What happened.</param>
    /// <param name="detail">Short description, containing no secrets.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <param name="userId">Which account, if known.</param>
    /// <param name="clientId">Which client, if known.</param>
    public async Task WriteAndSaveAsync(
        AuthEventType type,
        string detail,
        CancellationToken cancellationToken,
        Guid? userId = null,
        string? clientId = null)
    {
        Write(type, detail, userId, clientId);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}
