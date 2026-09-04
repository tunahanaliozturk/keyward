using Keyward.Data;
using Keyward.Domain;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Keyward.Host.Security;

/// <summary>Why a refresh grant was refused.</summary>
public enum FamilyCheckResult
{
    /// <summary>The family is alive and may be rotated.</summary>
    Usable = 0,

    /// <summary>No family exists for this authorization. Nothing to trust.</summary>
    Unknown = 1,

    /// <summary>The family was revoked, most often because one of its tokens was replayed.</summary>
    Revoked = 2,

    /// <summary>The family reached its absolute lifetime. Activity does not extend it.</summary>
    Expired = 3,
}

/// <summary>
/// Tracks each chain of refresh tokens and kills the whole chain when one is replayed.
/// </summary>
/// <remarks>
/// <para>
/// Rotation alone does not protect a stolen refresh token. A thief who has one simply uses it, receives a
/// fresh one, and carries on; the theft shows up only when the legitimate client later presents the token
/// the thief already spent. At that instant two parties hold one chain, nothing distinguishes them, and
/// the only safe move is to kill everything descended from that grant.
/// </para>
/// <para>
/// Doing so logs out a session that was working. That is the intended behaviour, not a rough edge: the
/// alternative is leaving an attacker holding a valid token because signing someone out seemed
/// heavy-handed.
/// </para>
/// <para>
/// The chain is OpenIddict's authorization, which already ties every token from one grant together. This
/// service adds what the library does not keep: an absolute lifetime a sliding window cannot extend, a
/// reason the chain died, and a handle an operator can revoke by at three in the morning.
/// </para>
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="tokenManager">OpenIddict's token store, used to revoke the chain.</param>
/// <param name="authorizationManager">OpenIddict's authorization store, used to end the grant itself.</param>
/// <param name="audit">The authentication trail.</param>
/// <param name="options">Lifetimes.</param>
/// <param name="timeProvider">Clock.</param>
public sealed class RefreshTokenFamilyService(
    KeywardDbContext dbContext,
    IOpenIddictTokenManager tokenManager,
    IOpenIddictAuthorizationManager authorizationManager,
    AuditWriter audit,
    IOptions<TokenOptions> options,
    TimeProvider timeProvider)
{
    private readonly TokenOptions _options = options.Value;

    /// <summary>Starts a chain, or returns the one already recorded for this authorization.</summary>
    /// <param name="authorizationId">OpenIddict's authorization id.</param>
    /// <param name="userId">Whose session.</param>
    /// <param name="clientId">Which client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<RefreshTokenFamily> StartAsync(
        string authorizationId,
        Guid userId,
        string clientId,
        CancellationToken cancellationToken)
    {
        RefreshTokenFamily? existing = await dbContext.RefreshTokenFamilies
            .FirstOrDefaultAsync(family => family.AuthorizationId == authorizationId, cancellationToken);

        if (existing is not null)
        {
            return existing;
        }

        RefreshTokenFamily created = RefreshTokenFamily.Start(
            authorizationId,
            userId,
            clientId,
            _options.RefreshFamilyAbsoluteLifetime,
            timeProvider.GetUtcNow());

        dbContext.RefreshTokenFamilies.Add(created);
        return created;
    }

    /// <summary>Decides whether a refresh grant on this authorization may proceed.</summary>
    /// <param name="authorizationId">OpenIddict's authorization id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<(FamilyCheckResult Result, RefreshTokenFamily? Family)> CheckAsync(
        string? authorizationId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(authorizationId))
        {
            return (FamilyCheckResult.Unknown, null);
        }

        RefreshTokenFamily? family = await dbContext.RefreshTokenFamilies
            .FirstOrDefaultAsync(candidate => candidate.AuthorizationId == authorizationId, cancellationToken);

        if (family is null)
        {
            return (FamilyCheckResult.Unknown, null);
        }

        if (family.Status is FamilyStatus.Revoked)
        {
            return (FamilyCheckResult.Revoked, family);
        }

        DateTimeOffset now = timeProvider.GetUtcNow();

        if (now >= family.AbsoluteExpiryUtc)
        {
            // Revoked here rather than merely refused, so the tokens still sitting in OpenIddict's store
            // stop being usable too and the reason is recorded once.
            await RevokeAsync(family, FamilyRevocationReason.AbsoluteLifetimeReached, cancellationToken);
            return (FamilyCheckResult.Expired, family);
        }

        return (FamilyCheckResult.Usable, family);
    }

    /// <summary>Records that the chain rotated.</summary>
    /// <param name="family">The chain.</param>
    public void RecordRotation(RefreshTokenFamily family)
    {
        ArgumentNullException.ThrowIfNull(family);
        family.RecordRotation(timeProvider.GetUtcNow());
    }

    /// <summary>
    /// Handles a replayed refresh token by destroying everything descended from the same grant.
    /// </summary>
    /// <remarks>
    /// Called when a token that has already been exchanged is presented again. It revokes tokens issued
    /// <em>after</em> the replayed one as well, which is the entire point: whoever is still holding a
    /// working token is exactly who cannot be trusted to keep it.
    /// </remarks>
    /// <param name="authorizationId">OpenIddict's authorization id.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The chain that was revoked, if one was found.</returns>
    public async Task<RefreshTokenFamily?> HandleReuseAsync(
        string? authorizationId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(authorizationId))
        {
            return null;
        }

        RefreshTokenFamily? family = await dbContext.RefreshTokenFamilies
            .FirstOrDefaultAsync(candidate => candidate.AuthorizationId == authorizationId, cancellationToken);

        if (family is null)
        {
            return null;
        }

        await RevokeAsync(family, FamilyRevocationReason.TokenReuseDetected, cancellationToken);

        audit.Write(
            AuthEventType.RefreshReuseDetected,
            $"An already-redeemed refresh token was presented; family {family.Id} was revoked after "
            + $"{family.RotationCount} rotations.",
            family.UserId,
            family.ClientId);

        return family;
    }

    /// <summary>Revokes a chain by the handle an operator holds.</summary>
    /// <param name="familyId">The chain.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<bool> RevokeByOperatorAsync(Guid familyId, CancellationToken cancellationToken)
    {
        RefreshTokenFamily? family = await dbContext.RefreshTokenFamilies
            .FirstOrDefaultAsync(candidate => candidate.Id == familyId, cancellationToken);

        if (family is null)
        {
            return false;
        }

        await RevokeAsync(family, FamilyRevocationReason.RevokedByOperator, cancellationToken);

        audit.Write(
            AuthEventType.FamilyRevokedByOperator,
            $"Family {family.Id} was revoked by an operator.",
            family.UserId,
            family.ClientId);

        return true;
    }

    /// <summary>Revokes every chain belonging to an account.</summary>
    /// <param name="userId">The account.</param>
    /// <param name="reason">Why.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<int> RevokeAllForUserAsync(
        Guid userId,
        FamilyRevocationReason reason,
        CancellationToken cancellationToken)
    {
        List<RefreshTokenFamily> families = await dbContext.RefreshTokenFamilies
            .Where(family => family.UserId == userId && family.Status == FamilyStatus.Active)
            .ToListAsync(cancellationToken);

        foreach (RefreshTokenFamily family in families)
        {
            await RevokeAsync(family, reason, cancellationToken);
        }

        return families.Count;
    }

    /// <summary>
    /// Marks the chain dead and revokes the tokens themselves.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three things, and all three matter. Marking the row alone would leave OpenIddict's tokens valid for
    /// anyone reaching a code path that does not consult this service. Revoking the tokens alone would lose
    /// the reason the chain died.
    /// </para>
    /// <para>
    /// The third is the grant itself. Without revoking the authorization, the next sign-in finds the same
    /// still-valid grant, attaches to the same authorization id, and lands straight back on this dead
    /// family: the user signs in successfully and then cannot refresh, forever. Ending the grant means the
    /// next sign-in creates a new one and starts a clean chain.
    /// </para>
    /// </remarks>
    /// <param name="family">The chain.</param>
    /// <param name="reason">Why.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task RevokeAsync(
        RefreshTokenFamily family,
        FamilyRevocationReason reason,
        CancellationToken cancellationToken)
    {
        family.Revoke(reason, timeProvider.GetUtcNow());

        await foreach (object token in tokenManager
            .FindByAuthorizationIdAsync(family.AuthorizationId, cancellationToken))
        {
            await tokenManager.TryRevokeAsync(token, cancellationToken);
        }

        if (await authorizationManager.FindByIdAsync(family.AuthorizationId, cancellationToken) is { } grant)
        {
            await authorizationManager.TryRevokeAsync(grant, cancellationToken);
        }
    }
}
