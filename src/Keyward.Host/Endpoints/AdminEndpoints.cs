using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;

namespace Keyward.Host.Endpoints;

/// <summary>
/// The endpoints an operator reaches for when something has gone wrong.
/// </summary>
/// <remarks>
/// <para>
/// These exist because the automatic reaction to a replayed token is correct but blunt: the chain dies and
/// whoever held it is signed out. When someone reports a stolen laptop, or a session that will not stop
/// working, an operator needs to see what is live for an account and end it without opening a database
/// client at three in the morning.
/// </para>
/// <para>
/// Every route sits behind a bearer token carrying the operator role, validated by the same pipeline as any
/// other API. An admin surface authenticated by cookie would be reachable from any page the operator
/// happened to have open in the same browser.
/// </para>
/// </remarks>
public static class AdminEndpoints
{
    /// <summary>The role a token must carry to reach any of these.</summary>
    public const string OperatorRole = "admin";

    private const int MaxPageSize = 200;

    /// <summary>Maps the operator endpoints.</summary>
    /// <param name="routes">Route builder.</param>
    public static IEndpointRouteBuilder MapAdminEndpoints(this IEndpointRouteBuilder routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        RouteGroupBuilder group = routes.MapGroup("/admin")
            .WithTags("Administration")
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser()
                .RequireRole(OperatorRole));

        group.MapGet("/users/{userId:guid}/sessions", ListSessionsAsync)
            .WithName("ListSessions");

        group.MapPost("/sessions/{familyId:guid}/revoke", RevokeSessionAsync)
            .WithName("RevokeSession");

        group.MapPost("/users/{userId:guid}/sessions/revoke", RevokeUserSessionsAsync)
            .WithName("RevokeUserSessions");

        group.MapGet("/audit", QueryAuditAsync)
            .WithName("QueryAudit");

        return routes;
    }

    /// <summary>Every refresh chain recorded for an account, live or dead.</summary>
    /// <remarks>
    /// Revoked chains are included rather than filtered out. The question being answered is usually "what
    /// happened to this account", and a chain that died three minutes ago because a token was replayed is
    /// the most interesting row on the page.
    /// </remarks>
    private static async Task<IResult> ListSessionsAsync(
        Guid userId,
        KeywardDbContext dbContext,
        CancellationToken cancellationToken)
    {
        List<SessionView> sessions = await dbContext.RefreshTokenFamilies
            .AsNoTracking()
            .Where(family => family.UserId == userId)
            .OrderByDescending(family => family.CreatedAtUtc)
            .Select(family => new SessionView(
                family.Id,
                family.ClientId,
                family.Status.ToString(),
                family.RevocationReason == FamilyRevocationReason.None
                    ? null
                    : family.RevocationReason.ToString(),
                family.RotationCount,
                family.CreatedAtUtc,
                family.LastRotatedAtUtc,
                family.AbsoluteExpiryUtc,
                family.RevokedAtUtc))
            .ToListAsync(cancellationToken);

        return Results.Ok(sessions);
    }

    /// <summary>Ends one chain.</summary>
    private static async Task<IResult> RevokeSessionAsync(
        Guid familyId,
        RefreshTokenFamilyService families,
        KeywardDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!await families.RevokeByOperatorAsync(familyId, cancellationToken))
        {
            return Results.NotFound();
        }

        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.NoContent();
    }

    /// <summary>Ends every live chain for an account, for the stolen-laptop case.</summary>
    private static async Task<IResult> RevokeUserSessionsAsync(
        Guid userId,
        RefreshTokenFamilyService families,
        AuditWriter audit,
        KeywardDbContext dbContext,
        CancellationToken cancellationToken)
    {
        int revoked = await families.RevokeAllForUserAsync(
            userId,
            FamilyRevocationReason.RevokedByOperator,
            cancellationToken);

        audit.Write(
            AuthEventType.FamilyRevokedByOperator,
            $"An operator revoked {revoked} active session(s).",
            userId);

        await dbContext.SaveChangesAsync(cancellationToken);

        return Results.Ok(new RevocationResult(revoked));
    }

    /// <summary>The authentication trail, newest first.</summary>
    /// <remarks>
    /// Paged by timestamp rather than by offset. An audit table only grows, and asking a database for
    /// <c>OFFSET 40000</c> makes it walk forty thousand rows in order to throw them away.
    /// </remarks>
    private static async Task<IResult> QueryAuditAsync(
        KeywardDbContext dbContext,
        CancellationToken cancellationToken,
        Guid? userId = null,
        AuthEventType? type = null,
        DateTimeOffset? before = null,
        int limit = 50)
    {
        IQueryable<AuthEvent> query = dbContext.AuthEvents.AsNoTracking();

        if (userId is { } account)
        {
            query = query.Where(entry => entry.UserId == account);
        }

        if (type is { } eventType)
        {
            query = query.Where(entry => entry.Type == eventType);
        }

        if (before is { } cursor)
        {
            query = query.Where(entry => entry.OccurredAtUtc < cursor);
        }

        List<AuditView> events = await query
            .OrderByDescending(entry => entry.OccurredAtUtc)
            .Take(Math.Clamp(limit, 1, MaxPageSize))
            .Select(entry => new AuditView(
                entry.Id,
                entry.Type.ToString(),
                entry.Detail,
                entry.UserId,
                entry.ClientId,
                entry.RemoteAddress,
                entry.TraceId,
                entry.OccurredAtUtc))
            .ToListAsync(cancellationToken);

        return Results.Ok(events);
    }

    /// <summary>How many chains a bulk revocation ended.</summary>
    /// <param name="Revoked">The count.</param>
    private sealed record RevocationResult(int Revoked);

    /// <summary>One refresh chain as an operator sees it.</summary>
    /// <param name="Id">The handle to revoke by.</param>
    /// <param name="ClientId">Which client started it.</param>
    /// <param name="Status">Active or revoked.</param>
    /// <param name="RevocationReason">Why it died, when it did.</param>
    /// <param name="RotationCount">How many times it has been exchanged.</param>
    /// <param name="CreatedAtUtc">When the grant happened.</param>
    /// <param name="LastRotatedAtUtc">Last sign of life.</param>
    /// <param name="AbsoluteExpiryUtc">When it dies regardless of activity.</param>
    /// <param name="RevokedAtUtc">When it was revoked, if it was.</param>
    private sealed record SessionView(
        Guid Id,
        string ClientId,
        string Status,
        string? RevocationReason,
        int RotationCount,
        DateTimeOffset CreatedAtUtc,
        DateTimeOffset LastRotatedAtUtc,
        DateTimeOffset AbsoluteExpiryUtc,
        DateTimeOffset? RevokedAtUtc);

    /// <summary>One entry from the authentication trail.</summary>
    /// <param name="Id">Entry id.</param>
    /// <param name="Type">What happened.</param>
    /// <param name="Detail">Short description.</param>
    /// <param name="UserId">Which account, if known.</param>
    /// <param name="ClientId">Which client, if known.</param>
    /// <param name="RemoteAddress">Where the request came from.</param>
    /// <param name="TraceId">Trace id, to line this up with the logs.</param>
    /// <param name="OccurredAtUtc">When.</param>
    private sealed record AuditView(
        Guid Id,
        string Type,
        string Detail,
        Guid? UserId,
        string? ClientId,
        string? RemoteAddress,
        string? TraceId,
        DateTimeOffset OccurredAtUtc);
}
