using Keyward.Data;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Keyward.Host.Security;

/// <summary>
/// Notices when a refresh token that was already exchanged is presented again, and kills its whole chain.
/// </summary>
/// <remarks>
/// <para>
/// OpenIddict already refuses a redeemed refresh token, and refusing it is not the interesting part. The
/// interesting part is what happens to the token the thief received in exchange, which is still perfectly
/// valid and is the one that matters. This handler records the replay and revokes everything descended
/// from the same grant.
/// </para>
/// <para>
/// It runs at the very front of the authentication pipeline rather than at the end, and that ordering is
/// the whole trick. OpenIddict stops dispatching handlers the moment one of them rejects the request, so a
/// handler placed after the redemption check would never be reached on exactly the requests it exists for.
/// Running first means looking the token up and reading its stored status, which is a better signal
/// anyway: a status of redeemed means one thing and will keep meaning it, whereas error text is written
/// for humans and changes between versions.
/// </para>
/// <para>
/// Nothing here rejects anything. The request is left to fail the way it always would, so the protocol
/// behaviour stays OpenIddict's and only the consequences are this service's own.
/// </para>
/// </remarks>
/// <param name="families">The chain tracker.</param>
/// <param name="tokenManager">OpenIddict's token store.</param>
/// <param name="dbContext">The database, saved once the revocation is staged.</param>
/// <param name="metrics">Where the reuse counter lives.</param>
/// <param name="logger">Logger.</param>
public sealed partial class RefreshTokenReuseDetector(
    RefreshTokenFamilyService families,
    IOpenIddictTokenManager tokenManager,
    KeywardDbContext dbContext,
    KeywardMetrics metrics,
    ILogger<RefreshTokenReuseDetector> logger)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    /// <summary>Registers the handler at the front of the authentication stack.</summary>
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor
            .CreateBuilder<OpenIddictServerEvents.ProcessAuthenticationContext>()
            .UseScopedHandler<RefreshTokenReuseDetector>()
            .SetOrder(int.MinValue + 100_000)
            .SetType(OpenIddictServerHandlerType.Custom)
            .Build();

    /// <inheritdoc />
    public async ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.Request?.IsRefreshTokenGrantType() is not true
            || string.IsNullOrWhiteSpace(context.Request.RefreshToken))
        {
            return;
        }

        // Refresh tokens are reference tokens, so what the client sent is a handle to a row rather than a
        // self-contained payload. That is what makes this lookup possible at all, and it is one of the
        // reasons they are configured that way.
        object? token = await tokenManager.FindByReferenceIdAsync(
            context.Request.RefreshToken,
            context.CancellationToken);

        if (token is null)
        {
            return;
        }

        string? status = await tokenManager.GetStatusAsync(token, context.CancellationToken);

        // Redeemed means this token was already traded in for another one. An honest client throws a
        // refresh token away the moment it exchanges it, so seeing one again means a copy exists somewhere
        // it should not, or the client is broken. There is no way to tell which from here, and the answer
        // to both is the same.
        if (!string.Equals(status, OpenIddictConstants.Statuses.Redeemed, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string? tokenId = await tokenManager.GetIdAsync(token, context.CancellationToken);
        string? authorizationId = await tokenManager.GetAuthorizationIdAsync(token, context.CancellationToken);

        LogReuse(logger, tokenId ?? "(unknown)", authorizationId ?? "(none)");
        metrics.RecordRefreshReuse(context.Request.ClientId);

        await families.HandleReuseAsync(authorizationId, context.CancellationToken);
        await dbContext.SaveChangesAsync(context.CancellationToken);
    }

    [LoggerMessage(
        EventId = 6000,
        Level = LogLevel.Warning,
        Message = "Refresh token {TokenId} was replayed after redemption. Revoking authorization {AuthorizationId}.")]
    private static partial void LogReuse(ILogger logger, string tokenId, string authorizationId);
}
