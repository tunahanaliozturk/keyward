using System.Diagnostics;
using System.Security.Claims;
using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;

namespace Keyward.Host.Endpoints;

/// <summary>
/// The protocol endpoints.
/// </summary>
/// <remarks>
/// OpenIddict parses, validates and serialises; this decides who the user is, what may be put in a token,
/// and whether a refresh grant is still allowed. Splitting it that way is the whole reason for using a
/// mature library: the protocol mechanics are the part with a specification and a decade of security
/// review behind them, and the identity decisions are the part that is actually this service's own.
/// </remarks>
public static class ConnectEndpoints
{
    /// <summary>The claim carrying which tenant an account belongs to.</summary>
    public const string TenantClaim = ClaimDestinations.TenantClaim;

    /// <summary>Marks a session as having completed a second factor.</summary>
    public const string MfaCompletedClaim = ClaimDestinations.MfaCompletedClaim;

    /// <summary>Form field the consent page sends when the user approves.</summary>
    public const string ConsentAcceptField = "submit.accept";

    /// <summary>Form field the consent page sends when the user refuses.</summary>
    public const string ConsentDenyField = "submit.deny";

    /// <summary>Maps the protocol endpoints.</summary>
    /// <param name="routes">Route builder.</param>
    public static IEndpointRouteBuilder MapConnectEndpoints(this IEndpointRouteBuilder routes)
    {
        ArgumentNullException.ThrowIfNull(routes);

        routes.MapMethods("/connect/authorize", ["GET", "POST"], (Delegate)AuthorizeAsync)
            .WithName("Authorize")
            .WithTags("OpenID Connect");

        routes.MapPost("/connect/token", ExchangeAsync)
            .WithName("Token")
            .WithTags("OpenID Connect");

        routes.MapMethods("/connect/userinfo", ["GET", "POST"], (Delegate)UserInfoAsync)
            .WithName("UserInfo")
            .WithTags("OpenID Connect")
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser());

        routes.MapGet("/connect/logout", (Delegate)LogoutAsync)
            .WithName("Logout")
            .WithTags("OpenID Connect");

        return routes;
    }

    /// <summary>
    /// The interactive half: work out who the user is, then hand OpenIddict a principal.
    /// </summary>
    /// <remarks>
    /// Four gates, in order. Are you signed in, have you cleared the second factor if your roles demand
    /// one, is this client registered, and have you agreed to what it is asking for. The first two redirect
    /// rather than failing, because the user is sitting in a browser and there is a page that can fix it.
    /// </remarks>
    private static async Task<IResult> AuthorizeAsync(
        HttpContext context,
        KeywardDbContext dbContext,
        MfaService mfa,
        IAntiforgery antiforgery,
        IOpenIddictApplicationManager applications,
        IOpenIddictAuthorizationManager authorizations,
        IOpenIddictScopeManager scopes,
        CancellationToken cancellationToken)
    {
        OpenIddictRequest request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request could not be read.");

        AuthenticateResult session = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        if (!session.Succeeded || session.Principal?.Identity?.IsAuthenticated is not true)
        {
            return Challenge(context);
        }

        Guid userId = Guid.Parse(session.Principal.FindFirstValue(ClaimTypes.NameIdentifier)!);

        User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null || !user.CanSignIn)
        {
            // The cookie outlived the account it referred to, or the account was suspended while the
            // session was open. Signing the cookie out first stops the next request repeating the loop.
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Challenge(context);
        }

        // A second factor is a property of the session, not of the account. Someone who signed in before
        // being given an admin role has a cookie that never cleared MFA, and must clear it now.
        if (mfa.IsRequiredFor(user) && session.Principal.FindFirst(MfaCompletedClaim) is null)
        {
            return Results.Redirect(
                $"/Account/Mfa?returnUrl={Uri.EscapeDataString(context.Request.GetEncodedPathAndQuery())}");
        }

        object? application = await applications.FindByClientIdAsync(request.ClientId!, cancellationToken);

        if (application is null)
        {
            return Results.Forbid(
                properties: Failure(
                    OpenIddictConstants.Errors.InvalidClient,
                    "The client is not registered."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        string clientKey = (await applications.GetIdAsync(application, cancellationToken))!;
        string subject = user.Id.ToString();

        List<object> existing = await authorizations.FindAsync(
            subject: subject,
            client: clientKey,
            status: OpenIddictConstants.Statuses.Valid,
            type: OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes: request.GetScopes(),
            cancellationToken).ToListAsync(cancellationToken);

        ConsentDecision decision = ReadConsentDecision(context);

        if (decision is ConsentDecision.Denied)
        {
            return Results.Forbid(
                properties: Failure(
                    OpenIddictConstants.Errors.AccessDenied,
                    "The user refused the request."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
        }

        string? consentType = await applications.GetConsentTypeAsync(application, cancellationToken);

        // A first-party client the operator registered as implicit does not ask; anything else asks once,
        // and the answer is kept as a permanent authorization so it is not asked again.
        if (existing.Count == 0
            && decision is not ConsentDecision.Accepted
            && !string.Equals(consentType, OpenIddictConstants.ConsentTypes.Implicit, StringComparison.Ordinal))
        {
            return Results.Redirect(
                $"/Account/Consent?returnUrl={Uri.EscapeDataString(context.Request.GetEncodedPathAndQuery())}");
        }

        if (decision is ConsentDecision.Accepted)
        {
            // The consent form is a cross-site request forgery target: without this check, a page under an
            // attacker's control could silently approve their own registered client using the victim's
            // session cookie. OpenIddict does not check it, because the authorize endpoint is normally
            // reached by redirect rather than by form post.
            try
            {
                await antiforgery.ValidateRequestAsync(context);
            }
            catch (AntiforgeryValidationException)
            {
                return Results.BadRequest();
            }
        }

        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        identity.SetClaim(OpenIddictConstants.Claims.Subject, subject)
            .SetClaim(OpenIddictConstants.Claims.Email, user.Email)
            .SetClaim(OpenIddictConstants.Claims.Name, user.Email)
            .SetClaim(TenantClaim, user.TenantId.ToString())
            .SetClaims(OpenIddictConstants.Claims.Role, [.. user.Roles]);

        if (session.Principal.FindFirst(MfaCompletedClaim) is not null)
        {
            identity.SetClaim(MfaCompletedClaim, "true");
        }

        identity.SetScopes(request.GetScopes());
        identity.SetResources(await scopes
            .ListResourcesAsync(identity.GetScopes(), cancellationToken)
            .ToListAsync(cancellationToken));

        object authorization = existing.LastOrDefault()
            ?? await authorizations.CreateAsync(
                identity: identity,
                subject: subject,
                client: clientKey,
                type: OpenIddictConstants.AuthorizationTypes.Permanent,
                scopes: identity.GetScopes(),
                cancellationToken: cancellationToken);

        // The authorization id ties every token from this grant together, and is therefore what a
        // refresh-token family is keyed on. Without it there is nothing for a family to revoke by.
        identity.SetAuthorizationId(await authorizations.GetIdAsync(authorization, cancellationToken));
        identity.SetDestinations(GetDestinations);

        return Results.SignIn(
            new ClaimsPrincipal(identity),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>The token endpoint, covering all three grants this service supports.</summary>
    private static async Task<IResult> ExchangeAsync(
        HttpContext context,
        KeywardDbContext dbContext,
        RefreshTokenFamilyService families,
        AuditWriter audit,
        KeywardMetrics metrics,
        CancellationToken cancellationToken)
    {
        OpenIddictRequest request = context.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request could not be read.");

        string grantType = request.GrantType ?? "unknown";
        long started = Stopwatch.GetTimestamp();

        // One span per grant type rather than one for the endpoint. The three grants have almost nothing in
        // common operationally, and averaging a machine-to-machine token together with an interactive one
        // hides whichever of them is slower.
        using Activity? activity = KeywardMetrics.ActivitySource.StartActivity(
            $"connect.token.{grantType}",
            ActivityKind.Server);

        activity?.SetTag("keyward.client_id", request.ClientId);

        IResult result;
        string outcome;

        if (request.IsClientCredentialsGrantType())
        {
            result = await ClientCredentialsAsync(request, audit, cancellationToken);
            outcome = "issued";
        }
        else if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            (result, outcome) = await CodeOrRefreshAsync(
                context, request, dbContext, families, audit, cancellationToken);
        }
        else
        {
            result = Results.Forbid(
                properties: Failure(
                    OpenIddictConstants.Errors.UnsupportedGrantType,
                    "This grant type is not supported."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

            outcome = "unsupported_grant_type";
        }

        activity?.SetTag("keyward.outcome", outcome);
        metrics.RecordIssuance(grantType, outcome, Stopwatch.GetElapsedTime(started));

        return result;
    }

    /// <summary>
    /// Service-to-service tokens.
    /// </summary>
    /// <remarks>
    /// No refresh token is issued, and that is deliberate rather than an omission. A service holding its
    /// own credentials can always ask for another access token; giving it a refresh token would add a
    /// second long-lived secret to steal and buy nothing.
    /// </remarks>
    private static async Task<IResult> ClientCredentialsAsync(
        OpenIddictRequest request,
        AuditWriter audit,
        CancellationToken cancellationToken)
    {
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        identity.SetClaim(OpenIddictConstants.Claims.Subject, request.ClientId)
            .SetClaim(OpenIddictConstants.Claims.Name, request.ClientId);

        identity.SetScopes(request.GetScopes());
        identity.SetDestinations(GetDestinations);

        await audit.WriteAndSaveAsync(
            AuthEventType.TokensIssued,
            "Client credentials grant.",
            cancellationToken,
            clientId: request.ClientId);

        return Results.SignIn(
            new ClaimsPrincipal(identity),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    /// <summary>Exchanging an authorization code, or rotating a refresh token.</summary>
    private static async Task<(IResult Result, string Outcome)> CodeOrRefreshAsync(
        HttpContext context,
        OpenIddictRequest request,
        KeywardDbContext dbContext,
        RefreshTokenFamilyService families,
        AuditWriter audit,
        CancellationToken cancellationToken)
    {
        AuthenticateResult result =
            await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        if (!result.Succeeded || result.Principal is null)
        {
            // A rejection here has already been dealt with by the reuse detector if it was a replay.
            return (Results.Forbid(
                properties: Failure(
                    OpenIddictConstants.Errors.InvalidGrant,
                    "The token is no longer valid."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]),
                "rejected");
        }

        ClaimsPrincipal principal = result.Principal;
        string? authorizationId = principal.GetAuthorizationId();

        if (!Guid.TryParse(principal.GetClaim(OpenIddictConstants.Claims.Subject), out Guid userId))
        {
            return (Results.Forbid(
                properties: Failure(OpenIddictConstants.Errors.InvalidGrant, "The subject is not a known user."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]),
                "unknown_subject");
        }

        User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null || !user.CanSignIn)
        {
            // An account suspended after the token was issued. Access tokens are short-lived and validated
            // without calling here, so refusing to refresh is the point at which a suspension actually
            // takes effect.
            await families.RevokeAllForUserAsync(
                userId,
                FamilyRevocationReason.UserCredentialsChanged,
                cancellationToken);

            await dbContext.SaveChangesAsync(cancellationToken);

            return (Results.Forbid(
                properties: Failure(OpenIddictConstants.Errors.InvalidGrant, "The account can no longer sign in."),
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]),
                "account_disabled");
        }

        if (request.IsRefreshTokenGrantType())
        {
            (FamilyCheckResult check, RefreshTokenFamily? family) =
                await families.CheckAsync(authorizationId, cancellationToken);

            if (check is not FamilyCheckResult.Usable)
            {
                audit.Write(
                    AuthEventType.TokenRefreshed,
                    $"Refresh refused: {check}.",
                    user.Id,
                    request.ClientId);

                await dbContext.SaveChangesAsync(cancellationToken);

                return (Results.Forbid(
                    properties: Failure(
                        OpenIddictConstants.Errors.InvalidGrant,
                        check switch
                        {
                            FamilyCheckResult.Revoked =>
                                "This session was revoked. Sign in again.",
                            FamilyCheckResult.Expired =>
                                "This session reached its maximum lifetime. Sign in again.",
                            _ => "The token is no longer valid.",
                        }),
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]),
                    $"family_{check}".ToLowerInvariant());
            }

            families.RecordRotation(family!);
            audit.Write(AuthEventType.TokenRefreshed, "Refresh token rotated.", user.Id, request.ClientId);
        }
        else if (authorizationId is not null)
        {
            await families.StartAsync(authorizationId, user.Id, request.ClientId!, cancellationToken);
            audit.Write(AuthEventType.TokensIssued, "Authorization code exchanged.", user.Id, request.ClientId);
        }

        var identity = new ClaimsIdentity(
            principal.Claims,
            authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            nameType: OpenIddictConstants.Claims.Name,
            roleType: OpenIddictConstants.Claims.Role);

        // Re-read from the account rather than carried across from the old token, so a tenant move or a
        // role change takes effect at the next refresh instead of at the next sign-in.
        identity.SetClaim(TenantClaim, user.TenantId.ToString())
            .SetClaims(OpenIddictConstants.Claims.Role, [.. user.Roles]);

        identity.SetDestinations(GetDestinations);

        await dbContext.SaveChangesAsync(cancellationToken);

        return (Results.SignIn(
            new ClaimsPrincipal(identity),
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme),
            "issued");
    }

    private static Task<IResult> UserInfoAsync(ClaimsPrincipal principal) =>
        Task.FromResult<IResult>(Results.Ok(new Dictionary<string, object?>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Claims.Subject] = principal.GetClaim(OpenIddictConstants.Claims.Subject),
            [OpenIddictConstants.Claims.Email] = principal.GetClaim(OpenIddictConstants.Claims.Email),
            [TenantClaim] = principal.GetClaim(TenantClaim),
            [OpenIddictConstants.Claims.Role] = principal.GetClaims(OpenIddictConstants.Claims.Role).ToArray(),
        }));

    private static async Task<IResult> LogoutAsync(HttpContext context)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        return Results.SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static ConsentDecision ReadConsentDecision(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || !context.Request.HasFormContentType)
        {
            return ConsentDecision.None;
        }

        IFormCollection form = context.Request.Form;

        if (form.ContainsKey(ConsentDenyField))
        {
            return ConsentDecision.Denied;
        }

        return form.ContainsKey(ConsentAcceptField) ? ConsentDecision.Accepted : ConsentDecision.None;
    }

    private static IResult Challenge(HttpContext context) =>
        Results.Challenge(
            new AuthenticationProperties
            {
                RedirectUri = context.Request.GetEncodedPathAndQuery(),
            },
            [CookieAuthenticationDefaults.AuthenticationScheme]);

    private static AuthenticationProperties Failure(string error, string description) =>
        new(new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description,
        });

    private static IEnumerable<string> GetDestinations(Claim claim) => ClaimDestinations.For(claim);

    private enum ConsentDecision
    {
        None = 0,
        Accepted = 1,
        Denied = 2,
    }
}
