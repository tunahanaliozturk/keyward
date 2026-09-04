using System.Security.Claims;
using Keyward.Domain;
using Keyward.Host.Endpoints;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Keyward.Host.Pages.Account;

/// <summary>
/// Issues the browser session for the provider itself.
/// </summary>
/// <remarks>
/// This cookie is not an access token and grants nothing on its own. It says the browser proved a password,
/// and optionally a second factor, so the authorize endpoint has something to work from. Every issuance
/// rewrites the cookie from scratch rather than adding a claim to the existing one, because a claim added
/// to a principal that is already signed in is easy to add and easy to forget to remove.
/// </remarks>
public static class SessionCookie
{
    /// <summary>Signs the browser in.</summary>
    /// <param name="context">The request.</param>
    /// <param name="user">Who signed in.</param>
    /// <param name="multiFactorCompleted">Whether a second factor was cleared during this sign-in.</param>
    public static Task IssueAsync(HttpContext context, User user, bool multiFactorCompleted)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(user);

        var identity = new ClaimsIdentity(
            CookieAuthenticationDefaults.AuthenticationScheme,
            ClaimTypes.Name,
            ClaimTypes.Role);

        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Email));

        foreach (string role in user.Roles)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }

        if (multiFactorCompleted)
        {
            identity.AddClaim(new Claim(ConnectEndpoints.MfaCompletedClaim, "true"));
        }

        return context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity));
    }

    /// <summary>Reads the signed-in account id, or null when there is no session.</summary>
    /// <param name="user">The principal on the request.</param>
    public static Guid? ReadUserId(ClaimsPrincipal? user)
    {
        string? value = user?.FindFirstValue(ClaimTypes.NameIdentifier);

        return Guid.TryParse(value, out Guid id) ? id : null;
    }
}
