using System.Collections.Frozen;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Primitives;
using OpenIddict.Abstractions;

namespace Keyward.Host.Pages.Account;

/// <summary>
/// Asks the user whether a client may act on their behalf.
/// </summary>
/// <remarks>
/// <para>
/// The page does not decide anything. It re-posts the original authorize request, unchanged, with one extra
/// field saying the user agreed. That keeps every protocol rule in one place: OpenIddict validates the
/// request again on the way back in, so a parameter altered between the redirect and the form post is
/// caught by the same code that would have caught it the first time.
/// </para>
/// <para>
/// The form carries an antiforgery token, and the authorize endpoint refuses an approval without one. A
/// consent screen that accepts an unauthenticated cross-site post is a one-click account grant to whoever
/// registered the client.
/// </para>
/// </remarks>
/// <param name="applications">The client registry.</param>
[Authorize]
public sealed class ConsentModel(IOpenIddictApplicationManager applications) : PageModel
{
    private static readonly FrozenDictionary<string, string> Descriptions =
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OpenIddictConstants.Scopes.OpenId] = "Confirm who you are",
            [OpenIddictConstants.Scopes.Profile] = "Read your display name",
            [OpenIddictConstants.Scopes.Email] = "Read your email address",
            [OpenIddictConstants.Scopes.Roles] = "Read the roles you hold",
            [OpenIddictConstants.Scopes.OfflineAccess] = "Stay signed in when you are away",
        }.ToFrozenDictionary(StringComparer.Ordinal);

    /// <summary>The authorize request being approved, as a local path and query.</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>Name of the client asking.</summary>
    public string ClientName { get; private set; } = "An application";

    /// <summary>What it is asking for, in words.</summary>
    public IReadOnlyList<string> Permissions { get; private set; } = [];

    /// <summary>Every parameter of the original request, to be posted back untouched.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Parameters { get; private set; } = [];

    /// <summary>Reads the pending request and describes it.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        // The return address is the authorize request this page will re-post. Anything that is not a local
        // path is either a mistake or an attempt to have this page post credentials somewhere else.
        if (!Url.IsLocalUrl(ReturnUrl))
        {
            return RedirectToPage("/Index");
        }

        int separator = ReturnUrl!.IndexOf('?', StringComparison.Ordinal);

        if (separator < 0)
        {
            return RedirectToPage("/Index");
        }

        Dictionary<string, StringValues> query = QueryHelpers.ParseQuery(ReturnUrl[separator..]);

        Parameters = [.. query
            .SelectMany(entry => entry.Value.Select(value => KeyValuePair.Create(entry.Key, value ?? string.Empty)))];

        if (query.TryGetValue(OpenIddictConstants.Parameters.ClientId, out StringValues clientId)
            && await applications.FindByClientIdAsync(clientId.ToString(), cancellationToken) is { } application)
        {
            ClientName = await applications.GetDisplayNameAsync(application, cancellationToken)
                ?? clientId.ToString();
        }

        if (query.TryGetValue(OpenIddictConstants.Parameters.Scope, out StringValues scope))
        {
            Permissions = [.. scope
                .ToString()
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(value => Descriptions.TryGetValue(value, out string? text) ? text : $"Use the {value} scope")
                .Distinct(StringComparer.Ordinal)];
        }

        return Page();
    }
}
