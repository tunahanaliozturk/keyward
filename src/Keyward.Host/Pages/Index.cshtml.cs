using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keyward.Host.Pages;

/// <summary>The landing page, which mostly exists so a redirect has somewhere to land.</summary>
public sealed class IndexModel : PageModel
{
    /// <summary>The signed-in account, if there is one.</summary>
    public string? SignedInAs { get; private set; }

    /// <summary>Reads the current session.</summary>
    public void OnGet() =>
        SignedInAs = User.Identity?.IsAuthenticated is true ? User.Identity.Name : null;
}
