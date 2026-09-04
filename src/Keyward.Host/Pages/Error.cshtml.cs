using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Keyward.Host.Pages;

/// <summary>
/// The failure page.
/// </summary>
/// <remarks>
/// It shows a trace id and nothing else. An exception message on a sign-in page tells whoever triggered it
/// which library threw, which is a free reconnaissance report; the trace id lets support find the same
/// request in the logs, where the detail belongs.
/// </remarks>
[ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
public sealed class ErrorModel : PageModel
{
    /// <summary>The identifier to quote when reporting the failure.</summary>
    public string? TraceId { get; private set; }

    /// <summary>Captures the trace id.</summary>
    public void OnGet() => TraceId = Activity.Current?.Id ?? HttpContext.TraceIdentifier;
}
