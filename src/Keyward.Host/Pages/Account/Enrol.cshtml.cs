using System.ComponentModel.DataAnnotations;
using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Keyward.Host.Pages.Account;

/// <summary>
/// Setting up an authenticator.
/// </summary>
/// <remarks>
/// <para>
/// The secret is generated on the GET and carried through the form encrypted, not held in a session. It is
/// only written to the database once the user has produced a working code from it, so closing the tab
/// halfway through leaves the account exactly as it was rather than locked out by a secret nobody has.
/// </para>
/// <para>
/// Carrying it through the form is safe because it is sealed with the Data Protection key ring: the browser
/// receives a value it cannot read or alter, and the server refuses anything it did not encrypt itself.
/// </para>
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="mfa">Enrolment and verification.</param>
/// <param name="audit">The authentication trail.</param>
[Authorize]
public sealed class EnrolModel(
    KeywardDbContext dbContext,
    MfaService mfa,
    AuditWriter audit) : PageModel
{
    /// <summary>The secret, encrypted, round-tripped through the form.</summary>
    [BindProperty]
    public string ProtectedSecret { get; set; } = string.Empty;

    /// <summary>The code the user read off their authenticator.</summary>
    [BindProperty]
    [Required]
    [Display(Name = "Code")]
    public string Code { get; set; } = string.Empty;

    /// <summary>Where to go once enrolment is complete.</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>The QR image, as a data URI.</summary>
    public string? QrCodeDataUri { get; private set; }

    /// <summary>The secret in text, for someone whose camera will not cooperate.</summary>
    public string? ManualEntryKey { get; private set; }

    /// <summary>The recovery codes, shown exactly once.</summary>
    public IReadOnlyList<string> BackupCodes { get; private set; } = [];

    /// <summary>Shown when the code did not verify.</summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>Produces a secret and shows it as a QR code.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IActionResult> OnGetAsync(CancellationToken cancellationToken)
    {
        if (SessionCookie.ReadUserId(User) is not { } userId)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        if (await mfa.IsEnrolledAsync(user.Id, cancellationToken))
        {
            // Already has an authenticator. Replacing it silently would be a way to take an account over
            // with nothing but a password.
            return RedirectToPage("Mfa", new { returnUrl = SafeReturnUrl() });
        }

        Present(mfa.BeginEnrolment(user.Email));

        return Page();
    }

    /// <summary>Confirms the code and records the enrolment.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (SessionCookie.ReadUserId(User) is not { } userId)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        IReadOnlyList<string>? codes =
            await mfa.CompleteEnrolmentAsync(user, ProtectedSecret, Code, cancellationToken);

        if (codes is null)
        {
            ErrorMessage = "That code is not valid. Check the clock on your phone and try again.";
            return Page();
        }

        await SessionCookie.IssueAsync(HttpContext, user, multiFactorCompleted: true);

        audit.Write(AuthEventType.MfaEnrolled, "An authenticator was enrolled.", user.Id);
        await dbContext.SaveChangesAsync(cancellationToken);

        BackupCodes = codes;

        return Page();
    }

    private void Present(MfaEnrolment enrolment)
    {
        ProtectedSecret = enrolment.ProtectedSecret;
        ManualEntryKey = enrolment.Secret;
        QrCodeDataUri = $"data:image/png;base64,{Convert.ToBase64String(enrolment.QrCodePng)}";
    }

    private string SafeReturnUrl() => Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/";
}
