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
/// The second-factor challenge.
/// </summary>
/// <remarks>
/// Accepts either a code from the authenticator or one of the recovery codes issued at enrolment. Both go
/// through the same lockout counter, because an attacker who can guess at one can guess at the other, and
/// a recovery code is worth more.
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="mfa">Second-factor checks.</param>
/// <param name="audit">The authentication trail.</param>
/// <param name="metrics">Challenge counters.</param>
[Authorize]
public sealed class MfaModel(
    KeywardDbContext dbContext,
    MfaService mfa,
    AuditWriter audit,
    KeywardMetrics metrics) : PageModel
{
    /// <summary>The code as typed.</summary>
    [BindProperty]
    [Required]
    [Display(Name = "Code")]
    public string Code { get; set; } = string.Empty;

    /// <summary>Where to go once the challenge is cleared.</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>Shown when the code was refused.</summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>Renders the challenge.</summary>
    public void OnGet()
    {
    }

    /// <summary>Checks the code.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        if (SessionCookie.ReadUserId(User) is not { } userId)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Id == userId, cancellationToken);

        if (user is null || !user.CanSignIn)
        {
            return RedirectToPage("Login", new { returnUrl = SafeReturnUrl() });
        }

        MfaOutcome outcome = await mfa.VerifyAsync(user, Code, cancellationToken);
        metrics.RecordMfaChallenge(outcome);

        switch (outcome)
        {
            case MfaOutcome.Verified:
            case MfaOutcome.BackupCodeAccepted:
                await SessionCookie.IssueAsync(HttpContext, user, multiFactorCompleted: true);

                audit.Write(
                    AuthEventType.MfaSucceeded,
                    outcome is MfaOutcome.BackupCodeAccepted
                        ? "A recovery code was accepted and is now spent."
                        : "Authenticator code accepted.",
                    user.Id);

                await dbContext.SaveChangesAsync(cancellationToken);

                return Redirect(SafeReturnUrl());

            case MfaOutcome.Locked:
                audit.Write(AuthEventType.MfaLocked, "The second-factor step is locked.", user.Id);
                await dbContext.SaveChangesAsync(cancellationToken);

                ErrorMessage = "Too many attempts. Wait a few minutes and try again.";
                return Page();

            case MfaOutcome.NotEnrolled:
                return RedirectToPage("Enrol", new { returnUrl = SafeReturnUrl() });

            default:
                audit.Write(AuthEventType.MfaFailed, "The code was rejected.", user.Id);
                await dbContext.SaveChangesAsync(cancellationToken);

                ErrorMessage = "That code is not valid.";
                return Page();
        }
    }

    private string SafeReturnUrl() => Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/";
}
