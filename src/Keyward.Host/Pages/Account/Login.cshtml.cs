using System.ComponentModel.DataAnnotations;
using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace Keyward.Host.Pages.Account;

/// <summary>
/// The password step.
/// </summary>
/// <remarks>
/// <para>
/// A failed sign-in says the same thing whichever half was wrong. Telling somebody that the address exists
/// but the password does not turns a credential-stuffing list into a verified account list, and the extra
/// helpfulness buys a legitimate user nothing they cannot work out themselves.
/// </para>
/// <para>
/// A password is checked even when no such account exists, against a throwaway hash. Skipping the check
/// would make the miss measurably faster than a wrong password, which is the same disclosure again with
/// a stopwatch instead of a message.
/// </para>
/// </remarks>
/// <param name="dbContext">The database.</param>
/// <param name="passwords">Password hashing.</param>
/// <param name="mfa">Second-factor policy.</param>
/// <param name="audit">The authentication trail.</param>
public sealed class LoginModel(
    KeywardDbContext dbContext,
    PasswordService passwords,
    MfaService mfa,
    AuditWriter audit) : PageModel
{
    private static readonly Domain.User Decoy = Domain.User.Register(
        "decoy@keyward.invalid",
        "AQAAAAIAAYagAAAAEEnVLbLb3xUMEjS2bTB0S1sq0lPQeXtDzKBKAmLPXAmzXcqRvfKfr0nZBrHmY6RLLA==",
        Guid.Empty,
        [],
        DateTimeOffset.UnixEpoch);

    /// <summary>What the form collected.</summary>
    [BindProperty]
    public InputModel Input { get; set; } = new();

    /// <summary>Where to go once the sign-in is complete.</summary>
    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    /// <summary>Shown when the attempt failed.</summary>
    public string? ErrorMessage { get; private set; }

    /// <summary>Renders the form.</summary>
    public void OnGet()
    {
    }

    /// <summary>Checks the credentials.</summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        string email = Input.Email.Trim().ToLowerInvariant();

        Domain.User? user = await dbContext.Users
            .FirstOrDefaultAsync(candidate => candidate.Email == email, cancellationToken);

        PasswordService.VerificationOutcome outcome = user is null
            ? Verify(Decoy)
            : Verify(user);

        if (user is null || outcome is PasswordService.VerificationOutcome.Failed || !user.CanSignIn)
        {
            await audit.WriteAndSaveAsync(
                AuthEventType.LoginFailed,
                $"Failed password attempt for '{email}'.",
                cancellationToken,
                user?.Id);

            ErrorMessage = "That email address and password do not match an account.";
            return Page();
        }

        if (outcome is PasswordService.VerificationOutcome.SucceededNeedsRehash)
        {
            // The stored hash predates the current iteration count. This is the only moment the plain
            // password is available to upgrade it, so it happens here or it never happens.
            user.SetPasswordHash(passwords.Hash(user, Input.Password));
        }

        // The cookie is issued before the second factor, and carries no proof of one. It is enough to reach
        // the enrolment and challenge pages and nothing else: the authorize endpoint refuses to issue a
        // token to a session that has not cleared MFA, and the admin API is behind a bearer token.
        await SessionCookie.IssueAsync(HttpContext, user, multiFactorCompleted: false);

        audit.Write(AuthEventType.LoginSucceeded, "Password accepted.", user.Id);
        await dbContext.SaveChangesAsync(cancellationToken);

        bool enrolled = await mfa.IsEnrolledAsync(user.Id, cancellationToken);

        if (mfa.IsRequiredFor(user) && !enrolled)
        {
            return RedirectToPage("Enrol", new { returnUrl = SafeReturnUrl() });
        }

        // Anyone who has enrolled is challenged, whether their roles demand it or not. Turning a second
        // factor on and then not being asked for it is the kind of surprise that ends in a support ticket.
        return enrolled
            ? RedirectToPage("Mfa", new { returnUrl = SafeReturnUrl() })
            : Redirect(SafeReturnUrl());
    }

    private PasswordService.VerificationOutcome Verify(Domain.User account) =>
        passwords.Verify(account, Input.Password);

    /// <summary>
    /// Keeps the redirect inside this site.
    /// </summary>
    /// <remarks>
    /// The return address arrives in the query string, which means an attacker controls it. Without this
    /// check the sign-in page becomes an open redirect that starts on a domain the user trusts.
    /// </remarks>
    private string SafeReturnUrl() =>
        Url.IsLocalUrl(ReturnUrl) ? ReturnUrl! : "/";

    /// <summary>The sign-in form.</summary>
    public sealed class InputModel
    {
        /// <summary>Sign-in address.</summary>
        [Required]
        [EmailAddress]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        /// <summary>Password.</summary>
        [Required]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;
    }
}
