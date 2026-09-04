using Keyward.Domain;

namespace Keyward.UnitTests;

/// <summary>
/// Account state, and the lockout arithmetic that stands between a leaked password and an account.
/// </summary>
/// <remarks>
/// A six-digit code has a million values. A fixed lockout window lets an attacker who already has the
/// password work steadily through a meaningful fraction of them, so the wait grows with each failure past
/// the threshold. These tests pin that growth down, because a backoff that quietly stops growing looks
/// exactly like one that works.
/// </remarks>
public sealed class UserTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Register_normalises_the_email_address()
    {
        User user = Register("  Someone@Example.COM ");

        user.Email.ShouldBe("someone@example.com");
        user.Status.ShouldBe(UserStatus.Active);
        user.CanSignIn.ShouldBeTrue();
    }

    [Fact]
    public void A_disabled_account_cannot_sign_in()
    {
        User user = Register();

        user.Disable();

        user.CanSignIn.ShouldBeFalse();
    }

    [Fact]
    public void Failures_below_the_threshold_do_not_lock()
    {
        User user = Register();

        for (int attempt = 0; attempt < 4; attempt++)
        {
            user.RecordFailedMfaAttempt(threshold: 5, Now);
        }

        user.FailedMfaAttempts.ShouldBe(4);
        user.IsMfaLocked(Now).ShouldBeFalse();
    }

    [Fact]
    public void The_wait_grows_with_every_failure_past_the_threshold()
    {
        User user = Register();

        for (int attempt = 0; attempt < 5; attempt++)
        {
            user.RecordFailedMfaAttempt(threshold: 5, Now);
        }

        user.IsMfaLocked(Now).ShouldBeTrue();
        DateTimeOffset first = user.MfaLockedUntilUtc!.Value;

        user.RecordFailedMfaAttempt(threshold: 5, Now);
        DateTimeOffset second = user.MfaLockedUntilUtc!.Value;

        second.ShouldBeGreaterThan(first);
    }

    [Fact]
    public void The_wait_is_capped_so_an_account_is_never_locked_out_forever()
    {
        User user = Register();

        for (int attempt = 0; attempt < 40; attempt++)
        {
            user.RecordFailedMfaAttempt(threshold: 5, Now);
        }

        (user.MfaLockedUntilUtc!.Value - Now).ShouldBeLessThanOrEqualTo(TimeSpan.FromHours(1));
    }

    [Fact]
    public void A_successful_check_clears_the_counter_and_the_lock()
    {
        User user = Register();

        for (int attempt = 0; attempt < 6; attempt++)
        {
            user.RecordFailedMfaAttempt(threshold: 5, Now);
        }

        user.ClearFailedMfaAttempts();

        user.FailedMfaAttempts.ShouldBe(0);
        user.MfaLockedUntilUtc.ShouldBeNull();
        user.IsMfaLocked(Now).ShouldBeFalse();
    }

    private static User Register(string email = "someone@example.com") =>
        User.Register(email, "hash", Guid.CreateVersion7(Now), ["user"], Now);
}
