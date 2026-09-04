using Keyward.Domain;

namespace Keyward.UnitTests;

/// <summary>Recovery codes, and the audit entry that records what happened to them.</summary>
public sealed class MfaDomainTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void A_backup_code_can_be_spent_once()
    {
        MfaBackupCode code = MfaBackupCode.Issue(Guid.CreateVersion7(Now), "hash", Now);

        code.IsUsable.ShouldBeTrue();
        code.Consume(Now).ShouldBeTrue();

        code.IsUsable.ShouldBeFalse();
        code.ConsumedAtUtc.ShouldBe(Now);
    }

    [Fact]
    public void Spending_a_backup_code_twice_fails_and_keeps_the_first_timestamp()
    {
        MfaBackupCode code = MfaBackupCode.Issue(Guid.CreateVersion7(Now), "hash", Now);

        code.Consume(Now).ShouldBeTrue();
        code.Consume(Now.AddMinutes(5)).ShouldBeFalse();

        code.ConsumedAtUtc.ShouldBe(Now);
    }

    [Fact]
    public void An_audit_detail_is_truncated_rather_than_rejected()
    {
        // A long detail is a bug in a caller, not a reason to lose the entry. The event that something
        // happened matters more than the last few hundred characters describing it.
        AuthEvent entry = AuthEvent.Record(
            AuthEventType.RefreshReuseDetected,
            new string('x', 900),
            Now);

        entry.Detail.Length.ShouldBe(512);
        entry.Type.ShouldBe(AuthEventType.RefreshReuseDetected);
        entry.OccurredAtUtc.ShouldBe(Now);
    }

    [Fact]
    public void Enrolment_keeps_the_secret_encrypted_and_records_when_it_completed()
    {
        Guid userId = Guid.CreateVersion7(Now);

        MfaSecret secret = MfaSecret.Enrol(userId, "protected-blob", Now);

        secret.UserId.ShouldBe(userId);
        secret.ProtectedSecret.ShouldBe("protected-blob");
        secret.EnrolledAtUtc.ShouldBe(Now);
    }
}
