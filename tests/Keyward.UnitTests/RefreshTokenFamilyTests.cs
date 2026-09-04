using Keyward.Domain;

namespace Keyward.UnitTests;

/// <summary>
/// The chain-of-custody rules for refresh tokens.
/// </summary>
/// <remarks>
/// These are the invariants the reuse-detection story rests on. If revocation is not idempotent, a second
/// replay rewrites the reason and an incident review loses the fact that the chain died of theft rather
/// than of old age. If the absolute expiry moves when the chain is used, a stolen token never expires.
/// </remarks>
public sealed class RefreshTokenFamilyTests
{
    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Start_records_an_absolute_expiry_from_the_lifetime()
    {
        RefreshTokenFamily family = Start(TimeSpan.FromDays(30));

        family.Status.ShouldBe(FamilyStatus.Active);
        family.RevocationReason.ShouldBe(FamilyRevocationReason.None);
        family.AbsoluteExpiryUtc.ShouldBe(Now.AddDays(30));
        family.RotationCount.ShouldBe(0);
    }

    [Fact]
    public void Rotation_does_not_extend_the_absolute_expiry()
    {
        RefreshTokenFamily family = Start(TimeSpan.FromDays(30));
        DateTimeOffset expiry = family.AbsoluteExpiryUtc;

        family.RecordRotation(Now.AddDays(10));
        family.RecordRotation(Now.AddDays(20));

        family.RotationCount.ShouldBe(2);
        family.LastRotatedAtUtc.ShouldBe(Now.AddDays(20));
        family.AbsoluteExpiryUtc.ShouldBe(expiry);
    }

    [Fact]
    public void A_family_stops_being_usable_at_its_absolute_expiry()
    {
        RefreshTokenFamily family = Start(TimeSpan.FromDays(30));

        family.IsUsable(Now.AddDays(29)).ShouldBeTrue();
        family.IsUsable(Now.AddDays(30)).ShouldBeFalse();
        family.IsUsable(Now.AddDays(31)).ShouldBeFalse();
    }

    [Fact]
    public void Revoking_records_the_reason_and_the_moment()
    {
        RefreshTokenFamily family = Start(TimeSpan.FromDays(30));

        family.Revoke(FamilyRevocationReason.TokenReuseDetected, Now.AddHours(1));

        family.Status.ShouldBe(FamilyStatus.Revoked);
        family.RevocationReason.ShouldBe(FamilyRevocationReason.TokenReuseDetected);
        family.RevokedAtUtc.ShouldBe(Now.AddHours(1));
        family.IsUsable(Now.AddHours(2)).ShouldBeFalse();
    }

    [Fact]
    public void Revoking_twice_keeps_the_first_reason()
    {
        RefreshTokenFamily family = Start(TimeSpan.FromDays(30));

        family.Revoke(FamilyRevocationReason.TokenReuseDetected, Now.AddHours(1));
        family.Revoke(FamilyRevocationReason.RevokedByOperator, Now.AddHours(2));

        // An operator cleaning up after an incident must not overwrite the record of why it happened.
        family.RevocationReason.ShouldBe(FamilyRevocationReason.TokenReuseDetected);
        family.RevokedAtUtc.ShouldBe(Now.AddHours(1));
    }

    private static RefreshTokenFamily Start(TimeSpan lifetime) => RefreshTokenFamily.Start(
        authorizationId: "auth-1",
        userId: Guid.CreateVersion7(Now),
        clientId: "keyward-demo-spa",
        absoluteLifetime: lifetime,
        now: Now);
}
