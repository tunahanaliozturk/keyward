using Keyward.Host.Security;

namespace Keyward.UnitTests;

/// <summary>
/// The tolerance window around a one-time code.
/// </summary>
/// <remarks>
/// The window is the only knob on TOTP that trades security for usability, and both ends of the trade are
/// worth pinning down. Too narrow and a phone thirty seconds out of step locks its owner out; too wide and
/// the number of codes valid at any moment multiplies for no benefit. One step either way is the RFC 6238
/// recommendation and what these tests hold it to.
/// </remarks>
public sealed class TotpVerifierTests
{
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    private static readonly DateTimeOffset Now = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_current_code_is_accepted()
    {
        string code = TotpVerifier.Compute(Secret, Now);

        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeTrue();
    }

    [Fact]
    public void A_code_one_step_old_is_still_accepted()
    {
        string code = TotpVerifier.Compute(Secret, Now - TotpVerifier.Step);

        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeTrue();
    }

    [Fact]
    public void A_code_one_step_early_is_accepted()
    {
        string code = TotpVerifier.Compute(Secret, Now + TotpVerifier.Step);

        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeTrue();
    }

    [Fact]
    public void A_code_two_steps_out_is_refused()
    {
        string code = TotpVerifier.Compute(Secret, Now - (2 * TotpVerifier.Step));

        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeFalse();
    }

    [Fact]
    public void A_zero_width_window_accepts_only_the_current_step()
    {
        TotpVerifier.Verify(Secret, TotpVerifier.Compute(Secret, Now), Now, windowSteps: 0).ShouldBeTrue();

        TotpVerifier
            .Verify(Secret, TotpVerifier.Compute(Secret, Now - TotpVerifier.Step), Now, windowSteps: 0)
            .ShouldBeFalse();
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("000000")]
    [InlineData("not-a-code")]
    public void Rubbish_is_refused_without_throwing(string? code) =>
        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeFalse();

    [Fact]
    public void Spaces_and_dashes_a_user_typed_are_ignored()
    {
        string code = TotpVerifier.Compute(Secret, Now);
        string typed = $"{code[..3]} {code[3..]}";

        TotpVerifier.Verify(Secret, typed, Now, windowSteps: 1).ShouldBeTrue();
    }

    [Fact]
    public void A_code_from_a_different_secret_is_refused()
    {
        const string Other = "KRSXG5CTMVRXEZLUGFZDGNBZGE2TINJW";

        string code = TotpVerifier.Compute(Other, Now);

        TotpVerifier.Verify(Secret, code, Now, windowSteps: 1).ShouldBeFalse();
    }
}
