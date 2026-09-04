using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Keyward.Host.Security;

/// <summary>
/// The instruments this service publishes.
/// </summary>
/// <remarks>
/// <para>
/// Three of these are ordinary operational telemetry. One of them is not: <c>keyward.refresh_reuse.total</c>
/// should read zero forever. Any nonzero rate means a refresh token was presented twice, and the only
/// explanations are a stolen token or a broken client. It belongs on the dashboard next to error rate and
/// in an alert rule, not in a debugging log nobody reads.
/// </para>
/// <para>
/// Registered as a singleton so the instruments are created once. A meter built per request produces a new
/// instrument each time and quietly drops the measurements.
/// </para>
/// </remarks>
public sealed class KeywardMetrics : IDisposable
{
    /// <summary>The meter name to subscribe to.</summary>
    public const string MeterName = "Keyward";

    /// <summary>The activity source name for spans this service starts itself.</summary>
    public const string ActivitySourceName = "Keyward";

    private readonly Meter _meter;
    private readonly Histogram<double> _issuance;
    private readonly Counter<long> _reuse;
    private readonly Counter<long> _mfa;

    /// <summary>Creates the meter and its instruments.</summary>
    /// <param name="factory">Meter factory, so the meter is disposed with the container.</param>
    public KeywardMetrics(IMeterFactory factory)
    {
        ArgumentNullException.ThrowIfNull(factory);

        _meter = factory.Create(MeterName);

        _issuance = _meter.CreateHistogram<double>(
            "keyward.token_issuance.duration",
            unit: "s",
            description: "How long a token request took, by grant type and outcome.");

        _reuse = _meter.CreateCounter<long>(
            "keyward.refresh_reuse.total",
            description: "Refresh tokens presented after they had already been exchanged.");

        _mfa = _meter.CreateCounter<long>(
            "keyward.mfa_challenge.total",
            description: "Second-factor challenges, by outcome.");
    }

    /// <summary>The source spans are started from.</summary>
    public static ActivitySource ActivitySource { get; } = new(ActivitySourceName);

    /// <summary>Records how long a token request took.</summary>
    /// <param name="grantType">Which grant.</param>
    /// <param name="outcome">Issued, or why not.</param>
    /// <param name="elapsed">Duration.</param>
    public void RecordIssuance(string grantType, string outcome, TimeSpan elapsed) =>
        _issuance.Record(
            elapsed.TotalSeconds,
            new KeyValuePair<string, object?>("grant_type", grantType),
            new KeyValuePair<string, object?>("outcome", outcome));

    /// <summary>Records that a replayed refresh token was caught.</summary>
    /// <param name="clientId">Which client presented it.</param>
    public void RecordRefreshReuse(string? clientId) =>
        _reuse.Add(1, new KeyValuePair<string, object?>("client_id", clientId ?? "unknown"));

    /// <summary>Records the result of a second-factor challenge.</summary>
    /// <param name="outcome">What the check concluded.</param>
    public void RecordMfaChallenge(MfaOutcome outcome) =>
        _mfa.Add(1, new KeyValuePair<string, object?>("outcome", outcome.ToString()));

    /// <inheritdoc />
    public void Dispose() => _meter.Dispose();
}
