using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;

namespace Keyward.TestSupport;

/// <summary>
/// Reads the claims out of a JWT without verifying it.
/// </summary>
/// <remarks>
/// Deliberately unverified, and only ever used to assert what a token contains. Verification belongs to
/// the relying party, and the conformance suite exercises that path properly by fetching the key set and
/// checking the signature. A helper that both decodes and trusts would be an easy thing to reach for in
/// production code by mistake, so this one cannot: it does not verify anything.
/// </remarks>
public static class JwtReader
{
    /// <summary>Decodes the payload.</summary>
    /// <param name="token">A compact JWT.</param>
    public static JsonElement ReadPayload(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        string[] parts = token.Split('.');

        if (parts.Length < 2)
        {
            throw new FormatException("That is not a compact JWT.");
        }

        return JsonDocument.Parse(Base64UrlTextEncoder.Decode(parts[1])).RootElement.Clone();
    }

    /// <summary>Reads one string claim, or null when it is absent.</summary>
    /// <param name="token">A compact JWT.</param>
    /// <param name="claim">Claim name.</param>
    public static string? ReadClaim(string token, string claim) =>
        ReadPayload(token).TryGetProperty(claim, out JsonElement value)
            ? value.ValueKind is JsonValueKind.Array
                ? value.EnumerateArray().FirstOrDefault().GetString()
                : value.GetString()
            : null;

    /// <summary>Reads a claim that may appear more than once.</summary>
    /// <param name="token">A compact JWT.</param>
    /// <param name="claim">Claim name.</param>
    public static string[] ReadClaims(string token, string claim)
    {
        if (!ReadPayload(token).TryGetProperty(claim, out JsonElement value))
        {
            return [];
        }

        return value.ValueKind is JsonValueKind.Array
            ? [.. value.EnumerateArray().Select(entry => entry.GetString()!)]
            : [value.GetString()!];
    }
}
