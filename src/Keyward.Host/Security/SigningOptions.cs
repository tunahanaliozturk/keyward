using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography.X509Certificates;

namespace Keyward.Host.Security;

/// <summary>One certificate, by file or inline.</summary>
/// <remarks>
/// A path suits a container with a mounted secret; the inline form suits a platform that only hands
/// configuration over as environment variables. Both carry a private key, so both are secrets.
/// </remarks>
public sealed class CertificateReference
{
    /// <summary>Path to a PKCS#12 file.</summary>
    public string? Path { get; init; }

    /// <summary>The same file, base64 encoded, for hosts that only offer string configuration.</summary>
    public string? Base64 { get; init; }

    /// <summary>Password protecting the private key, if there is one.</summary>
    public string? Password { get; init; }

    /// <summary>Reads the certificate.</summary>
    /// <exception cref="InvalidOperationException">Neither a path nor inline content was given.</exception>
    public X509Certificate2 Load()
    {
        if (!string.IsNullOrWhiteSpace(Base64))
        {
            return X509CertificateLoader.LoadPkcs12(
                Convert.FromBase64String(Base64),
                Password,
                X509KeyStorageFlags.EphemeralKeySet);
        }

        if (!string.IsNullOrWhiteSpace(Path))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                Path,
                Password,
                X509KeyStorageFlags.EphemeralKeySet);
        }

        throw new InvalidOperationException(
            "A certificate reference needs either a Path or a Base64 value.");
    }
}

/// <summary>
/// The keys tokens are signed and encrypted with.
/// </summary>
/// <remarks>
/// <para>
/// Order is the whole design. The first signing certificate is the one used to sign; every certificate in
/// the list is published to the JWKS document. Rotating therefore means prepending the new certificate and
/// leaving the old one in place for a grace window, so a token signed a second before the rotation is
/// still verifiable by a relying party that has not refreshed its key cache yet. Removing the old key at
/// the same moment the new one appears is how a rotation turns into an outage.
/// </para>
/// <para>
/// The grace window has to outlast two things: the longest access-token lifetime, and whatever interval
/// relying parties re-fetch JWKS on. Twenty-four hours covers both comfortably for a five-minute token.
/// </para>
/// <para>
/// When nothing is configured, ephemeral development keys are generated instead. Those are regenerated on
/// every start, which means every restart invalidates every token, which is exactly why the service refuses
/// to fall back to them outside development.
/// </para>
/// </remarks>
public sealed class SigningOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Keyward:Signing";

    /// <summary>Signing certificates, newest first. The first one signs; the rest stay verifiable.</summary>
    [MaxLength(8)]
    public IReadOnlyList<CertificateReference> SigningCertificates { get; init; } = [];

    /// <summary>Certificates used to encrypt tokens the service issues to itself.</summary>
    [MaxLength(8)]
    public IReadOnlyList<CertificateReference> EncryptionCertificates { get; init; } = [];

    /// <summary>True when real keys were supplied and the development fallback is not needed.</summary>
    public bool HasCertificates => SigningCertificates.Count > 0 && EncryptionCertificates.Count > 0;
}
