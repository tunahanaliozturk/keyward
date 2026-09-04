using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keyward.TestSupport;

/// <summary>
/// Throwaway certificates for the tests.
/// </summary>
/// <remarks>
/// Generated per run rather than checked in. A private key in a repository is a private key on every fork
/// of it, and a test suite that quietly depends on one is how such a key ends up in production defaults.
/// </remarks>
public static class TestCertificates
{
    /// <summary>Creates a self-signed RSA certificate and returns it as a base64 PKCS#12 blob.</summary>
    /// <param name="subject">Common name, so a failure names the certificate that caused it.</param>
    public static string CreateBase64(string subject)
    {
        using var key = RSA.Create(2048);

        var request = new CertificateRequest(
            $"CN={subject}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        using X509Certificate2 certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        return Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));
    }
}
