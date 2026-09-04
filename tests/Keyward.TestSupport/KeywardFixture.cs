using Keyward.Host;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Testcontainers.PostgreSql;
using Xunit;

namespace Keyward.TestSupport;

/// <summary>
/// A real instance of the provider, against a real Postgres, listening on a real socket.
/// </summary>
/// <remarks>
/// <para>
/// Not a test server and not an in-memory store. Half of what this service does happens inside
/// OpenIddict's Entity Framework stores, and an in-memory provider does not enforce the unique constraints
/// or the transaction semantics those stores depend on. A test suite that swaps them out is testing a
/// different program.
/// </para>
/// <para>
/// The host listens on a loopback port so the same fixture works for an ordinary <see cref="HttpClient"/>
/// and for a browser driving the interactive flow.
/// </para>
/// </remarks>
public sealed class KeywardFixture : IAsyncLifetime
{
    /// <summary>Sign-in address of the seeded account with no special roles.</summary>
    public const string UserEmail = "user@keyward.local";

    /// <summary>Password for <see cref="UserEmail"/>.</summary>
    public const string UserPassword = "ChangeMe!User1";

    /// <summary>Sign-in address of the seeded account holding the operator role.</summary>
    public const string AdminEmail = "admin@keyward.local";

    /// <summary>Password for <see cref="AdminEmail"/>.</summary>
    public const string AdminPassword = "ChangeMe!Admin1";

    /// <summary>Where the demo interactive client is registered to receive the code.</summary>
    public const string RedirectUri = "http://localhost:5199/callback";

    /// <summary>The demo public client.</summary>
    public const string InteractiveClientId = "keyward-demo-spa";

    /// <summary>The demo confidential client.</summary>
    public const string ServiceClientId = "keyward-demo-service";

    /// <summary>Secret for <see cref="ServiceClientId"/>.</summary>
    public const string ServiceClientSecret = "ChangeMe!Service-Secret";

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:18-alpine")
        .WithDatabase("keyward")
        .WithUsername("keyward")
        .WithPassword("keyward")
        .Build();

    private WebApplication? _app;

    /// <summary>Where the provider is listening.</summary>
    public Uri BaseAddress { get; private set; } = new("http://localhost");

    /// <summary>The running application's services, for tests that need to look at the database.</summary>
    public IServiceProvider Services =>
        _app?.Services ?? throw new InvalidOperationException("The host has not been started.");

    /// <summary>The signing certificate currently in use, base64 encoded.</summary>
    public string CurrentSigningCertificate { get; } = TestCertificates.CreateBase64("keyward-signing-current");

    /// <summary>The certificate the previous one rotated out of, still published for verification.</summary>
    public string PreviousSigningCertificate { get; } = TestCertificates.CreateBase64("keyward-signing-previous");

    /// <summary>Starts Postgres and the provider.</summary>
    public async ValueTask InitializeAsync()
    {
        await _postgres.StartAsync();

        _app = KeywardHost.Build([], builder =>
        {
            builder.Environment.EnvironmentName = "Testing";
            builder.WebHost.UseUrls("http://127.0.0.1:0");
            builder.Logging.ClearProviders();

            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>(StringComparer.Ordinal)
            {
                ["ConnectionStrings:keyward"] = _postgres.GetConnectionString(),
                ["Keyward:AllowInsecureTransport"] = "true",
                ["Keyward:Database:MigrateOnStartup"] = "true",
                ["Keyward:Seed:Enabled"] = "true",
                ["Keyward:Seed:DemoClientRedirectUris:0"] = RedirectUri,

                // Two signing certificates, which is the shape a rotation leaves behind: the new key signs,
                // the old one stays in JWKS so tokens issued a moment earlier still verify.
                ["Keyward:Signing:SigningCertificates:0:Base64"] = CurrentSigningCertificate,
                ["Keyward:Signing:SigningCertificates:1:Base64"] = PreviousSigningCertificate,
                ["Keyward:Signing:EncryptionCertificates:0:Base64"] =
                    TestCertificates.CreateBase64("keyward-encryption"),
            });
        });

        await _app.StartAsync();

        string address = _app.Services
            .GetRequiredService<IServer>()
            .Features
            .Get<IServerAddressesFeature>()!
            .Addresses
            .First();

        BaseAddress = new Uri(address);
    }

    /// <summary>Stops everything.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_app is not null)
        {
            await _app.StopAsync();
            await _app.DisposeAsync();
        }

        await _postgres.DisposeAsync();
    }

    /// <summary>
    /// A client that keeps cookies and does not follow redirects.
    /// </summary>
    /// <remarks>
    /// Redirects are the interesting part of an OpenID Connect flow, not something to be followed silently.
    /// Every test here inspects where it was sent and why.
    /// </remarks>
    public HttpClient CreateClient() =>
        new(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer(),
        })
        {
            BaseAddress = BaseAddress,
        };
}
