using Keyward.Data;
using Keyward.Host.Endpoints;
using Keyward.Host.Security;
using Keyward.Host.Seeding;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using OpenIddict.Validation.AspNetCore;
using OpenTelemetry;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Keyward.Host;

/// <summary>Builds the identity provider.</summary>
/// <remarks>
/// Separated from the entry point so the test suites can start and stop it in process, against a database
/// they created, without the flow under test knowing it is being tested.
/// </remarks>
public static class KeywardHost
{
    /// <summary>Builds the application.</summary>
    /// <param name="args">Command-line arguments.</param>
    /// <param name="configure">Applied to the builder before it is built.</param>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        // The application name is pinned to this assembly rather than left to default to whatever started
        // the process. Razor Pages are discovered through the application name, so a host built from a test
        // assembly would otherwise come up with no pages at all and answer 404 to its own login form.
        WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(KeywardHost).Assembly.GetName().Name,
        });

        configure?.Invoke(builder);

        AddOptions(builder);
        AddPersistence(builder);
        AddAuthentication(builder);
        AddTelemetry(builder);

        builder.Services.AddHttpContextAccessor();
        builder.Services.AddRazorPages();
        builder.Services.AddProblemDetails();
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<KeywardMetrics>();
        builder.Services.AddAntiforgery();
        builder.Services.AddSingleton<PasswordService>();
        builder.Services.AddScoped<MfaService>();
        builder.Services.AddScoped<AuditWriter>();
        builder.Services.AddScoped<RefreshTokenFamilyService>();
        builder.Services.AddScoped<RefreshTokenReuseDetector>();
        builder.Services.AddHostedService<DatabaseInitializer>();

        builder.Services.AddHealthChecks()
            .AddDbContextCheck<KeywardDbContext>("database", tags: ["ready"]);

        WebApplication app = builder.Build();

        // The browser half of this service renders pages, so a failure has to land on one. The API half is
        // covered by the same handler: a request that asked for JSON gets problem details from
        // AddProblemDetails rather than the HTML page.
        app.UseExceptionHandler("/Error");
        app.UseStatusCodePages();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapRazorPages();
        app.MapConnectEndpoints();
        app.MapAdminEndpoints();

        app.MapHealthChecks("/health/live", new()
        {
            Predicate = static registration => registration.Tags.Count == 0,
        });

        app.MapHealthChecks("/health/ready", new()
        {
            Predicate = static registration => registration.Tags.Contains("ready"),
        });

        return app;
    }

    private static void AddOptions(WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<TokenOptions>()
            .Bind(builder.Configuration.GetSection(TokenOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.AddOptions<MfaOptions>()
            .Bind(builder.Configuration.GetSection(MfaOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.AddOptions<SigningOptions>()
            .Bind(builder.Configuration.GetSection(SigningOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.AddOptions<DatabaseOptions>()
            .Bind(builder.Configuration.GetSection(DatabaseOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();

        builder.Services.AddOptions<SeedOptions>()
            .Bind(builder.Configuration.GetSection(SeedOptions.SectionName))
            .ValidateDataAnnotations()
            .ValidateOnStart();
    }

    private static void AddPersistence(WebApplicationBuilder builder)
    {
        string connectionString = builder.Configuration.GetConnectionString("keyward")
            ?? throw new InvalidOperationException("Connection string 'keyward' is not configured.");

        builder.Services.AddDbContext<KeywardDbContext>(options => options
            .UseNpgsql(connectionString, npgsql =>
                npgsql.MigrationsAssembly(typeof(KeywardDbContext).Assembly.FullName))
            .UseSnakeCaseNamingConvention()
            .UseOpenIddict());

        // The key ring goes in the database, not on disk. On disk it works until there are two instances,
        // and then each signs with its own key and rejects everything the other issued.
        builder.Services.AddDataProtection()
            .SetApplicationName("Keyward")
            .PersistKeysToDbContext<KeywardDbContext>();
    }

    private static void AddAuthentication(WebApplicationBuilder builder)
    {
        builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/connect/logout";
                options.ExpireTimeSpan = TimeSpan.FromHours(8);
                options.SlidingExpiration = true;

                // The browser session cookie for the provider itself. Http-only so script cannot read it,
                // and same-site lax rather than strict because the whole point is being arrived at from
                // another site's redirect.
                options.Cookie.Name = "keyward.session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            });

        builder.Services.AddOpenIddict()
            .AddCore(options => options
                .UseEntityFrameworkCore()
                .UseDbContext<KeywardDbContext>())

            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetIntrospectionEndpointUris("connect/introspect")
                    .SetRevocationEndpointUris("connect/revoke");

                options.AllowAuthorizationCodeFlow()
                    .AllowRefreshTokenFlow()
                    .AllowClientCredentialsFlow();

                // Proof key is mandatory, not merely supported. A public client cannot keep a secret, so
                // without it an authorization code intercepted on the redirect is enough on its own.
                options.RequireProofKeyForCodeExchange();

                options.RegisterScopes(
                    OpenIddictConstants.Scopes.OpenId,
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Roles,
                    OpenIddictConstants.Scopes.OfflineAccess,
                    "api");

                TokenOptions tokens = builder.Configuration
                    .GetSection(TokenOptions.SectionName)
                    .Get<TokenOptions>() ?? new TokenOptions();

                options.SetAccessTokenLifetime(tokens.AccessTokenLifetime)
                    .SetIdentityTokenLifetime(tokens.IdentityTokenLifetime)
                    .SetAuthorizationCodeLifetime(tokens.AuthorizationCodeLifetime)
                    .SetRefreshTokenLifetime(tokens.RefreshTokenLifetime);

                // Two settings that only mean anything together.
                //
                // Reference refresh tokens are opaque handles backed by a database row, so a token can be
                // marked redeemed and recognised when it turns up again. Rotation itself is already
                // OpenIddict's default; what is not default is the leeway. OpenIddict allows a redeemed
                // refresh token to be presented again for a short grace period, so a client that lost the
                // response to a network error is not punished for retrying. That grace period is also
                // exactly the window a thief needs, and this service would rather treat a second
                // presentation as an incident than as a hiccup, so it is set to nothing.
                options.UseReferenceRefreshTokens()
                    .SetRefreshTokenReuseLeeway(TimeSpan.Zero);

                // The plain challenge method sends the verifier itself, which protects against nothing once
                // the authorize request has been seen. Advertising it in the discovery document would tell
                // a client library it is on the table.
                options.Configure(server => server.CodeChallengeMethods.Remove(
                    OpenIddictConstants.CodeChallengeMethods.Plain));

                // Access tokens are plain signed JWTs, not encrypted ones. Encryption would mean only this
                // service could read them, and the entire point is that a relying party validates a token
                // against JWKS without calling back here.
                options.DisableAccessTokenEncryption();

                OpenIddictServerAspNetCoreBuilder aspNetCore = options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();

                // Plain HTTP is refused unless something says otherwise, which is the right default for a
                // service whose entire job is handling credentials. Development and the test suites turn it
                // on deliberately; nothing else should.
                if (builder.Configuration.GetValue("Keyward:AllowInsecureTransport", defaultValue: false))
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }

                AddKeys(builder, options);

                options.AddEventHandler(RefreshTokenReuseDetector.Descriptor);
            })

            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        builder.Services.AddAuthorizationBuilder();
    }

    /// <summary>
    /// Registers the signing and encryption keys.
    /// </summary>
    /// <remarks>
    /// Every configured certificate is registered, not only the newest, because OpenIddict publishes all of
    /// them to JWKS and signs with the first. That is what makes a key rotation survivable: the previous
    /// key stays verifiable while relying parties still have it cached.
    /// </remarks>
    private static void AddKeys(WebApplicationBuilder builder, OpenIddictServerBuilder options)
    {
        SigningOptions signing = builder.Configuration
            .GetSection(SigningOptions.SectionName)
            .Get<SigningOptions>() ?? new SigningOptions();

        if (!signing.HasCertificates)
        {
            if (!builder.Environment.IsDevelopment())
            {
                throw new InvalidOperationException(
                    "Signing and encryption certificates must be configured under "
                    + $"'{SigningOptions.SectionName}' outside development. Ephemeral development keys are "
                    + "regenerated on every start, which invalidates every token that was already issued.");
            }

            options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();

            return;
        }

        foreach (CertificateReference reference in signing.SigningCertificates)
        {
            options.AddSigningCertificate(reference.Load());
        }

        foreach (CertificateReference reference in signing.EncryptionCertificates)
        {
            options.AddEncryptionCertificate(reference.Load());
        }
    }

    private static void AddTelemetry(WebApplicationBuilder builder)
    {
        builder.Services.AddOpenTelemetry()
            .WithMetrics(metrics => metrics
                .AddMeter(KeywardMetrics.MeterName)
                .AddAspNetCoreInstrumentation()
                .AddRuntimeInstrumentation())
            .WithTracing(tracing => tracing
                .AddSource(KeywardMetrics.ActivitySourceName)
                .AddAspNetCoreInstrumentation());

        if (!string.IsNullOrWhiteSpace(builder.Configuration["OTEL_EXPORTER_OTLP_ENDPOINT"]))
        {
            builder.Services.AddOpenTelemetry().UseOtlpExporter();
        }
    }
}
