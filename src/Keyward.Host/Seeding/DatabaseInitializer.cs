using Keyward.Data;
using Keyward.Domain;
using Keyward.Host.Security;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace Keyward.Host.Seeding;

/// <summary>
/// Brings the database up to date and, when asked, puts a working set of demo records in it.
/// </summary>
/// <remarks>
/// <para>
/// Both halves are off by default. Migrating on startup is convenient in development and a liability in
/// production, where a rolling deploy can put two versions of the schema migrator in the ring at once and
/// where the person running the release wants to see the SQL first. Seeding is worse: a seeder that runs
/// unconditionally is a seeder that eventually creates a known account with a known password on a public
/// host.
/// </para>
/// <para>
/// Everything here is written to be run twice. Clients are looked up before they are created, users are
/// matched on their email address, and a second run changes nothing.
/// </para>
/// </remarks>
/// <param name="services">Root scope factory, since this runs before the request pipeline exists.</param>
/// <param name="database">Whether to migrate.</param>
/// <param name="seed">Whether to seed, and what with.</param>
/// <param name="timeProvider">Clock.</param>
/// <param name="logger">Logger.</param>
public sealed partial class DatabaseInitializer(
    IServiceScopeFactory services,
    IOptions<DatabaseOptions> database,
    IOptions<SeedOptions> seed,
    TimeProvider timeProvider,
    ILogger<DatabaseInitializer> logger) : IHostedService
{
    /// <summary>The demo interactive client.</summary>
    public const string DemoInteractiveClientId = "keyward-demo-spa";

    /// <summary>The demo machine client.</summary>
    public const string DemoServiceClientId = "keyward-demo-service";

    /// <summary>
    /// A demo client the operator has marked as first-party.
    /// </summary>
    /// <remarks>
    /// Registered with implicit consent, which is what makes it first-party in practice: asking a user
    /// whether their employer's own portal may read their own name is a dialog people learn to click
    /// through, and a consent screen that is always approved teaches exactly the wrong habit.
    /// </remarks>
    public const string DemoFirstPartyClientId = "keyward-demo-portal";

    private readonly DatabaseOptions _database = database.Value;
    private readonly SeedOptions _seed = seed.Value;

    /// <inheritdoc />
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!_database.MigrateOnStartup && !_seed.Enabled)
        {
            return;
        }

        await using AsyncServiceScope scope = services.CreateAsyncScope();

        KeywardDbContext dbContext = scope.ServiceProvider.GetRequiredService<KeywardDbContext>();

        if (_database.MigrateOnStartup)
        {
            LogMigrating(logger);
            await dbContext.Database.MigrateAsync(cancellationToken);
        }

        if (!_seed.Enabled)
        {
            return;
        }

        LogSeeding(logger);

        await SeedClientsAsync(scope.ServiceProvider, cancellationToken);
        await SeedScopesAsync(scope.ServiceProvider, cancellationToken);
        await SeedUsersAsync(scope.ServiceProvider, dbContext, cancellationToken);
    }

    /// <inheritdoc />
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private async Task SeedClientsAsync(IServiceProvider provider, CancellationToken cancellationToken)
    {
        IOpenIddictApplicationManager applications =
            provider.GetRequiredService<IOpenIddictApplicationManager>();

        await CreateInteractiveClientAsync(
            applications,
            DemoInteractiveClientId,
            "Keyward demo application",
            OpenIddictConstants.ConsentTypes.Explicit,
            cancellationToken);

        await CreateInteractiveClientAsync(
            applications,
            DemoFirstPartyClientId,
            "Keyward portal",
            OpenIddictConstants.ConsentTypes.Implicit,
            cancellationToken);

        if (await applications.FindByClientIdAsync(DemoServiceClientId, cancellationToken) is null)
        {
            await applications.CreateAsync(
                new OpenIddictApplicationDescriptor
                {
                    ClientId = DemoServiceClientId,
                    ClientSecret = _seed.DemoServiceClientSecret,
                    ClientType = OpenIddictConstants.ClientTypes.Confidential,
                    DisplayName = "Keyward demo service",
                    Permissions =
                    {
                        OpenIddictConstants.Permissions.Endpoints.Token,
                        OpenIddictConstants.Permissions.Endpoints.Introspection,
                        OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                        OpenIddictConstants.Permissions.Prefixes.Scope + "api",
                    },
                },
                cancellationToken);

            LogClientCreated(logger, DemoServiceClientId);
        }
    }

    /// <summary>Registers a browser-based client, unless one with that id already exists.</summary>
    /// <param name="applications">The client registry.</param>
    /// <param name="clientId">Client id.</param>
    /// <param name="displayName">What the consent screen calls it.</param>
    /// <param name="consentType">Explicit for a third-party client, implicit for a first-party one.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    private async Task CreateInteractiveClientAsync(
        IOpenIddictApplicationManager applications,
        string clientId,
        string displayName,
        string consentType,
        CancellationToken cancellationToken)
    {
        if (await applications.FindByClientIdAsync(clientId, cancellationToken) is not null)
        {
            return;
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = consentType,
            DisplayName = displayName,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.EndSession,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Scopes.Roles,
                OpenIddictConstants.Permissions.Prefixes.Scope + "api",
            },

            // Proof key is required of each client as well as globally. The global switch is the one that
            // matters, but a client that records the requirement keeps it if the global setting is ever
            // relaxed for something else.
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange },
        };

        foreach (string uri in _seed.DemoClientRedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(uri, UriKind.Absolute));
        }

        await applications.CreateAsync(descriptor, cancellationToken);
        LogClientCreated(logger, clientId);
    }

    private static async Task SeedScopesAsync(IServiceProvider provider, CancellationToken cancellationToken)
    {
        IOpenIddictScopeManager scopes = provider.GetRequiredService<IOpenIddictScopeManager>();

        if (await scopes.FindByNameAsync("api", cancellationToken) is null)
        {
            await scopes.CreateAsync(
                new OpenIddictScopeDescriptor
                {
                    Name = "api",
                    DisplayName = "Access to the demo API",
                    Resources = { "keyward-demo-api" },
                },
                cancellationToken);
        }

        // A registered scope that no demo client is permitted to ask for. It exists so the difference
        // between "there is no such scope" and "you may not have that scope" is a real difference here and
        // not only in theory.
        if (await scopes.FindByNameAsync("reports", cancellationToken) is null)
        {
            await scopes.CreateAsync(
                new OpenIddictScopeDescriptor
                {
                    Name = "reports",
                    DisplayName = "Access to reporting data",
                    Resources = { "keyward-demo-reports" },
                },
                cancellationToken);
        }
    }

    private async Task SeedUsersAsync(
        IServiceProvider provider,
        KeywardDbContext dbContext,
        CancellationToken cancellationToken)
    {
        PasswordService passwords = provider.GetRequiredService<PasswordService>();
        Guid tenantId = _seed.DemoTenantId;
        bool changed = false;

        foreach ((string email, string password, string[] roles) in DemoAccounts())
        {
            if (await dbContext.Users.AnyAsync(user => user.Email == email, cancellationToken))
            {
                continue;
            }

            User user = User.Register(email, "placeholder", tenantId, roles, timeProvider.GetUtcNow());
            user.SetPasswordHash(passwords.Hash(user, password));

            dbContext.Users.Add(user);
            changed = true;

            LogUserCreated(logger, email);
        }

        if (changed)
        {
            await dbContext.SaveChangesAsync(cancellationToken);
        }
    }

    private IEnumerable<(string Email, string Password, string[] Roles)> DemoAccounts()
    {
        yield return (_seed.DemoAdminEmail, _seed.DemoAdminPassword, ["admin"]);
        yield return (_seed.DemoUserEmail, _seed.DemoUserPassword, ["user"]);
    }

    [LoggerMessage(EventId = 7000, Level = LogLevel.Information, Message = "Applying database migrations.")]
    private static partial void LogMigrating(ILogger logger);

    [LoggerMessage(EventId = 7001, Level = LogLevel.Warning, Message = "Seeding demo data. This must never run in production.")]
    private static partial void LogSeeding(ILogger logger);

    [LoggerMessage(EventId = 7002, Level = LogLevel.Information, Message = "Registered client {ClientId}.")]
    private static partial void LogClientCreated(ILogger logger, string clientId);

    [LoggerMessage(EventId = 7003, Level = LogLevel.Information, Message = "Created demo account {Email}.")]
    private static partial void LogUserCreated(ILogger logger, string email);
}
