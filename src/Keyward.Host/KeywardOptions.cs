using System.ComponentModel.DataAnnotations;

namespace Keyward.Host;

/// <summary>Everything about how long a credential stays good for.</summary>
public sealed class TokenOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Keyward:Tokens";

    /// <summary>
    /// How long an access token is accepted for.
    /// </summary>
    /// <remarks>
    /// Deliberately short. Relying parties validate this token locally against JWKS and never call back
    /// here, so between issuing it and it expiring there is no way to take it back. Five minutes is the
    /// blast radius of a leak.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan AccessTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How long a refresh token is good for, counted from when it was issued.</summary>
    [Range(typeof(TimeSpan), "00:05:00", "90.00:00:00")]
    public TimeSpan RefreshTokenLifetime { get; init; } = TimeSpan.FromDays(14);

    /// <summary>
    /// The hard stop on a whole chain of refresh tokens, however often it is used.
    /// </summary>
    /// <remarks>
    /// Without this, a sliding window means a session used daily never ends, and a token stolen from an
    /// active user is good forever. At some point everybody signs in again.
    /// </remarks>
    [Range(typeof(TimeSpan), "00:05:00", "365.00:00:00")]
    public TimeSpan RefreshFamilyAbsoluteLifetime { get; init; } = TimeSpan.FromDays(30);

    /// <summary>How long an authorization code may be exchanged for.</summary>
    [Range(typeof(TimeSpan), "00:00:10", "00:10:00")]
    public TimeSpan AuthorizationCodeLifetime { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>How long an identity token is accepted for.</summary>
    [Range(typeof(TimeSpan), "00:01:00", "01:00:00")]
    public TimeSpan IdentityTokenLifetime { get; init; } = TimeSpan.FromMinutes(5);
}

/// <summary>How the second factor behaves.</summary>
public sealed class MfaOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Keyward:Mfa";

    /// <summary>Name shown in the authenticator app.</summary>
    [Required]
    public string Issuer { get; init; } = "Keyward";

    /// <summary>
    /// How many steps either side of now are accepted.
    /// </summary>
    /// <remarks>
    /// One step in each direction, as RFC 6238 recommends. Phones and servers drift, and a user typing a
    /// code that was correct four seconds ago should not be told they are wrong. Widening this trades
    /// tolerance for the number of codes valid at any moment, so it stays at one.
    /// </remarks>
    [Range(0, 3)]
    public int VerificationWindowSteps { get; init; } = 1;

    /// <summary>Failed attempts before the second-factor step locks.</summary>
    [Range(1, 20)]
    public int LockoutThreshold { get; init; } = 5;

    /// <summary>How many single-use recovery codes are issued at enrolment.</summary>
    [Range(1, 32)]
    public int BackupCodeCount { get; init; } = 10;

    /// <summary>
    /// Roles for which a second factor is mandatory.
    /// </summary>
    /// <remarks>
    /// Empty means nobody is forced. A password alone is enough for a low-value account and a nuisance to
    /// mandate; it is not enough for anyone who can change what other people can do.
    /// </remarks>
    public IReadOnlyList<string> RequiredForRoles { get; init; } = ["admin"];
}

/// <summary>What the service does on first start in a development environment.</summary>
public sealed class SeedOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Keyward:Seed";

    /// <summary>
    /// Whether to create the demo clients and users if they are missing.
    /// </summary>
    /// <remarks>
    /// Off unless something turns it on. A seeder that runs by default is a seeder that eventually creates
    /// a known account with a known password in production.
    /// </remarks>
    public bool Enabled { get; init; }

    /// <summary>Where the demo interactive client is allowed to send a user back to.</summary>
    public IReadOnlyList<string> DemoClientRedirectUris { get; init; } = ["http://localhost:5199/callback"];

    /// <summary>The tenant the demo accounts belong to.</summary>
    public Guid DemoTenantId { get; init; } = new("00000000-0000-0000-0000-0000000000a1");

    /// <summary>Sign-in address of the demo account holding the operator role.</summary>
    [Required]
    [EmailAddress]
    public string DemoAdminEmail { get; init; } = "admin@keyward.local";

    /// <summary>Password for the demo operator account.</summary>
    [Required]
    [MinLength(12)]
    public string DemoAdminPassword { get; init; } = "ChangeMe!Admin1";

    /// <summary>Sign-in address of the demo account with no special rights.</summary>
    [Required]
    [EmailAddress]
    public string DemoUserEmail { get; init; } = "user@keyward.local";

    /// <summary>Password for the ordinary demo account.</summary>
    [Required]
    [MinLength(12)]
    public string DemoUserPassword { get; init; } = "ChangeMe!User1";

    /// <summary>Secret handed to the demo machine client.</summary>
    [Required]
    [MinLength(16)]
    public string DemoServiceClientSecret { get; init; } = "ChangeMe!Service-Secret";
}

/// <summary>How the service treats the schema it finds.</summary>
public sealed class DatabaseOptions
{
    /// <summary>Configuration section name.</summary>
    public const string SectionName = "Keyward:Database";

    /// <summary>
    /// Whether to apply pending migrations during startup.
    /// </summary>
    /// <remarks>
    /// Off by default, and it should stay off anywhere real. A rolling deploy runs the old and new versions
    /// side by side for a minute or two, and a migration racing itself across two instances is a bad way to
    /// find that out. In production the schema is applied deliberately, by someone who has read the SQL
    /// that <c>dotnet ef migrations script</c> produced.
    /// </remarks>
    public bool MigrateOnStartup { get; init; }
}
