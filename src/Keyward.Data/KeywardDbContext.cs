using Keyward.Domain;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Keyward.Data;

/// <summary>
/// One database holding the accounts, the protocol state, and the keys that sign the tokens.
/// </summary>
/// <remarks>
/// <para>
/// The Data Protection key ring lives here rather than on disk. Keys on a local filesystem work until
/// there are two instances, at which point each signs with its own and every token one issues is rejected
/// by the other. Sharing the ring through the database is what makes the service horizontally scalable at
/// all, and it is not something to discover after the second replica is deployed.
/// </para>
/// <para>
/// OpenIddict's four tables are added by <c>UseOpenIddict</c>. They are the library's, not this project's,
/// and nothing here reaches into them directly except through its managers.
/// </para>
/// </remarks>
/// <param name="options">Provider options.</param>
public sealed class KeywardDbContext(DbContextOptions<KeywardDbContext> options)
    : DbContext(options), IDataProtectionKeyContext
{
    /// <summary>Accounts.</summary>
    public DbSet<User> Users => Set<User>();

    /// <summary>Enrolled authenticators, one per account.</summary>
    public DbSet<MfaSecret> MfaSecrets => Set<MfaSecret>();

    /// <summary>Unspent and spent backup codes.</summary>
    public DbSet<MfaBackupCode> MfaBackupCodes => Set<MfaBackupCode>();

    /// <summary>Refresh token chains.</summary>
    public DbSet<RefreshTokenFamily> RefreshTokenFamilies => Set<RefreshTokenFamily>();

    /// <summary>The authentication trail.</summary>
    public DbSet<AuthEvent> AuthEvents => Set<AuthEvent>();

    /// <inheritdoc />
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.UseOpenIddict();

        modelBuilder.Entity<User>(user =>
        {
            user.ToTable("users");
            user.HasKey(entity => entity.Id);

            user.Property(entity => entity.Email).HasMaxLength(256).IsRequired();
            user.Property(entity => entity.PasswordHash).HasMaxLength(512).IsRequired();
            user.Property(entity => entity.Status).HasConversion<int>();

            user.Property(entity => entity.Roles)
                .HasField("_roles")
                .UsePropertyAccessMode(PropertyAccessMode.Field)
                .HasColumnType("text[]")
                .IsRequired();

            // Sign-in looks an account up by address on every attempt, and two accounts sharing one address
            // would make which of them you authenticated as a matter of row order.
            user.HasIndex(entity => entity.Email).IsUnique();
        });

        modelBuilder.Entity<MfaSecret>(secret =>
        {
            secret.ToTable("mfa_secrets");
            secret.HasKey(entity => entity.UserId);
            secret.Property(entity => entity.ProtectedSecret).HasMaxLength(1024).IsRequired();
        });

        modelBuilder.Entity<MfaBackupCode>(code =>
        {
            code.ToTable("mfa_backup_codes");
            code.HasKey(entity => entity.Id);
            code.Property(entity => entity.CodeHash).HasMaxLength(256).IsRequired();

            // Redeeming a code scans this user's unspent ones.
            code.HasIndex(entity => new { entity.UserId, entity.ConsumedAtUtc });
        });

        modelBuilder.Entity<RefreshTokenFamily>(family =>
        {
            family.ToTable("refresh_token_families");
            family.HasKey(entity => entity.Id);

            family.Property(entity => entity.AuthorizationId).HasMaxLength(64).IsRequired();
            family.Property(entity => entity.ClientId).HasMaxLength(128).IsRequired();
            family.Property(entity => entity.Status).HasConversion<int>();
            family.Property(entity => entity.RevocationReason).HasConversion<int>();

            // Every refresh grant looks the family up by the authorization on the presented token, so this
            // is on the hot path of the flow the whole mechanism guards.
            family.HasIndex(entity => entity.AuthorizationId).IsUnique();

            // Listing or revoking a user's sessions.
            family.HasIndex(entity => new { entity.UserId, entity.Status });
        });

        modelBuilder.Entity<AuthEvent>(auditEvent =>
        {
            auditEvent.ToTable("auth_events");
            auditEvent.HasKey(entity => entity.Id);

            auditEvent.Property(entity => entity.Type).HasConversion<int>();
            auditEvent.Property(entity => entity.Detail).HasMaxLength(512).IsRequired();
            auditEvent.Property(entity => entity.ClientId).HasMaxLength(128);
            auditEvent.Property(entity => entity.RemoteAddress).HasMaxLength(64);
            auditEvent.Property(entity => entity.TraceId).HasMaxLength(64);

            // The two questions asked after an incident: what happened to this account, and what did this
            // client do.
            auditEvent.HasIndex(entity => new { entity.UserId, entity.OccurredAtUtc }).IsDescending(false, true);
            auditEvent.HasIndex(entity => new { entity.ClientId, entity.OccurredAtUtc }).IsDescending(false, true);
            auditEvent.HasIndex(entity => new { entity.Type, entity.OccurredAtUtc }).IsDescending(false, true);
        });
    }
}

/// <summary>Lets the EF tooling build a context without booting the service.</summary>
public sealed class KeywardDbContextFactory : IDesignTimeDbContextFactory<KeywardDbContext>
{
    /// <inheritdoc />
    public KeywardDbContext CreateDbContext(string[] args) =>
        new(new DbContextOptionsBuilder<KeywardDbContext>()
            .UseNpgsql("Host=localhost;Database=keyward;Username=postgres")
            .UseSnakeCaseNamingConvention()
            .UseOpenIddict()
            .Options);
}
