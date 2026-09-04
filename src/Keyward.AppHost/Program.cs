// One command brings up Postgres, the identity provider, and the telemetry dashboard, with the schema
// applied and the demo clients and accounts registered. The walkthrough in the README starts here.
IDistributedApplicationBuilder builder = DistributedApplication.CreateBuilder(args);

IResourceBuilder<PostgresDatabaseResource> database = builder
    .AddPostgres("postgres")
    .WithDataVolume()
    .AddDatabase("keyward");

builder.AddProject<Projects.Keyward_Host>("keyward")
    .WithReference(database)
    .WaitFor(database)

    // Development settings, stated here rather than left implicit. Migrating and seeding on startup are
    // both off by default precisely so that turning them on has to be a decision somebody made.
    .WithEnvironment("Keyward__Database__MigrateOnStartup", "true")
    .WithEnvironment("Keyward__Seed__Enabled", "true")
    .WithEnvironment("Keyward__AllowInsecureTransport", "true")
    .WithHttpHealthCheck("/health/ready");

await builder.Build().RunAsync();
