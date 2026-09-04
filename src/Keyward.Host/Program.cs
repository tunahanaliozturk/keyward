using Keyward.Host;

WebApplication app = KeywardHost.Build(args);
await app.RunAsync();
