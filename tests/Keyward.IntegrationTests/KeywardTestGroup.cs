using Keyward.TestSupport;

namespace Keyward.IntegrationTests;

/// <summary>Shares one provider and one database across every test in the group.</summary>
[CollectionDefinition(Name)]
public sealed class KeywardTestGroup : ICollectionFixture<KeywardFixture>
{
    /// <summary>The collection name.</summary>
    public const string Name = "keyward";
}
