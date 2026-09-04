using Keyward.TestSupport;

namespace Keyward.ConformanceTests;

/// <summary>Shares one provider, one database and one browser across the conformance suite.</summary>
[CollectionDefinition(Name)]
public sealed class KeywardTestGroup
    : ICollectionFixture<KeywardFixture>, ICollectionFixture<BrowserFixture>
{
    /// <summary>The collection name.</summary>
    public const string Name = "keyward-conformance";
}
