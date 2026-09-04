using Microsoft.Playwright;

namespace Keyward.ConformanceTests;

/// <summary>
/// A headless browser, installed on first use.
/// </summary>
/// <remarks>
/// The browser is what makes this suite worth having. An authorization code flow is a chain of redirects
/// through HTML forms, and a hand-written HTTP client walking that chain is really testing the walker: it
/// follows the redirects the author expected and fills the fields the author knew about. A browser follows
/// what is actually there.
/// </remarks>
public sealed class BrowserFixture : IAsyncLifetime
{
    private IPlaywright? _playwright;
    private IBrowser? _browser;

    /// <summary>The browser, once it has started.</summary>
    public IBrowser Browser =>
        _browser ?? throw new InvalidOperationException("The browser has not been started.");

    /// <summary>Installs the browser if it is missing, then starts it.</summary>
    public async ValueTask InitializeAsync()
    {
        int exitCode = Microsoft.Playwright.Program.Main(["install", "chromium"]);

        if (exitCode is not 0)
        {
            throw new InvalidOperationException($"Playwright could not install Chromium (exit code {exitCode}).");
        }

        _playwright = await Playwright.CreateAsync();

        _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
        {
            Headless = true,
        });
    }

    /// <summary>Closes the browser.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_browser is not null)
        {
            await _browser.CloseAsync();
        }

        _playwright?.Dispose();
    }
}
