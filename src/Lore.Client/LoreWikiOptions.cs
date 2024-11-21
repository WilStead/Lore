using Tavenem.Wiki;
using Tavenem.Wiki.Blazor.Client;

namespace Lore.Client;

public static class LoreWikiOptions
{
    public static WikiBlazorOptions WikiOptions { get; } = new()
    {
        AppBar = typeof(TopAppBar),
        ContactPageTitle = null,
        DefaultAnonymousPermission = WikiPermission.None,
        LoginPath = "/Account/Login",
        MaxFileSize = 0,
        WikiServerApiRoute = WikiBlazorOptions.DefaultWikiServerApiRoute,
    };
}
