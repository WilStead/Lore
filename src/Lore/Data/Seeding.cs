using Microsoft.AspNetCore.Identity;

namespace Lore.Data;

public static class Seeding
{
    public static async Task SetDefaultAdminUserAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var wikiSettings = app.Configuration.GetRequiredSection("Wiki");
        var defaultAdminPassword = wikiSettings.GetValue<string>("DefaultAdminPassword");
        if (string.IsNullOrEmpty(defaultAdminPassword))
        {
            throw new InvalidOperationException("Missing Wiki.DefaultAdminPassword Configuration setting.");
        }

        var userStore = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var admin = userStore.Users.Where(x => x.IsWikiAdmin).FirstOrDefault();
        if (admin is null)
        {
            admin = new()
            {
                Id = "c6798a76-7831-4675-959b-2951566ef068",
                DisplayName = "Wil",
                Email = "wil.stead@williamstead.com",
                EmailConfirmed = true,
                IsWikiAdmin = true,
                NormalizedEmail = "WIL@WILLIAMSTEAD.COM",
                NormalizedUserName = "WIL",
                UserName = "Wil",
            };
            var result = await userStore.CreateAsync(admin, defaultAdminPassword);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException(string.Join("; ", result.Errors.Select(x => $"{x.Code}: {x.Description}")));
            }
        }
    }
}
