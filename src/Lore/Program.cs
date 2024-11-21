using Lore.Client;
using Lore.Components;
using Lore.Components.Account;
using Lore.Data;
using Lore.Services.Email;
using Marten;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Tavenem.DataStorage;
using Tavenem.DataStorage.Marten;
using Tavenem.Wiki;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddRazorComponents()
    .AddInteractiveWebAssemblyComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, PersistingServerAuthenticationStateProvider>();

builder.Services.AddAuthorization();
builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = IdentityConstants.ApplicationScheme;
        options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
    })
    .AddIdentityCookies();

builder.Services.AddMarten(options =>
{
    options.Connection(builder.Configuration.GetConnectionString("DefaultConnection")
        ?? throw new InvalidOperationException("Missing Database connection string"));

    options.UseSystemTextJsonForSerialization();

    options.Schema.For<Page>().AddSubClassHierarchy();

    options.AutoCreateSchemaObjects = builder.Environment.IsDevelopment()
        ? Weasel.Core.AutoCreate.All
        : Weasel.Core.AutoCreate.CreateOrUpdate;
});
builder.Services.AddSingleton<IDataStore, MartenDataStore>();

builder.Services.AddSingleton<ApplicationUserStore>();
builder.Services.AddIdentityCore<ApplicationUser>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.User.RequireUniqueEmail = true;
})
    .AddUserStore<ApplicationUserStore>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

var store = new InMemoryDataStore();
builder.Services.AddSingleton<IDataStore>(_ => store);

builder.Services.AddScoped<WikiGroupManager>();

builder.Services.Configure<AuthMessageSenderOptions>(builder.Configuration.GetSection(nameof(AuthMessageSenderOptions)));
builder.Services.AddTransient<IEmailSender, EmailSender>();
builder.Services.AddTransient<IEmailSender<ApplicationUser>, EmailSender>();

builder.Services.AddWikiServer(
    LoreWikiOptions.WikiOptions,
    config => config.ConfigureUserManager(provider => provider.GetRequiredService<ApplicationUserStore>()));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseWebAssemblyDebugging();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseAntiforgery();

app.MapStaticAssets();

app.MapWiki();
app.MapRazorComponents<App>()
    .AddInteractiveWebAssemblyRenderMode()
    .AddAdditionalAssemblies(typeof(Lore.Client._Imports).Assembly,
        typeof(Tavenem.Wiki.Blazor.Client._Imports).Assembly);

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

await app.SetDefaultAdminUserAsync();

app.Run();
