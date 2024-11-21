using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace Lore.Client;

/// <summary>
/// <para>
/// This is a client-side <see cref="AuthenticationStateProvider"/> that determines the user's
/// authentication state by looking for data persisted in the page when it was rendered on the
/// server. This authentication state will be fixed for the lifetime of the WebAssembly application.
/// So, if the user needs to log in or out, a full page reload is required.
/// </para>
/// <para>
/// This only provides a user name and email for display purposes. It does not actually include any
/// tokens that authenticate to the server when making subsequent requests. That works separately
/// using a cookie that will be included on HttpClient requests to the server.
/// </para>
/// </summary>
internal class PersistentAuthenticationStateProvider : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> defaultUnauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly Task<AuthenticationState> authenticationStateTask = defaultUnauthenticatedTask;

    public PersistentAuthenticationStateProvider(PersistentComponentState state)
    {
        if (!state.TryTakeFromJson<UserInfo>(nameof(UserInfo), out var userInfo) || userInfo is null)
        {
            return;
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userInfo.Id),
            new(ClaimTypes.Email, userInfo.Email),
        };
        if (!string.IsNullOrEmpty(userInfo.DisplayName))
        {
            claims.Add(new(ClaimTypes.Name, userInfo.DisplayName));
        }

        authenticationStateTask = Task.FromResult(
            new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims,
                authenticationType: nameof(PersistentAuthenticationStateProvider)))));
    }

    public override Task<AuthenticationState> GetAuthenticationStateAsync() => authenticationStateTask;
}
