using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using Tavenem.DataStorage;
using Tavenem.Wiki;

namespace Lore.Data;

public class ApplicationUserStore_Memory([FromServices] IDataStore store, [FromServices] IOptions<IdentityOptions> optionsAccessor)
    : IUserClaimStore<ApplicationUser>,
    IUserPasswordStore<ApplicationUser>,
    IUserSecurityStampStore<ApplicationUser>,
    IUserTwoFactorStore<ApplicationUser>,
    IUserEmailStore<ApplicationUser>,
    IUserLockoutStore<ApplicationUser>,
    IQueryableUserStore<ApplicationUser>,
    IWikiUserManager
{
    private readonly IdentityOptions _identityOptions = optionsAccessor.Value;

    private bool _disposedValue;

    /// <inheritdoc />
    public IQueryable<ApplicationUser> Users => store.Query<ApplicationUser>().AsEnumerable().AsQueryable();

    /// <inheritdoc />
    public async Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        foreach (var claim in claims)
        {
            if (claim.Type == _identityOptions.ClaimsIdentity.UserIdClaimType)
            {
                if (string.IsNullOrEmpty(user.Id))
                {
                    user.Id = claim.Value;
                }
                else if (claim.Value != user.Id)
                {
                    throw new InvalidOperationException("Attempted to assign incorrect ID claim to user");
                }
                continue;
            }
            if (claim.Type == _identityOptions.ClaimsIdentity.EmailClaimType)
            {
                user.Email = claim.Value;
                user.NormalizedEmail = claim.Value.ToUpperInvariant();
                continue;
            }
            if (claim.Type == ClaimTypes.Name)
            {
                user.UserName = claim.Value;
                user.NormalizedUserName = claim.Value.ToUpperInvariant();
                continue;
            }
            (user.Claims ??= []).Add(claim);
        }
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        try
        {
            await store.StoreItemAsync(user);
            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            return IdentityResult.Failed(new IdentityError { Code = ex.HResult.ToString(), Description = ex.Message });
        }
    }

    /// <inheritdoc />
    public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        try
        {
            await store.RemoveItemAsync(user);
            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            return IdentityResult.Failed(new IdentityError { Code = ex.HResult.ToString(), Description = ex.Message });
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    /// <inheritdoc />
    public async Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
    {
        return await store
            .Query<ApplicationUser>()
            .Where(x => x.NormalizedEmail == normalizedEmail)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public async Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        return await store.GetItemAsync<ApplicationUser>(userId);
    }

    /// <inheritdoc />
    public async ValueTask<IWikiUser?> FindByIdAsync(string? userId)
    {
        if (string.IsNullOrEmpty(userId))
        {
            return null;
        }
        return await store.GetItemAsync<ApplicationUser>(userId);
    }

    /// <inheritdoc />
    public async Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        return await store
            .Query<ApplicationUser>()
            .Where(x => x.NormalizedUserName == normalizedUserName)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public async ValueTask<IWikiUser?> FindByNameAsync(string? userName)
    {
        if (string.IsNullOrEmpty(userName))
        {
            return null;
        }
        var normalizedUserName = userName.ToUpperInvariant();
        return await store
            .Query<ApplicationUser>()
            .Where(x => x.NormalizedUserName == normalizedUserName)
            .FirstOrDefaultAsync();
    }

    /// <inheritdoc />
    public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.AccessFailedCount);

    /// <inheritdoc />
    public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        var claims = user.Claims is null
            ? new List<Claim>()
            : [.. user.Claims];
        claims.Add(new(_identityOptions.ClaimsIdentity.UserIdClaimType, user.Id));
        if (!string.IsNullOrEmpty(user.Email))
        {
            claims.Add(new(_identityOptions.ClaimsIdentity.EmailClaimType, user.Email));
        }
        if (!string.IsNullOrEmpty(user.UserName))
        {
            claims.Add(new(ClaimTypes.Name, user.UserName));
        }
        return Task.FromResult<IList<Claim>>(claims);
    }

    /// <inheritdoc />
    public Task<string?> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.Email);

    /// <inheritdoc />
    public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.EmailConfirmed);

    /// <inheritdoc />
    public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.LockoutEnabled);

    /// <inheritdoc />
    public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.LockoutEnd);

    /// <inheritdoc />
    public Task<string?> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.NormalizedEmail);

    /// <inheritdoc />
    public Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.NormalizedUserName);

    /// <inheritdoc />
    public Task<string?> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.PasswordHash);

    /// <inheritdoc />
    public Task<string?> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.SecurityStamp);

    /// <inheritdoc />
    public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.TwoFactorEnabled);

    /// <inheritdoc />
    public async ValueTask<IWikiUser?> GetUserAsync(ClaimsPrincipal? principal)
    {
        if (principal?.Identity?.IsAuthenticated != true)
        {
            return null;
        }
        var userId = principal
            .Claims
            .FirstOrDefault(x => x.Type == _identityOptions.ClaimsIdentity.UserIdClaimType)?
            .Value;
        if (string.IsNullOrEmpty(userId))
        {
            return null;
        }
        return await store.GetItemAsync<ApplicationUser>(userId);
    }

    /// <inheritdoc />
    public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.Id);

    /// <inheritdoc />
    public Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(user.UserName);

    /// <inheritdoc />
    public async Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        return [..await store
            .Query<ApplicationUser>()
            .Where(x
            => x.Claims != null
            && x.Claims.Any(y
                => y.Type == claim.Type
                && y.Value == claim.Value
                && y.Issuer == claim.Issuer))
            .ToListAsync()];
    }

    /// <inheritdoc />
    public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        => Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));

    /// <inheritdoc />
    public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount++;
        await store.StoreItemAsync(user);
        return user.AccessFailedCount;
    }

    /// <inheritdoc />
    public async Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        if (user.Claims is null)
        {
            return;
        }
        foreach (var claim in claims)
        {
            user.Claims.Remove(claim);
        }
        if (user.Claims.Count == 0)
        {
            user.Claims = null;
        }
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        user.Claims?.Remove(claim);
        (user.Claims ??= []).Add(newClaim);
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        user.AccessFailedCount = 0;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetEmailAsync(ApplicationUser user, string? email, CancellationToken cancellationToken)
    {
        user.Email = email;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
    {
        user.EmailConfirmed = confirmed;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
    {
        user.LockoutEnabled = enabled;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
    {
        user.LockoutEnd = lockoutEnd;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetNormalizedEmailAsync(ApplicationUser user, string? normalizedEmail, CancellationToken cancellationToken)
    {
        user.NormalizedEmail = normalizedEmail;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        user.NormalizedUserName = normalizedName;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetPasswordHashAsync(ApplicationUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        user.PasswordHash = passwordHash;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
    {
        user.SecurityStamp = stamp;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
    {
        user.TwoFactorEnabled = enabled;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken cancellationToken)
    {
        user.UserName = userName;
        await store.StoreItemAsync(user);
    }

    /// <inheritdoc />
    public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
    {
        try
        {
            await store.StoreItemAsync(user);
            return IdentityResult.Success;
        }
        catch (Exception ex)
        {
            return IdentityResult.Failed(new IdentityError { Code = ex.HResult.ToString(), Description = ex.Message });
        }
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting
    /// unmanaged resources.
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposedValue)
        {
            if (disposing)
            {
                //store.Dispose();
            }

            _disposedValue = true;
        }
    }
}
