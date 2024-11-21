using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Text.Json.Serialization;
using Tavenem.DataStorage;
using Tavenem.Wiki;

namespace Lore.Data;

// Add profile data for application users by adding properties to the ApplicationUser class
public class ApplicationUser : IdentityUser, IWikiUser, IIdItem
{
    /// <summary>
    /// The <see cref="Claim"/>s assigned to this user.
    /// </summary>
    public List<Claim>? Claims { get; set; }

    /// <inheritdoc />
    public IList<string>? Groups { get; set; }

    /// <inheritdoc />
    public bool IsDeleted { get; set; }

    /// <inheritdoc />
    public bool IsDisabled { get; set; }

    /// <inheritdoc />
    public bool IsWikiAdmin { get; set; }

    /// <inheritdoc />
    public IList<PageTitle>? AllowedEditPages { get; set; }

    /// <inheritdoc />
    public IList<PageTitle>? AllowedViewPages { get; set; }

    /// <inheritdoc />
    public IList<string>? AllowedViewDomains { get; set; }

    /// <inheritdoc />
    [JsonIgnore]
    public string? DisplayName
    {
        get => UserName;
        set => UserName = value;
    }

    /// <inheritdoc />
    public int UploadLimit { get; set; }

    /// <inheritdoc />
    public bool Equals(IIdItem? other) => other?.Id.Equals(Id, StringComparison.Ordinal) == true;
}
