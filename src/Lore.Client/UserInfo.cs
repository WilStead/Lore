namespace Lore.Client;

public class UserInfo
{
    /// <inheritdoc />
    public string? DisplayName { get; set; }

    /// <inheritdoc />
    public required string Email { get; set; }

    /// <inheritdoc />
    public required string Id { get; init; }
}
