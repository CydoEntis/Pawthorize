namespace Pawthorize.Models;

/// <summary>
/// User information retrieved from an OAuth provider.
/// </summary>
public class ExternalUserInfo
{
    /// <summary>
    /// The user's unique ID from the provider.
    /// </summary>
    public required string ProviderId { get; init; }

    /// <summary>
    /// The user's email address.
    /// </summary>
    public string? Email { get; init; }

    /// <summary>
    /// Whether the email is verified by the provider.
    /// </summary>
    public bool EmailVerified { get; init; }

    /// <summary>
    /// The user's display name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The user's username (if applicable).
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// The user's profile picture URL.
    /// </summary>
    public string? ProfilePictureUrl { get; init; }

    /// <summary>
    /// Additional provider-specific data.
    /// </summary>
    public Dictionary<string, object>? AdditionalData { get; init; }
}
