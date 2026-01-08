namespace Pawthorize.Abstractions;

/// <summary>
/// Represents an external OAuth provider linked to a user account.
/// </summary>
public interface IExternalIdentity
{
    /// <summary>
    /// The provider name (e.g., "google", "discord", "github").
    /// </summary>
    string Provider { get; }

    /// <summary>
    /// The user's unique ID from the provider.
    /// </summary>
    string ProviderId { get; }

    /// <summary>
    /// The email from the provider.
    /// </summary>
    string? ProviderEmail { get; }

    /// <summary>
    /// The username from the provider.
    /// </summary>
    string? ProviderUsername { get; }

    /// <summary>
    /// When the provider was linked to the account.
    /// </summary>
    DateTime LinkedAt { get; }

    /// <summary>
    /// Additional metadata (JSON serializable).
    /// </summary>
    Dictionary<string, string>? Metadata { get; }
}
