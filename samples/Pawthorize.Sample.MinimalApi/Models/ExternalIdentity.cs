using Pawthorize.Abstractions;

namespace Pawthorize.Sample.MinimalApi.Models;

/// <summary>
/// Represents an external OAuth provider linked to a user account.
/// </summary>
public class ExternalIdentity : IExternalIdentity
{
    public string Provider { get; set; } = string.Empty;
    public string ProviderId { get; set; } = string.Empty;
    public string? ProviderEmail { get; set; }
    public string? ProviderUsername { get; set; }
    public DateTime LinkedAt { get; set; }
    public Dictionary<string, string>? Metadata { get; set; }

    // For in-memory storage, we need to track which user this belongs to
    public string UserId { get; set; } = string.Empty;
}
