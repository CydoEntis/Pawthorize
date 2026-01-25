using Pawthorize.Abstractions;

namespace Pawthorize.Services.OAuth.Models;

/// <summary>
/// Default implementation of IExternalIdentity.
/// </summary>
public class ExternalIdentity : IExternalIdentity
{
    public required string Provider { get; init; }
    public required string ProviderId { get; init; }
    public string? ProviderEmail { get; init; }
    public string? ProviderUsername { get; init; }
    public DateTime LinkedAt { get; init; } = DateTime.UtcNow;
    public Dictionary<string, string>? Metadata { get; init; }
}
