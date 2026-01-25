using Pawthorize.Abstractions;

namespace Pawthorize.Services.OAuth.Models;

/// <summary>
/// Default implementation of IStateToken.
/// </summary>
public class StateToken : IStateToken
{
    public required string Token { get; init; }
    public string? ReturnUrl { get; init; }
    public string? CodeVerifier { get; init; }
    public DateTime CreatedAt { get; init; } = DateTime.UtcNow;
    public DateTime ExpiresAt { get; init; }
    public string Action { get; init; } = "login";
    public string? UserId { get; init; }
}
