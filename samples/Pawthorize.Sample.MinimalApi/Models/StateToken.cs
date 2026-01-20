using Pawthorize.Abstractions;

namespace Pawthorize.Sample.MinimalApi.Models;

/// <summary>
/// OAuth state token for CSRF protection during OAuth flow.
/// </summary>
public class StateToken : IStateToken
{
    public string Token { get; set; } = string.Empty;
    public string? ReturnUrl { get; set; }
    public string? CodeVerifier { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Action { get; set; } = "login";
    public string? UserId { get; set; }
}
