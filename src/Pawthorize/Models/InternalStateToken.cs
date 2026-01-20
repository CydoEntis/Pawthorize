using Pawthorize.Abstractions;

namespace Pawthorize.Models;

/// <summary>
/// Internal state token implementation used by Pawthorize OAuth.
/// Users don't need to implement this - it's handled automatically.
/// </summary>
internal class InternalStateToken : IStateToken
{
    public string Token { get; set; } = string.Empty;
    public string? ReturnUrl { get; set; }
    public string? CodeVerifier { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Action { get; set; } = "login";
    public string? UserId { get; set; }
}
