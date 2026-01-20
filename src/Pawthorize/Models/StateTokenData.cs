namespace Pawthorize.Models;

/// <summary>
/// Data associated with an OAuth state token.
/// </summary>
public class StateTokenData
{
    public required string Token { get; init; }
    public string? ReturnUrl { get; init; }
    public string? CodeVerifier { get; init; }
    public DateTime ExpiresAt { get; init; }

    /// <summary>
    /// The action type for this OAuth flow.
    /// "login" for standard login/register, "link" for linking a provider to an existing account.
    /// </summary>
    public string Action { get; init; } = "login";

    /// <summary>
    /// The user ID for link actions. Only set when Action is "link".
    /// </summary>
    public string? UserId { get; init; }
}
