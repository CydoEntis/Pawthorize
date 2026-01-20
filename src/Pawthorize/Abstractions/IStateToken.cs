namespace Pawthorize.Abstractions;

/// <summary>
/// Represents a stored OAuth state token.
/// </summary>
public interface IStateToken
{
    string Token { get; }
    string? ReturnUrl { get; }
    string? CodeVerifier { get; }
    DateTime CreatedAt { get; }
    DateTime ExpiresAt { get; }

    /// <summary>
    /// The action type: "login" for standard login/register, "link" for linking a provider to an existing account.
    /// </summary>
    string Action { get; }

    /// <summary>
    /// The user ID for link actions. Only set when Action is "link".
    /// </summary>
    string? UserId { get; }
}
