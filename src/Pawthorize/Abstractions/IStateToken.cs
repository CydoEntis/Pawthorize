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
}
