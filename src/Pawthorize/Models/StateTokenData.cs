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
}
