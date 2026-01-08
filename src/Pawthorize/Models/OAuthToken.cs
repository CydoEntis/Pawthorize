namespace Pawthorize.Models;

/// <summary>
/// OAuth access token response from a provider.
/// </summary>
public class OAuthToken
{
    public required string AccessToken { get; init; }
    public string? RefreshToken { get; init; }
    public string? TokenType { get; init; }
    public int? ExpiresIn { get; init; }
    public string? Scope { get; init; }
}
