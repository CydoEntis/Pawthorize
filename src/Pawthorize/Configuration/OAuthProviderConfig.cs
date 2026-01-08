namespace Pawthorize.Configuration;

/// <summary>
/// Configuration for a single OAuth provider.
/// </summary>
public class OAuthProviderConfig
{
    /// <summary>
    /// Whether this provider is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// OAuth client ID.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// OAuth client secret.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// OAuth callback redirect URI (e.g., "https://localhost:5001/api/auth/oauth/google/callback").
    /// </summary>
    public string RedirectUri { get; set; } = string.Empty;

    /// <summary>
    /// OAuth scopes to request.
    /// </summary>
    public string[] Scopes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Whether to require email verification from the provider.
    /// </summary>
    public bool RequireVerifiedEmail { get; set; } = true;

    /// <summary>
    /// Custom authorization endpoint (overrides provider default).
    /// </summary>
    public string? AuthorizationEndpoint { get; set; }

    /// <summary>
    /// Custom token endpoint (overrides provider default).
    /// </summary>
    public string? TokenEndpoint { get; set; }

    /// <summary>
    /// Custom user info endpoint (overrides provider default).
    /// </summary>
    public string? UserInfoEndpoint { get; set; }
}
