namespace Pawthorize.Configuration;

/// <summary>
/// OAuth configuration options.
/// </summary>
public class OAuthOptions
{
    public const string SectionName = "Pawthorize:OAuth";

    /// <summary>
    /// OAuth provider configurations keyed by provider name.
    /// </summary>
    public Dictionary<string, OAuthProviderConfig> Providers { get; set; } = new();

    /// <summary>
    /// Whether to automatically create user accounts on first OAuth login.
    /// </summary>
    public bool AllowAutoRegistration { get; set; } = true;

    /// <summary>
    /// Default state token expiration in minutes.
    /// </summary>
    public int StateTokenExpirationMinutes { get; set; } = 10;

    /// <summary>
    /// Enable PKCE (Proof Key for Code Exchange) by default.
    /// </summary>
    public bool UsePkce { get; set; } = true;

    /// <summary>
    /// Frontend callback URL for SPA applications.
    /// After OAuth authentication, users are redirected here with the access token as a query parameter.
    /// Example: "http://localhost:3000/auth/callback" -> "http://localhost:3000/auth/callback?accessToken=..."
    /// </summary>
    public string? FrontendCallbackUrl { get; set; }
}
