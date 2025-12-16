namespace Pawthorize.Core.Models;

/// <summary>
/// Configuration settings for JWT token generation and validation.
/// Bound from appsettings.json "Jwt" section.
/// </summary>
/// <remarks>
/// Example appsettings.json:
/// {
///   "Jwt": {
///     "Secret": "your-super-secret-key-min-32-chars",
///     "Issuer": "MyApp",
///     "Audience": "MyApp",
///     "AccessTokenLifetimeMinutes": 15,
///     "RefreshTokenLifetimeDays": 7
///   }
/// }
/// </remarks>
public class JwtSettings
{
    /// <summary>
    /// Configuration section name for binding
    /// </summary>
    public const string SectionName = "Jwt";
    
    /// <summary>
    /// Secret key used to sign JWT tokens.
    /// MUST be at least 32 characters for HS256 algorithm.
    /// Should be stored in environment variables or Azure Key Vault in production.
    /// </summary>
    /// <example>"my-super-secret-key-that-is-at-least-32-characters-long"</example>
    public string? Secret { get; set; }
    
    /// <summary>
    /// The issuer claim (iss) identifies who issued the token.
    /// Typically your application name or domain.
    /// </summary>
    /// <example>"Pawthorize", "myapp.com"</example>
    public string Issuer { get; set; } = "Pawthorize";
    
    /// <summary>
    /// The audience claim (aud) identifies who the token is intended for.
    /// Typically your application name or API identifier.
    /// </summary>
    /// <example>"Pawthorize", "myapp-api"</example>
    public string Audience { get; set; } = "Pawthorize";
    
    /// <summary>
    /// How long access tokens are valid (in minutes).
    /// Default: 15 minutes (recommended for security)
    /// </summary>
    /// <remarks>
    /// Short-lived tokens are more secure because:
    /// - Less time for attackers to use stolen tokens
    /// - Reduced window of exposure
    /// - Forces regular token refresh (which can be revoked)
    /// </remarks>
    public int AccessTokenLifetimeMinutes { get; set; } = 15;
    
    /// <summary>
    /// How long refresh tokens are valid (in days).
    /// Default: 7 days
    /// </summary>
    /// <remarks>
    /// Longer than access tokens because:
    /// - Stored securely (httpOnly cookie or secure storage)
    /// - Can be revoked in database
    /// - Less frequently transmitted
    /// </remarks>
    public int RefreshTokenLifetimeDays { get; set; } = 7;
}