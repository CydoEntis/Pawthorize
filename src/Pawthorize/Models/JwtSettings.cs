namespace Pawthorize.Models;

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
///     "RefreshTokenLifetimeDaysRemembered": 30,
///     "RefreshTokenLifetimeHoursDefault": 24,
///     "UseSessionCookieWhenNotRemembered": false
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
    /// How long refresh tokens are valid (in days) when "Remember Me" is selected.
    /// Default: 30 days
    /// </summary>
    /// <remarks>
    /// Used when the user explicitly opts into a longer session.
    /// These sessions persist across browser restarts and are suitable for trusted devices.
    /// </remarks>
    public int RefreshTokenLifetimeDaysRemembered { get; set; } = 30;

    /// <summary>
    /// How long refresh tokens are valid (in hours) when "Remember Me" is NOT selected.
    /// Default: 24 hours
    /// </summary>
    /// <remarks>
    /// Shorter lifetime for sessions where the user didn't opt into "remember me".
    /// This is ignored if UseSessionCookieWhenNotRemembered is true.
    /// </remarks>
    public int RefreshTokenLifetimeHoursDefault { get; set; } = 24;

    /// <summary>
    /// Whether to use session cookies (no expiry) when "Remember Me" is NOT selected.
    /// Default: false
    /// </summary>
    /// <remarks>
    /// When true, the refresh token cookie will not have an Expires attribute,
    /// causing it to be deleted when the browser closes.
    /// When false, uses RefreshTokenLifetimeHoursDefault for the cookie expiry.
    /// Note: Session cookies can be lost if the browser crashes or is force-closed.
    /// </remarks>
    public bool UseSessionCookieWhenNotRemembered { get; set; } = false;

    /// <summary>
    /// Get access token lifetime as TimeSpan (computed from minutes)
    /// </summary>
    public TimeSpan AccessTokenLifetime => TimeSpan.FromMinutes(AccessTokenLifetimeMinutes);

    /// <summary>
    /// Get refresh token lifetime for "Remember Me" sessions as TimeSpan (computed from days)
    /// </summary>
    public TimeSpan RefreshTokenLifetimeRemembered => TimeSpan.FromDays(RefreshTokenLifetimeDaysRemembered);

    /// <summary>
    /// Get refresh token lifetime for default sessions as TimeSpan (computed from hours)
    /// </summary>
    public TimeSpan RefreshTokenLifetimeDefault => TimeSpan.FromHours(RefreshTokenLifetimeHoursDefault);

    /// <summary>
    /// Get refresh token lifetime based on remember me preference.
    /// </summary>
    /// <param name="rememberMe">Whether the user selected "Remember Me"</param>
    /// <returns>The appropriate refresh token lifetime</returns>
    public TimeSpan GetRefreshTokenLifetime(bool rememberMe) =>
        rememberMe ? RefreshTokenLifetimeRemembered : RefreshTokenLifetimeDefault;
}