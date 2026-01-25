namespace Pawthorize.Services.Models;

/// <summary>
/// Result of successful authentication (login or registration).
/// Contains tokens but no user data (fetch user via /me endpoint).
/// </summary>
public class AuthResult
{
    /// <summary>
    /// JWT access token (short-lived, use for API requests)
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// Refresh token (long-lived, use to get new access tokens)
    /// Note: May be null if using HttpOnlyCookies strategy (token is in cookie)
    /// </summary>
    public string? RefreshToken { get; set; }

    /// <summary>
    /// When the access token expires (UTC)
    /// </summary>
    public DateTime AccessTokenExpiresAt { get; set; }

    /// <summary>
    /// When the refresh token expires (UTC)
    /// </summary>
    public DateTime RefreshTokenExpiresAt { get; set; }

    /// <summary>
    /// Token type (always "Bearer" for JWT)
    /// </summary>
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// Whether this is a "Remember Me" session with extended token lifetime.
    /// Used internally for cookie handling - not serialized to JSON response.
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public bool IsRememberedSession { get; set; } = false;
}