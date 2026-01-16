using System.Text.Json.Serialization;

namespace Pawthorize.DTOs;

/// <summary>
/// Request model for user login.
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// User's email address for login.
    /// Pawthorize is opinionated and uses email-only authentication.
    /// </summary>
    /// <example>john@example.com</example>
    [JsonPropertyName("email")]
    public string Email { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Whether to create a long-lived session ("remember me" functionality).
    /// When true, the refresh token will have a longer expiry (default 30 days).
    /// When false, the refresh token will have a shorter expiry (default 24 hours) or use a session cookie.
    /// </summary>
    /// <example>true</example>
    [JsonPropertyName("rememberMe")]
    public bool RememberMe { get; set; } = false;
}