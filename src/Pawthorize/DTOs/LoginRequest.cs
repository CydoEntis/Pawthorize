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
}