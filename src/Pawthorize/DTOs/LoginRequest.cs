using System.Text.Json.Serialization;

namespace Pawthorize.DTOs;

/// <summary>
/// Request model for user login.
/// </summary>
public class LoginRequest
{
    /// <summary>
    /// Login identifier.
    /// The type of identifier depends on your Pawthorize configuration:
    /// - Email login (default): provide email address
    /// - Username login: provide username
    /// - Phone login: provide phone number
    /// </summary>
    /// <example>john@example.com</example>
    /// <example>johndoe</example>
    [JsonPropertyName("identifier")]
    public string Identifier { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;
}