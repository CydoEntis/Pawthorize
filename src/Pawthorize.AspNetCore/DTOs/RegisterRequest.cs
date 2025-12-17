namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for user registration.
/// </summary>
public class RegisterRequest
{
    /// <summary>
    /// User's email address
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// User's password (plaintext - will be hashed)
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// User's full name (optional)
    /// </summary>
    public string? Name { get; set; }
}