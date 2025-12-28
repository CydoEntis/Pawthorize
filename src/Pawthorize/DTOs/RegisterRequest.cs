namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for user registration.
/// </summary>
public class RegisterRequest
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string? Name { get; set; }
}