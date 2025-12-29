namespace Pawthorize.DTOs;

/// <summary>
/// Request model for forgot password (request password reset email).
/// </summary>
public class ForgotPasswordRequest
{
    public string Email { get; set; } = string.Empty;
}
