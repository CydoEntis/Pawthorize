namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for resetting password with a reset token.
/// </summary>
public class ResetPasswordRequest
{
    /// <summary>
    /// Password reset token (from email link)
    /// </summary>
    public string Token { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
