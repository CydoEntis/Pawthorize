namespace Pawthorize.DTOs;

/// <summary>
/// Request model for setting a password (for OAuth-only users who don't have a password yet).
/// </summary>
public class SetPasswordRequest
{
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
