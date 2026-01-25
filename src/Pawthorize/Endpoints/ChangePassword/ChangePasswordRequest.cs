namespace Pawthorize.Endpoints.ChangePassword;

/// <summary>
/// Request model for changing password (for authenticated users).
/// </summary>
public class ChangePasswordRequest
{
    public string CurrentPassword { get; set; } = string.Empty;
    public string NewPassword { get; set; } = string.Empty;
    public string ConfirmPassword { get; set; } = string.Empty;
}
