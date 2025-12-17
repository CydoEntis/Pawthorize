namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for logout.
/// </summary>
public class LogoutRequest
{
    /// <summary>
    /// Refresh token to revoke
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}