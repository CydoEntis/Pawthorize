namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for logout.
/// </summary>
public class LogoutRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}