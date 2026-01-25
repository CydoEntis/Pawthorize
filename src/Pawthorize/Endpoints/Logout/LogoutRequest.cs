namespace Pawthorize.Endpoints.Logout;

/// <summary>
/// Request model for logout.
/// </summary>
public class LogoutRequest
{
    public string RefreshToken { get; set; } = string.Empty;
}
