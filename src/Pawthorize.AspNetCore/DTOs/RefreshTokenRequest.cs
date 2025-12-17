namespace Pawthorize.AspNetCore.DTOs;

/// <summary>
/// Request model for refreshing access token.
/// </summary>
public class RefreshTokenRequest
{
    /// <summary>
    /// Refresh token (long-lived token from database)
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
}