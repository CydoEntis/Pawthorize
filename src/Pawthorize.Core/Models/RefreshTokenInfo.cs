namespace Pawthorize.Core.Models;

/// <summary>
/// Information about a validated refresh token.
/// Returned by IRefreshTokenRepository.ValidateAsync()
/// </summary>
public class RefreshTokenInfo
{
    /// <summary>
    /// User ID this token belongs to
    /// </summary>
    public string UserId { get; set; } = string.Empty;
    
    /// <summary>
    /// When this token expires (UTC)
    /// </summary>
    public DateTime ExpiresAt { get; set; }
    
    /// <summary>
    /// Check if token has expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
    
    /// <summary>
    /// When this token was created (optional, for auditing)
    /// </summary>
    public DateTime? CreatedAt { get; set; }
    
    /// <summary>
    /// Device/client info (optional, for security)
    /// Example: "Chrome on Windows", "iOS App"
    /// </summary>
    public string? DeviceInfo { get; set; }
}