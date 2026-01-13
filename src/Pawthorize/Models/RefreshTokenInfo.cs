namespace Pawthorize.Models;

/// <summary>
/// Information about a validated refresh token (immutable).
/// Returned by IRefreshTokenRepository.ValidateAsync()
/// </summary>
public record RefreshTokenInfo(
    string TokenHash,
    string UserId,
    DateTime ExpiresAt,
    bool IsRevoked,
    DateTime? CreatedAt = null,
    string? DeviceInfo = null,
    string? IpAddress = null,
    DateTime? LastActivityAt = null)
{
    /// <summary>
    /// Check if token has expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiresAt;
}