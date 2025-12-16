using Pawthorize.Core.Models;

namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Repository for refresh token storage and validation.
/// </summary>
public interface IRefreshTokenRepository
{
    Task StoreAsync(string token, string userId, DateTime expiresAt, CancellationToken cancellationToken = default);
    Task<RefreshTokenInfo?> ValidateAsync(string token, CancellationToken cancellationToken = default);
    Task RevokeAsync(string token, CancellationToken cancellationToken = default);
    Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default);
}