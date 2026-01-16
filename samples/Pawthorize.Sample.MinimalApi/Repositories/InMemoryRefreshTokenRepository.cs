using Pawthorize.Abstractions;
using Pawthorize.Models;

namespace Pawthorize.Sample.MinimalApi.Repositories;

/// <summary>
/// In-memory refresh token repository for testing.
/// DO NOT USE IN PRODUCTION.
/// </summary>
public class InMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly Dictionary<string, StoredRefreshToken> _tokens = new();

    /// <summary>
    /// Stores a refresh token hash in the repository.
    /// </summary>
    /// <param name="tokenHash">The refresh token hash to store.</param>
    /// <param name="userId">The user ID associated with the token.</param>
    /// <param name="expiresAt">The expiration date and time of the token.</param>
    /// <param name="deviceInfo">Optional device/browser information.</param>
    /// <param name="ipAddress">Optional IP address.</param>
    /// <param name="isRememberedSession">Whether this is a "Remember Me" session.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task StoreAsync(string tokenHash, string userId, DateTime expiresAt, string? deviceInfo = null, string? ipAddress = null,
        bool isRememberedSession = false, CancellationToken cancellationToken = default)
    {
        _tokens[tokenHash] = new StoredRefreshToken
        {
            TokenHash = tokenHash,
            UserId = userId,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
            IsRevoked = false,
            DeviceInfo = deviceInfo,
            IpAddress = ipAddress,
            LastActivityAt = DateTime.UtcNow,
            IsRememberedSession = isRememberedSession
        };
        return Task.CompletedTask;
    }

    /// <summary>
    /// Validates a refresh token hash and returns its information if valid.
    /// </summary>
    /// <param name="tokenHash">The refresh token hash to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token information if valid, null otherwise.</returns>
    public Task<RefreshTokenInfo?> ValidateAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(tokenHash, out var storedToken))
            return Task.FromResult<RefreshTokenInfo?>(null);

        if (storedToken.IsRevoked || storedToken.ExpiresAt < DateTime.UtcNow)
            return Task.FromResult<RefreshTokenInfo?>(null);

        var tokenInfo = new RefreshTokenInfo(
            storedToken.TokenHash,
            storedToken.UserId,
            storedToken.ExpiresAt,
            storedToken.IsRevoked,
            storedToken.CreatedAt,
            storedToken.DeviceInfo,
            storedToken.IpAddress,
            storedToken.LastActivityAt,
            storedToken.IsRememberedSession);

        return Task.FromResult<RefreshTokenInfo?>(tokenInfo);
    }

    /// <summary>
    /// Revokes a specific refresh token hash.
    /// </summary>
    /// <param name="tokenHash">The refresh token hash to revoke.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RevokeAsync(string tokenHash, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(tokenHash, out var storedToken))
        {
            storedToken.IsRevoked = true;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Revokes all refresh tokens for a specific user.
    /// </summary>
    /// <param name="userId">The user ID whose tokens should be revoked.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default)
    {
        foreach (var storedToken in _tokens.Values.Where(t => t.UserId == userId))
        {
            storedToken.IsRevoked = true;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Gets all active (non-revoked, non-expired) refresh tokens for a specific user.
    /// </summary>
    /// <param name="userId">The user ID whose active tokens to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of active refresh token information.</returns>
    public Task<IEnumerable<RefreshTokenInfo>> GetAllActiveAsync(string userId, CancellationToken cancellationToken = default)
    {
        var activeTokens = _tokens.Values
            .Where(t => t.UserId == userId && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .Select(t => new RefreshTokenInfo(
                t.TokenHash,
                t.UserId,
                t.ExpiresAt,
                t.IsRevoked,
                t.CreatedAt,
                t.DeviceInfo,
                t.IpAddress,
                t.LastActivityAt,
                t.IsRememberedSession))
            .ToList();

        return Task.FromResult<IEnumerable<RefreshTokenInfo>>(activeTokens);
    }

    /// <summary>
    /// Revokes all refresh tokens for a user except the specified token hash.
    /// </summary>
    /// <param name="userId">The user ID whose tokens should be revoked.</param>
    /// <param name="exceptTokenHash">The token hash to keep active (current session).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RevokeAllExceptAsync(string userId, string exceptTokenHash, CancellationToken cancellationToken = default)
    {
        foreach (var storedToken in _tokens.Values.Where(t => t.UserId == userId && t.TokenHash != exceptTokenHash))
        {
            storedToken.IsRevoked = true;
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Updates the last activity timestamp for a refresh token.
    /// </summary>
    /// <param name="tokenHash">The token hash to update.</param>
    /// <param name="lastActivityAt">The timestamp of the last activity.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task UpdateLastActivityAsync(string tokenHash, DateTime lastActivityAt, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(tokenHash, out var storedToken))
        {
            storedToken.LastActivityAt = lastActivityAt;
        }

        return Task.CompletedTask;
    }

    private class StoredRefreshToken
    {
        public string TokenHash { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
        public bool IsRevoked { get; set; }
        public string? DeviceInfo { get; set; }
        public string? IpAddress { get; set; }
        public DateTime? LastActivityAt { get; set; }
        public bool IsRememberedSession { get; set; }
    }
}