using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;

namespace Pawthorize.Sample.MinimalApi.Repositories;

/// <summary>
/// In-memory refresh token repository for testing.
/// DO NOT USE IN PRODUCTION.
/// </summary>
public class InMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly Dictionary<string, RefreshTokenInfo> _tokens = new();

    /// <summary>
    /// Stores a refresh token in the repository.
    /// </summary>
    /// <param name="token">The refresh token to store.</param>
    /// <param name="userId">The user ID associated with the token.</param>
    /// <param name="expiresAt">The expiration date and time of the token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task StoreAsync(string token, string userId, DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        _tokens[token] = new RefreshTokenInfo
        {
            Token = token,
            UserId = userId,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
            IsRevoked = false
        };
        return Task.CompletedTask;
    }

    /// <summary>
    /// Validates a refresh token and returns its information if valid.
    /// </summary>
    /// <param name="token">The refresh token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token information if valid, null otherwise.</returns>
    public Task<RefreshTokenInfo?> ValidateAsync(string token, CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(token, out var tokenInfo))
            return Task.FromResult<RefreshTokenInfo?>(null);

        if (tokenInfo.IsRevoked || tokenInfo.ExpiresAt < DateTime.UtcNow)
            return Task.FromResult<RefreshTokenInfo?>(null);

        return Task.FromResult<RefreshTokenInfo?>(tokenInfo);
    }

    /// <summary>
    /// Revokes a specific refresh token.
    /// </summary>
    /// <param name="token">The refresh token to revoke.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task RevokeAsync(string token, CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(token, out var tokenInfo))
        {
            tokenInfo.IsRevoked = true;
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
        foreach (var tokenInfo in _tokens.Values.Where(t => t.UserId == userId))
        {
            tokenInfo.IsRevoked = true;
        }

        return Task.CompletedTask;
    }
}