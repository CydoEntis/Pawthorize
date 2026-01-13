using Pawthorize.Abstractions;
using Pawthorize.Models;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly List<StoredRefreshToken> _tokens = new();

    public Task StoreAsync(
        string tokenHash,
        string userId,
        DateTime expiresAt,
        string? deviceInfo = null,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        _tokens.Add(new StoredRefreshToken
        {
            TokenHash = tokenHash,
            UserId = userId,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
            IsRevoked = false,
            DeviceInfo = deviceInfo,
            IpAddress = ipAddress,
            LastActivityAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public Task<RefreshTokenInfo?> ValidateAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t => t.TokenHash == tokenHash);
        if (storedToken == null)
            return Task.FromResult<RefreshTokenInfo?>(null);

        var tokenInfo = new RefreshTokenInfo(
            storedToken.TokenHash,
            storedToken.UserId,
            storedToken.ExpiresAt,
            storedToken.IsRevoked,
            storedToken.CreatedAt,
            storedToken.DeviceInfo,
            storedToken.IpAddress,
            storedToken.LastActivityAt);

        return Task.FromResult<RefreshTokenInfo?>(tokenInfo);
    }

    public Task RevokeAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t => t.TokenHash == tokenHash);
        if (storedToken != null)
            storedToken.IsRevoked = true;

        return Task.CompletedTask;
    }

    public Task RevokeAllForUserAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        foreach (var token in _tokens.Where(t => t.UserId == userId))
        {
            token.IsRevoked = true;
        }
        return Task.CompletedTask;
    }

    public Task<IEnumerable<RefreshTokenInfo>> GetAllActiveAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        var activeTokens = _tokens
            .Where(t => t.UserId == userId && !t.IsRevoked && t.ExpiresAt > DateTime.UtcNow)
            .Select(t => new RefreshTokenInfo(
                t.TokenHash,
                t.UserId,
                t.ExpiresAt,
                t.IsRevoked,
                t.CreatedAt,
                t.DeviceInfo,
                t.IpAddress,
                t.LastActivityAt))
            .ToList();

        return Task.FromResult<IEnumerable<RefreshTokenInfo>>(activeTokens);
    }

    public Task RevokeAllExceptAsync(
        string userId,
        string exceptTokenHash,
        CancellationToken cancellationToken = default)
    {
        foreach (var token in _tokens.Where(t => t.UserId == userId && t.TokenHash != exceptTokenHash))
        {
            token.IsRevoked = true;
        }
        return Task.CompletedTask;
    }

    public Task UpdateLastActivityAsync(
        string tokenHash,
        DateTime lastActivityAt,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t => t.TokenHash == tokenHash);
        if (storedToken != null)
        {
            storedToken.LastActivityAt = lastActivityAt;
        }
        return Task.CompletedTask;
    }

    public void Clear() => _tokens.Clear();

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
    }
}
