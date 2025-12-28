using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryRefreshTokenRepository : IRefreshTokenRepository
{
    private readonly List<RefreshTokenInfo> _tokens = new();

    public Task StoreAsync(
        string token,
        string userId,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        _tokens.Add(new RefreshTokenInfo
        {
            Token = token,
            UserId = userId,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow,
            IsRevoked = false
        });
        return Task.CompletedTask;
    }

    public Task<RefreshTokenInfo?> ValidateAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var refreshToken = _tokens.FirstOrDefault(t => t.Token == token);
        return Task.FromResult(refreshToken);
    }

    public Task RevokeAsync(
        string token,
        CancellationToken cancellationToken = default)
    {
        var refreshToken = _tokens.FirstOrDefault(t => t.Token == token);
        if (refreshToken != null)
            refreshToken.IsRevoked = true;

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
            .ToList();

        return Task.FromResult<IEnumerable<RefreshTokenInfo>>(activeTokens);
    }

    public Task RevokeAllExceptAsync(
        string userId,
        string exceptToken,
        CancellationToken cancellationToken = default)
    {
        foreach (var token in _tokens.Where(t => t.UserId == userId && t.Token != exceptToken))
        {
            token.IsRevoked = true;
        }
        return Task.CompletedTask;
    }

    public void Clear() => _tokens.Clear();
}
