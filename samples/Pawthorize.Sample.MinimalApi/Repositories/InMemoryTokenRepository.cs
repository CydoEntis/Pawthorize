using System.Collections.Concurrent;
using Pawthorize.Abstractions;

namespace Pawthorize.Sample.MinimalApi.Repositories;

public class InMemoryTokenRepository : ITokenRepository
{
    private readonly ConcurrentDictionary<string, StoredToken> _tokens = new();

    public Task StoreTokenAsync(
        string userId,
        string tokenHash,
        TokenType type,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        var storedToken = new StoredToken
        {
            TokenHash = tokenHash,
            UserId = userId,
            Type = type,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            IsInvalidated = false
        };

        _tokens[tokenHash] = storedToken;
        return Task.CompletedTask;
    }

    public Task<TokenInfo?> ValidateTokenAsync(
        string tokenHash,
        TokenType type,
        CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(tokenHash, out var storedToken))
            return Task.FromResult<TokenInfo?>(null);

        if (storedToken.Type != type)
            return Task.FromResult<TokenInfo?>(null);

        if (storedToken.IsInvalidated)
            return Task.FromResult<TokenInfo?>(null);

        var tokenInfo = new TokenInfo(
            storedToken.UserId,
            storedToken.CreatedAt,
            storedToken.ExpiresAt);

        return Task.FromResult<TokenInfo?>(tokenInfo);
    }

    public Task<TokenInfo?> ConsumeTokenAsync(
        string tokenHash,
        TokenType type,
        CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(tokenHash, out var storedToken))
            return Task.FromResult<TokenInfo?>(null);

        if (storedToken.Type != type)
            return Task.FromResult<TokenInfo?>(null);

        if (storedToken.IsInvalidated)
            return Task.FromResult<TokenInfo?>(null);

        // Invalidate the token atomically
        storedToken.IsInvalidated = true;

        var tokenInfo = new TokenInfo(
            storedToken.UserId,
            storedToken.CreatedAt,
            storedToken.ExpiresAt);

        return Task.FromResult<TokenInfo?>(tokenInfo);
    }

    public Task InvalidateTokenAsync(
        string tokenHash,
        TokenType type,
        CancellationToken cancellationToken = default)
    {
        if (_tokens.TryGetValue(tokenHash, out var storedToken) && storedToken.Type == type)
        {
            storedToken.IsInvalidated = true;
        }

        return Task.CompletedTask;
    }

    public Task InvalidateAllTokensForUserAsync(
        string userId,
        TokenType type,
        CancellationToken cancellationToken = default)
    {
        foreach (var kvp in _tokens.Where(x => x.Value.UserId == userId && x.Value.Type == type))
        {
            kvp.Value.IsInvalidated = true;
        }

        return Task.CompletedTask;
    }

    private class StoredToken
    {
        public string TokenHash { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public TokenType Type { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsInvalidated { get; set; }
    }
}
