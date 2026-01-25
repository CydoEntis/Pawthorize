using System.Collections.Concurrent;
using Pawthorize.Abstractions;
using Pawthorize.Services;

namespace Pawthorize.Sample.MinimalApi.Repositories;

public class InMemoryTokenRepository : IEmailChangeTokenRepository
{
    private readonly ConcurrentDictionary<string, StoredToken> _tokens = new();
    private readonly ConcurrentDictionary<string, string> _emailChangeTokens = new(); // tokenHash -> newEmail

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

    public Task StoreEmailChangeTokenAsync(
        string userId,
        string tokenHash,
        string newEmail,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        var storedToken = new StoredToken
        {
            TokenHash = tokenHash,
            UserId = userId,
            Type = TokenType.EmailChange,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = expiresAt,
            IsInvalidated = false
        };

        _tokens[tokenHash] = storedToken;
        _emailChangeTokens[tokenHash] = newEmail;
        return Task.CompletedTask;
    }

    public Task<EmailChangeTokenInfo?> ConsumeEmailChangeTokenAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        if (!_tokens.TryGetValue(tokenHash, out var storedToken))
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        if (storedToken.Type != TokenType.EmailChange)
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        if (storedToken.IsInvalidated)
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        if (!_emailChangeTokens.TryGetValue(tokenHash, out var newEmail))
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        // Invalidate the token atomically
        storedToken.IsInvalidated = true;
        _emailChangeTokens.TryRemove(tokenHash, out _);

        var tokenInfo = new EmailChangeTokenInfo(
            storedToken.UserId,
            newEmail,
            storedToken.CreatedAt,
            storedToken.ExpiresAt);

        return Task.FromResult<EmailChangeTokenInfo?>(tokenInfo);
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
