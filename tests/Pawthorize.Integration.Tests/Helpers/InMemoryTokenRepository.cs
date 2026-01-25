using Pawthorize.Abstractions;
using Pawthorize.Services;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryTokenRepository : IEmailChangeTokenRepository
{
    private readonly List<StoredToken> _tokens = new();
    private readonly Dictionary<string, string> _emailChangeTokens = new(); // tokenHash -> newEmail

    public Task StoreTokenAsync(
        string userId,
        string tokenHash,
        TokenType tokenType,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        _tokens.Add(new StoredToken
        {
            UserId = userId,
            TokenHash = tokenHash,
            TokenType = tokenType,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public Task<TokenInfo?> ValidateTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.TokenHash == tokenHash &&
            t.TokenType == tokenType &&
            !t.IsInvalidated);

        if (storedToken == null)
            return Task.FromResult<TokenInfo?>(null);

        return Task.FromResult<TokenInfo?>(new TokenInfo(
            storedToken.UserId,
            storedToken.CreatedAt,
            storedToken.ExpiresAt));
    }

    public Task<TokenInfo?> ConsumeTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.TokenHash == tokenHash &&
            t.TokenType == tokenType &&
            !t.IsInvalidated);

        if (storedToken == null)
            return Task.FromResult<TokenInfo?>(null);

        storedToken.IsInvalidated = true;

        return Task.FromResult<TokenInfo?>(new TokenInfo(
            storedToken.UserId,
            storedToken.CreatedAt,
            storedToken.ExpiresAt));
    }

    public Task InvalidateTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.TokenHash == tokenHash &&
            t.TokenType == tokenType);

        if (storedToken != null)
            storedToken.IsInvalidated = true;

        return Task.CompletedTask;
    }

    public Task InvalidateAllTokensForUserAsync(
        string userId,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        foreach (var token in _tokens.Where(t => t.UserId == userId && t.TokenType == tokenType))
        {
            token.IsInvalidated = true;
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
        _tokens.Add(new StoredToken
        {
            UserId = userId,
            TokenHash = tokenHash,
            TokenType = TokenType.EmailChange,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow
        });
        _emailChangeTokens[tokenHash] = newEmail;
        return Task.CompletedTask;
    }

    public Task<EmailChangeTokenInfo?> ConsumeEmailChangeTokenAsync(
        string tokenHash,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.TokenHash == tokenHash &&
            t.TokenType == TokenType.EmailChange &&
            !t.IsInvalidated);

        if (storedToken == null)
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        if (!_emailChangeTokens.TryGetValue(tokenHash, out var newEmail))
            return Task.FromResult<EmailChangeTokenInfo?>(null);

        storedToken.IsInvalidated = true;
        _emailChangeTokens.Remove(tokenHash);

        return Task.FromResult<EmailChangeTokenInfo?>(new EmailChangeTokenInfo(
            storedToken.UserId,
            newEmail,
            storedToken.CreatedAt,
            storedToken.ExpiresAt));
    }

    public void Clear()
    {
        _tokens.Clear();
        _emailChangeTokens.Clear();
    }

    private class StoredToken
    {
        public string UserId { get; set; } = string.Empty;
        public string TokenHash { get; set; } = string.Empty;
        public TokenType TokenType { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsInvalidated { get; set; }
    }
}
