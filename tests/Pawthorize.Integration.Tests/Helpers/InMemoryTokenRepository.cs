using Pawthorize.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryTokenRepository : ITokenRepository
{
    private readonly List<StoredToken> _tokens = new();

    public Task StoreTokenAsync(
        string userId,
        string token,
        TokenType tokenType,
        DateTime expiresAt,
        CancellationToken cancellationToken = default)
    {
        _tokens.Add(new StoredToken
        {
            UserId = userId,
            Token = token,
            TokenType = tokenType,
            ExpiresAt = expiresAt,
            CreatedAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public Task<TokenInfo?> ValidateTokenAsync(
        string token,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.Token == token &&
            t.TokenType == tokenType &&
            !t.IsInvalidated);

        if (storedToken == null)
            return Task.FromResult<TokenInfo?>(null);

        return Task.FromResult<TokenInfo?>(new TokenInfo
        {
            UserId = storedToken.UserId,
            CreatedAt = storedToken.CreatedAt,
            ExpiresAt = storedToken.ExpiresAt
        });
    }

    public Task InvalidateTokenAsync(
        string token,
        TokenType tokenType,
        CancellationToken cancellationToken = default)
    {
        var storedToken = _tokens.FirstOrDefault(t =>
            t.Token == token &&
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

    public void Clear() => _tokens.Clear();

    private class StoredToken
    {
        public string UserId { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public TokenType TokenType { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsInvalidated { get; set; }
    }
}
