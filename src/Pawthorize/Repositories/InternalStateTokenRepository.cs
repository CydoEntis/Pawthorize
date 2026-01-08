using System.Collections.Concurrent;
using Pawthorize.Abstractions;
using Pawthorize.Models;

namespace Pawthorize.Repositories;

/// <summary>
/// Internal in-memory state token repository.
/// For production, users should implement IStateTokenRepository with database/cache storage.
/// This is a fallback that works but won't scale across multiple servers.
/// </summary>
internal class InternalStateTokenRepository : IStateTokenRepository<InternalStateToken>
{
    private readonly ConcurrentDictionary<string, InternalStateToken> _tokens = new();

    public Task CreateAsync(InternalStateToken stateToken, CancellationToken cancellationToken = default)
    {
        _tokens[stateToken.Token] = stateToken;
        return Task.CompletedTask;
    }

    public Task<InternalStateToken?> FindByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        _tokens.TryGetValue(token, out var stateToken);
        return Task.FromResult(stateToken);
    }

    public Task DeleteAsync(string token, CancellationToken cancellationToken = default)
    {
        _tokens.TryRemove(token, out _);
        return Task.CompletedTask;
    }

    public Task DeleteExpiredAsync(CancellationToken cancellationToken = default)
    {
        var now = DateTime.UtcNow;
        var expiredTokens = _tokens
            .Where(kvp => kvp.Value.ExpiresAt < now)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var token in expiredTokens)
        {
            _tokens.TryRemove(token, out _);
        }

        return Task.CompletedTask;
    }
}
