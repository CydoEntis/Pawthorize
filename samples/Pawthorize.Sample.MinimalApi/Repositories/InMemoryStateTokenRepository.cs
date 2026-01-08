using Pawthorize.Abstractions;
using Pawthorize.Sample.MinimalApi.Models;

namespace Pawthorize.Sample.MinimalApi.Repositories;

/// <summary>
/// In-memory implementation of state token repository for demo purposes.
/// In production, use a database or distributed cache.
/// </summary>
public class InMemoryStateTokenRepository : IStateTokenRepository<StateToken>
{
    private readonly List<StateToken> _stateTokens = new();
    private readonly object _lock = new();

    public Task CreateAsync(StateToken stateToken, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            _stateTokens.Add(stateToken);
        }
        return Task.CompletedTask;
    }

    public Task<StateToken?> FindByTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var stateToken = _stateTokens.FirstOrDefault(t => t.Token == token);
            return Task.FromResult(stateToken);
        }
    }

    public Task DeleteAsync(string token, CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var stateToken = _stateTokens.FirstOrDefault(t => t.Token == token);
            if (stateToken != null)
            {
                _stateTokens.Remove(stateToken);
            }
        }
        return Task.CompletedTask;
    }

    public Task DeleteExpiredAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            var now = DateTime.UtcNow;
            _stateTokens.RemoveAll(t => t.ExpiresAt < now);
        }
        return Task.CompletedTask;
    }
}
