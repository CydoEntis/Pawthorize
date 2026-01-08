using Pawthorize.Abstractions;
using Pawthorize.Sample.MinimalApi.Models;

namespace Pawthorize.Sample.MinimalApi.Repositories;

/// <summary>
/// In-memory implementation of external auth repository for demo purposes.
/// In production, use a database-backed implementation.
/// </summary>
public class InMemoryExternalAuthRepository : IExternalAuthRepository<User>
{
    private readonly List<ExternalIdentity> _externalIdentities = new();
    private readonly IUserRepository<User> _userRepository;

    public InMemoryExternalAuthRepository(IUserRepository<User> userRepository)
    {
        _userRepository = userRepository;
    }

    public Task<User?> FindByExternalProviderAsync(
        string provider,
        string providerId,
        CancellationToken cancellationToken = default)
    {
        var identity = _externalIdentities.FirstOrDefault(e =>
            e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase) &&
            e.ProviderId == providerId);

        if (identity == null)
            return Task.FromResult<User?>(null);

        return _userRepository.FindByIdAsync(identity.UserId, cancellationToken);
    }

    public Task LinkExternalProviderAsync(
        string userId,
        IExternalIdentity identity,
        CancellationToken cancellationToken = default)
    {
        var externalIdentity = new ExternalIdentity
        {
            UserId = userId,
            Provider = identity.Provider,
            ProviderId = identity.ProviderId,
            ProviderEmail = identity.ProviderEmail,
            ProviderUsername = identity.ProviderUsername,
            LinkedAt = identity.LinkedAt,
            Metadata = identity.Metadata
        };

        _externalIdentities.Add(externalIdentity);
        return Task.CompletedTask;
    }

    public Task UnlinkExternalProviderAsync(
        string userId,
        string provider,
        CancellationToken cancellationToken = default)
    {
        var identity = _externalIdentities.FirstOrDefault(e =>
            e.UserId == userId &&
            e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase));

        if (identity != null)
        {
            _externalIdentities.Remove(identity);
        }

        return Task.CompletedTask;
    }

    public Task<IEnumerable<IExternalIdentity>> GetLinkedProvidersAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        var identities = _externalIdentities
            .Where(e => e.UserId == userId)
            .Cast<IExternalIdentity>();

        return Task.FromResult(identities);
    }

    public Task<bool> IsProviderLinkedToAnotherUserAsync(
        string provider,
        string providerId,
        string currentUserId,
        CancellationToken cancellationToken = default)
    {
        var exists = _externalIdentities.Any(e =>
            e.Provider.Equals(provider, StringComparison.OrdinalIgnoreCase) &&
            e.ProviderId == providerId &&
            e.UserId != currentUserId);

        return Task.FromResult(exists);
    }
}
