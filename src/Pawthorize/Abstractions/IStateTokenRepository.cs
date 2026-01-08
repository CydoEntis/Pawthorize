namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for storing OAuth state tokens temporarily.
/// </summary>
/// <typeparam name="TStateToken">The state token entity type.</typeparam>
public interface IStateTokenRepository<TStateToken> where TStateToken : class, IStateToken
{
    /// <summary>
    /// Stores a state token.
    /// </summary>
    Task CreateAsync(TStateToken stateToken, CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds a state token by its value.
    /// </summary>
    Task<TStateToken?> FindByTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes a state token (consumed after use).
    /// </summary>
    Task DeleteAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Deletes expired state tokens (cleanup).
    /// </summary>
    Task DeleteExpiredAsync(CancellationToken cancellationToken = default);
}
