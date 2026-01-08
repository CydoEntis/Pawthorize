namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for managing external OAuth provider linkages.
/// </summary>
/// <typeparam name="TUser">The user entity type.</typeparam>
public interface IExternalAuthRepository<TUser> where TUser : class, IAuthenticatedUser
{
    /// <summary>
    /// Finds a user by their external provider ID.
    /// </summary>
    /// <param name="provider">The provider name (e.g., "google").</param>
    /// <param name="providerId">The user's ID from the provider.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user if found, null otherwise.</returns>
    Task<TUser?> FindByExternalProviderAsync(
        string provider,
        string providerId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Links an external provider to a user account.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="identity">The external identity to link.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task LinkExternalProviderAsync(
        string userId,
        IExternalIdentity identity,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Unlinks an external provider from a user account.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="provider">The provider name to unlink.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task UnlinkExternalProviderAsync(
        string userId,
        string provider,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all external providers linked to a user.
    /// </summary>
    /// <param name="userId">The user's ID.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of linked external identities.</returns>
    Task<IEnumerable<IExternalIdentity>> GetLinkedProvidersAsync(
        string userId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if a provider is linked to a different user.
    /// </summary>
    /// <param name="provider">The provider name.</param>
    /// <param name="providerId">The provider user ID.</param>
    /// <param name="currentUserId">The current user's ID to exclude.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if linked to another user, false otherwise.</returns>
    Task<bool> IsProviderLinkedToAnotherUserAsync(
        string provider,
        string providerId,
        string currentUserId,
        CancellationToken cancellationToken = default);
}
