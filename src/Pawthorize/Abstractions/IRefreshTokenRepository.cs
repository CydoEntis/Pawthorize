using Pawthorize.Models;

namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for refresh token storage and validation.
/// </summary>
public interface IRefreshTokenRepository
{
    /// <summary>
    /// Stores a refresh token in the repository.
    /// </summary>
    /// <param name="token">The refresh token to store.</param>
    /// <param name="userId">The user ID associated with the token.</param>
    /// <param name="expiresAt">The expiration date and time of the token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task StoreAsync(string token, string userId, DateTime expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a refresh token and returns its information if valid.
    /// </summary>
    /// <param name="token">The refresh token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token information if valid, null otherwise.</returns>
    Task<RefreshTokenInfo?> ValidateAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a specific refresh token.
    /// </summary>
    /// <param name="token">The refresh token to revoke.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all refresh tokens for a specific user.
    /// </summary>
    /// <param name="userId">The user ID whose tokens should be revoked.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAllForUserAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets all active (non-revoked, non-expired) refresh tokens for a specific user.
    /// Used for session management (listing active sessions).
    /// </summary>
    /// <param name="userId">The user ID whose active tokens to retrieve.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Collection of active refresh token information.</returns>
    Task<IEnumerable<RefreshTokenInfo>> GetAllActiveAsync(string userId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes all refresh tokens for a user except the specified token.
    /// Used for "logout all other devices" functionality.
    /// </summary>
    /// <param name="userId">The user ID whose tokens should be revoked.</param>
    /// <param name="exceptToken">The token to keep active (current session).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAllExceptAsync(string userId, string exceptToken, CancellationToken cancellationToken = default);
}