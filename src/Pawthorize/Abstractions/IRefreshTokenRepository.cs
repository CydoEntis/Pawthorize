using Pawthorize.Models;

namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for refresh token storage and validation.
/// IMPORTANT: All tokens are hashed before storage for security.
/// </summary>
public interface IRefreshTokenRepository
{
    /// <summary>
    /// Stores a refresh token hash in the repository.
    /// The framework hashes tokens before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the refresh token to store.</param>
    /// <param name="userId">The user ID associated with the token.</param>
    /// <param name="expiresAt">The expiration date and time of the token.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task StoreAsync(string tokenHash, string userId, DateTime expiresAt, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validates a refresh token hash and returns its information if valid.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the refresh token to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Token information if valid, null otherwise.</returns>
    Task<RefreshTokenInfo?> ValidateAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a specific refresh token hash.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the refresh token to revoke.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAsync(string tokenHash, CancellationToken cancellationToken = default);

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
    /// Revokes all refresh tokens for a user except the specified token hash.
    /// Used for "logout all other devices" functionality.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="userId">The user ID whose tokens should be revoked.</param>
    /// <param name="exceptTokenHash">SHA256 hash of the token to keep active (current session).</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    Task RevokeAllExceptAsync(string userId, string exceptTokenHash, CancellationToken cancellationToken = default);
}