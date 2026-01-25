using Pawthorize.Abstractions;

namespace Pawthorize.Services;

/// <summary>
/// Repository for storing email change tokens with associated new email addresses.
/// Extends ITokenRepository to support storing additional metadata (new email) with tokens.
/// Consumer implements this to store email change tokens in their database.
/// IMPORTANT: All tokens are hashed before storage for security.
/// </summary>
public interface IEmailChangeTokenRepository : ITokenRepository
{
    /// <summary>
    /// Store an email change token hash with the new email address.
    /// The framework hashes tokens before calling this method.
    /// </summary>
    /// <param name="userId">User ID the token belongs to</param>
    /// <param name="tokenHash">SHA256 hash of the email change token</param>
    /// <param name="newEmail">The new email address to change to</param>
    /// <param name="expiresAt">When the token expires</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task StoreEmailChangeTokenAsync(
        string userId,
        string tokenHash,
        string newEmail,
        DateTime expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Consume an email change token and retrieve the new email address.
    /// This validates, invalidates, and returns the new email in one operation.
    /// Returns null if token doesn't exist, is invalid, or is expired.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the token to consume</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Email change token information if valid, null otherwise</returns>
    Task<EmailChangeTokenInfo?> ConsumeEmailChangeTokenAsync(
        string tokenHash,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Information about a validated email change token (immutable)
/// </summary>
public record EmailChangeTokenInfo(
    string UserId,
    string NewEmail,
    DateTime CreatedAt,
    DateTime ExpiresAt)
{
    /// <summary>
    /// Check if token has expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
}
