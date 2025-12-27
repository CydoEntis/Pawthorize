namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Service for handling password reset flow.
/// Pawthorize provides the implementation - consumer just uses it.
/// </summary>
public interface IPasswordResetService
{
    /// <summary>
    /// Generate and send a password reset token.
    /// </summary>
    /// <param name="userId">User ID to send reset token to</param>
    /// <param name="email">User's email address</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The generated token</returns>
    Task<string> SendPasswordResetEmailAsync(
        string userId,
        string email,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify a password reset token.
    /// </summary>
    /// <param name="token">The reset token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User ID if token is valid, null if token invalid/expired</returns>
    Task<string?> ValidateResetTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidate a password reset token (after successful password reset).
    /// </summary>
    /// <param name="token">The token to invalidate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task InvalidateResetTokenAsync(
        string token,
        CancellationToken cancellationToken = default);
}
