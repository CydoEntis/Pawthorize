namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Service for handling email verification flow.
/// Pawthorize provides the implementation - consumer just uses it.
/// </summary>
public interface IEmailVerificationService
{
    /// <summary>
    /// Generate and send an email verification token.
    /// </summary>
    /// <param name="userId">User ID to send verification to</param>
    /// <param name="email">User's email address</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The generated token</returns>
    Task<string> SendVerificationEmailAsync(
        string userId,
        string email,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify an email verification token and mark user as verified.
    /// </summary>
    /// <param name="token">The verification token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>User ID if verification successful, null if token invalid/expired</returns>
    Task<string?> VerifyEmailAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resend verification email (if original expired or lost).
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="email">User's email address</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task ResendVerificationEmailAsync(
        string userId,
        string email,
        CancellationToken cancellationToken = default);
}