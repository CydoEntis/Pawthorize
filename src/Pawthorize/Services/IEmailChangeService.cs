namespace Pawthorize.Services;

/// <summary>
/// Service for handling email change flow.
/// Pawthorize provides the implementation - consumer just uses it.
/// </summary>
public interface IEmailChangeService
{
    /// <summary>
    /// Initiate email change by sending verification email to new address.
    /// If RequireEmailVerification is false, updates email immediately.
    /// </summary>
    /// <param name="userId">User ID requesting email change</param>
    /// <param name="currentEmail">User's current email address</param>
    /// <param name="newEmail">New email address to change to</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if verification email was sent, false if email was updated immediately</returns>
    Task<bool> InitiateEmailChangeAsync(
        string userId,
        string currentEmail,
        string newEmail,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Verify an email change token and update the user's email.
    /// </summary>
    /// <param name="token">The email change token</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Email change token information if verification successful, null if token invalid/expired</returns>
    Task<EmailChangeTokenInfo?> VerifyEmailChangeAsync(
        string token,
        CancellationToken cancellationToken = default);
}
