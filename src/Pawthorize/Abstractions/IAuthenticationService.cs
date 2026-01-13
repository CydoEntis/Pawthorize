using Pawthorize.Models;

namespace Pawthorize.Abstractions;

/// <summary>
/// Service for generating authentication tokens and validating user account status.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public interface IAuthenticationService<TUser> where TUser : IAuthenticatedUser
{
    /// <summary>
    /// Generate access and refresh tokens for a user.
    /// Stores refresh token in database with session metadata.
    /// </summary>
    Task<AuthResult> GenerateTokensAsync(TUser user, string? deviceInfo = null, string? ipAddress = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Validate user account status (email verification, account lock, etc.)
    /// Throws appropriate error if validation fails.
    /// </summary>
    void ValidateAccountStatus(TUser user);
}
