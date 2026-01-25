namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for storing email verification and password reset tokens.
/// Consumer implements this to store tokens in their database.
/// IMPORTANT: All tokens are hashed before storage for security.
/// </summary>
public interface ITokenRepository
{
    /// <summary>
    /// Store a verification token hash.
    /// The framework hashes tokens before calling this method.
    /// </summary>
    /// <param name="userId">User ID the token belongs to</param>
    /// <param name="tokenHash">SHA256 hash of the verification token</param>
    /// <param name="tokenType">Type of token (EmailVerification, PasswordReset, etc.)</param>
    /// <param name="expiresAt">When the token expires</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task StoreTokenAsync(
        string userId,
        string tokenHash,
        TokenType tokenType,
        DateTime expiresAt,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validate a token hash and retrieve its information.
    /// Returns null if token doesn't exist or is expired.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the token to validate</param>
    /// <param name="tokenType">Expected token type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token information if valid, null otherwise</returns>
    Task<TokenInfo?> ValidateTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Consume a token (validate and invalidate in one operation).
    /// This is the preferred method for one-time token usage.
    /// Returns null if token doesn't exist, is invalid, or is expired.
    /// The framework hashes the raw token before calling this method.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the token to consume</param>
    /// <param name="tokenType">Expected token type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token information if valid, null otherwise</returns>
    Task<TokenInfo?> ConsumeTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidate/delete a token hash after it's been used.
    /// Note: ConsumeTokenAsync is preferred for one-time token flows.
    /// </summary>
    /// <param name="tokenHash">SHA256 hash of the token to invalidate</param>
    /// <param name="tokenType">Token type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task InvalidateTokenAsync(
        string tokenHash,
        TokenType tokenType,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Invalidate all tokens of a specific type for a user.
    /// Useful when user changes email or password.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="tokenType">Token type to invalidate</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task InvalidateAllTokensForUserAsync(
        string userId,
        TokenType tokenType,
        CancellationToken cancellationToken = default);
}

public enum TokenType
{
    /// <summary>
    /// Email verification token (sent during registration)
    /// </summary>
    EmailVerification,
    
    /// <summary>
    /// Password reset token (sent during forgot password flow)
    /// </summary>
    PasswordReset,
    
    /// <summary>
    /// Email change token (sent when user requests to change email)
    /// </summary>
    EmailChange
}

/// <summary>
/// Information about a validated token (immutable)
/// </summary>
public record TokenInfo(
    string UserId,
    DateTime CreatedAt,
    DateTime ExpiresAt)
{
    /// <summary>
    /// Check if token has expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
}

