namespace Pawthorize.Abstractions;

/// <summary>
/// Repository for storing email verification and password reset tokens.
/// Consumer implements this to store tokens in their database.
/// </summary>
public interface ITokenRepository
{
    /// <summary>
    /// Store a verification token.
    /// </summary>
    /// <param name="userId">User ID the token belongs to</param>
    /// <param name="token">The verification token</param>
    /// <param name="tokenType">Type of token (EmailVerification, PasswordReset, etc.)</param>
    /// <param name="expiresAt">When the token expires</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task StoreTokenAsync(
        string userId, 
        string token, 
        TokenType tokenType, 
        DateTime expiresAt, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Validate a token and retrieve its information.
    /// Returns null if token doesn't exist or is expired.
    /// </summary>
    /// <param name="token">The token to validate</param>
    /// <param name="tokenType">Expected token type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Token information if valid, null otherwise</returns>
    Task<TokenInfo?> ValidateTokenAsync(
        string token, 
        TokenType tokenType, 
        CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Invalidate/delete a token after it's been used.
    /// </summary>
    /// <param name="token">The token to invalidate</param>
    /// <param name="tokenType">Token type</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task InvalidateTokenAsync(
        string token, 
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
    PasswordReset
}

/// <summary>
/// Information about a validated token
/// </summary>
public class TokenInfo
{
    public string UserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
}

