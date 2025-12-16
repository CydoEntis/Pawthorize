using Pawthorize.Core.Abstractions;

namespace Pawthorize.Core.Models;

/// <summary>
/// Result of successful authentication containing tokens and user info.
/// Returned by login, register, and refresh operations.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class AuthResult<TUser> where TUser : IAuthenticatedUser
{
    /// <summary>
    /// JWT access token (short-lived, stateless)
    /// Include this in Authorization header: "Bearer {AccessToken}"
    /// </summary>
    public string AccessToken { get; set; } = string.Empty;
    
    /// <summary>
    /// Refresh token (long-lived, stored in database)
    /// Use this to get new access tokens without re-authenticating
    /// </summary>
    public string RefreshToken { get; set; } = string.Empty;
    
    /// <summary>
    /// The authenticated user's information
    /// </summary>
    public TUser User { get; set; } = default!;
    
    /// <summary>
    /// When the access token expires (UTC)
    /// Frontend should refresh before this time
    /// </summary>
    public DateTime AccessTokenExpiresAt { get; set; }
    
    /// <summary>
    /// When the refresh token expires (UTC)
    /// User must re-login after this time
    /// </summary>
    public DateTime RefreshTokenExpiresAt { get; set; }
    
    /// <summary>
    /// Token type (typically "Bearer")
    /// </summary>
    public string TokenType { get; set; } = "Bearer";
}