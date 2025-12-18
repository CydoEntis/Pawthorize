namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Represents a user that can be authenticated with Pawthorize.
/// Consumer's User entity must implement this interface.
/// </summary>
public interface IAuthenticatedUser
{
    /// <summary>
    /// Unique user identifier
    /// </summary>
    string Id { get; }

    /// <summary>
    /// User's email address
    /// </summary>
    string Email { get; }

    /// <summary>
    /// Hashed password
    /// </summary>
    string PasswordHash { get; }

    /// <summary>
    /// User's display name (optional)
    /// </summary>
    string? Name { get; }

    /// <summary>
    /// User's roles (for authorization)
    /// </summary>
    IEnumerable<string> Roles { get; }

    /// <summary>
    /// Additional claims to include in JWT (optional)
    /// </summary>
    IDictionary<string, string>? AdditionalClaims { get; }

    /// <summary>
    /// Whether the user's email has been verified.
    /// Default: true (for backwards compatibility)
    /// </summary>
    bool IsEmailVerified => true;

    /// <summary>
    /// Whether the account is locked (e.g., due to failed login attempts).
    /// Default: false
    /// </summary>
    bool IsLocked => false;

    /// <summary>
    /// When the account lock expires (if locked).
    /// Null means locked indefinitely or not locked.
    /// </summary>
    DateTime? LockedUntil => null;
}