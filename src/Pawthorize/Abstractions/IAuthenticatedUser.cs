namespace Pawthorize.Abstractions;

/// <summary>
/// Represents a user that can be authenticated with Pawthorize.
/// Consumer's User entity must implement this interface.
/// </summary>
public interface IAuthenticatedUser
{
    string Id { get; }
    string Email { get; set; }
    string PasswordHash { get; }
    IEnumerable<string> Roles { get; }
    IDictionary<string, string>? AdditionalClaims { get; }
    bool IsEmailVerified { get; set; }
    bool IsLocked => false;
    DateTime? LockedUntil => null;

    /// <summary>
    /// Number of consecutive failed login attempts.
    /// Incremented on failed login, reset to 0 on successful login.
    /// Used for account lockout protection.
    /// </summary>
    int FailedLoginAttempts { get; set; }

    /// <summary>
    /// Timestamp when the account lockout will end.
    /// If null or in the past, account is not locked.
    /// Set when failed attempts exceed the threshold.
    /// </summary>
    DateTime? LockoutEnd { get; set; }
}