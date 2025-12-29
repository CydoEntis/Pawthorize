namespace Pawthorize.Abstractions;

/// <summary>
/// Represents a user that can be authenticated with Pawthorize.
/// Consumer's User entity must implement this interface.
/// </summary>
public interface IAuthenticatedUser
{
    string Id { get; }
    string Email { get; }
    string PasswordHash { get; }
    string? Name { get; }
    IEnumerable<string> Roles { get; }
    IDictionary<string, string>? AdditionalClaims { get; }
    bool IsEmailVerified => true;
    bool IsLocked => false;
    DateTime? LockedUntil => null;
}