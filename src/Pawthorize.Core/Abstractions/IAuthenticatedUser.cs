namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Represents a user that can be authenticated with Pawthorize.
/// Consumer's User entity must implement this interface.
/// </summary>
public interface IAuthenticatedUser
{
    /// <summary>
    /// Unique identifier for the user
    /// </summary>
    string Id { get; }
    
    /// <summary>
    /// Email address used for authentication
    /// </summary>
    string Email { get; }
    
    /// <summary>
    /// User's full name or display name (optional)
    /// </summary>
    string? Name { get; }
    
    /// <summary>
    /// User's roles for authorization
    /// </summary>
    IEnumerable<string> Roles { get; }
    
    /// <summary>
    /// Additional custom claims to include in JWT (optional)
    /// </summary>
    IDictionary<string, string>? AdditionalClaims { get; }
}