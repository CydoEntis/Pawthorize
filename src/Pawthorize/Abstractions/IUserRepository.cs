namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Repository for user data access.
/// Consumer must implement this to connect Pawthorize to their database.
/// </summary>
public interface IUserRepository<TUser> where TUser : IAuthenticatedUser
{
    /// <summary>
    /// Find a user by identifier (email, username, phone, etc.)
    /// The identifier type is determined by consumer's implementation.
    /// </summary>
    Task<TUser?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Find a user by ID.
    /// </summary>
    Task<TUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default);

    /// <summary>
    /// Find a user by email address.
    /// </summary>
    Task<TUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Create a new user.
    /// </summary>
    Task<TUser> CreateAsync(TUser user, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Update an existing user.
    /// </summary>
    Task<TUser> UpdateAsync(TUser user, CancellationToken cancellationToken = default);
    
    /// <summary>
    /// Check if an email address is already registered.
    /// </summary>
    Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default);

    /// <summary>
    /// Update a user's password.
    /// </summary>
    /// <param name="userId">User ID</param>
    /// <param name="newPasswordHash">New hashed password</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task UpdatePasswordAsync(string userId, string newPasswordHash, CancellationToken cancellationToken = default);
}