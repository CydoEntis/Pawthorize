using Pawthorize.Abstractions;
using Pawthorize.Sample.MinimalApi.Models;

namespace Pawthorize.Sample.MinimalApi.Repositories;

/// <summary>
/// In-memory user repository for testing.
/// </summary>
public class InMemoryUserRepository : IUserRepository<User>
{
    private readonly Dictionary<string, User> _users = new();

    /// <summary>
    /// Finds a user by their unique identifier.
    /// </summary>
    /// <param name="id">The user ID to search for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user if found, null otherwise.</returns>
    public Task<User?> FindByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        _users.TryGetValue(id, out var user);
        return Task.FromResult(user);
    }

    /// <summary>
    /// Finds a user by their email address.
    /// </summary>
    /// <param name="email">The email address to search for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user if found, null otherwise.</returns>
    public Task<User?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var user = _users.Values.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(user);
    }

    /// <summary>
    /// Finds a user by their identifier (email in this implementation).
    /// </summary>
    /// <param name="identifier">The identifier to search for.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The user if found, null otherwise.</returns>
    public Task<User?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken = default)
    {
        return FindByEmailAsync(identifier, cancellationToken);
    }

    /// <summary>
    /// Checks if an email address is already registered.
    /// </summary>
    /// <param name="email">The email address to check.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>True if the email exists, false otherwise.</returns>
    public Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        var exists = _users.Values.Any(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(exists);
    }

    /// <summary>
    /// Creates a new user in the repository.
    /// </summary>
    /// <param name="user">The user to create.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created user.</returns>
    public Task<User> CreateAsync(User user, CancellationToken cancellationToken = default)
    {
        _users[user.Id] = user;
        return Task.FromResult(user);
    }

    /// <summary>
    /// Updates an existing user in the repository.
    /// </summary>
    /// <param name="user">The user with updated information.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The updated user.</returns>
    public Task<User> UpdateAsync(User user, CancellationToken cancellationToken = default)
    {
        _users[user.Id] = user;
        return Task.FromResult(user);
    }

    /// <summary>
    /// Updates the password hash for a specific user.
    /// </summary>
    /// <param name="userId">The user ID whose password should be updated.</param>
    /// <param name="newPasswordHash">The new password hash.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task UpdatePasswordAsync(string userId, string newPasswordHash, CancellationToken cancellationToken = default)
    {
        if (_users.TryGetValue(userId, out var user))
        {
            user.PasswordHash = newPasswordHash;
        }
        return Task.CompletedTask;
    }

    /// <summary>
    /// Deletes a user from the repository.
    /// </summary>
    /// <param name="id">The user ID to delete.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    public Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        _users.Remove(id);
        return Task.CompletedTask;
    }
}