using Pawthorize.Abstractions;
using Pawthorize.Endpoints.Register;
using Pawthorize.Sample.MinimalApi.Models;

namespace Pawthorize.Sample.MinimalApi.Factories;

/// <summary>
/// Factory for creating User entities from registration requests.
/// </summary>
public class UserFactory : IUserFactory<User, RegisterRequest>
{
    /// <summary>
    /// Creates a new User entity from the registration request.
    /// </summary>
    /// <param name="request">The registration request containing user information.</param>
    /// <param name="passwordHash">The hashed password for the user.</param>
    /// <returns>A newly created User entity.</returns>
    public User CreateUser(RegisterRequest request, string passwordHash)
    {
        return new User
        {
            Id = Guid.NewGuid().ToString(),
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name ?? string.Empty,
            Roles = new List<string> { "User" },
            IsEmailVerified = false,
            IsLocked = false,
            CreatedAt = DateTime.UtcNow
        };
    }
}