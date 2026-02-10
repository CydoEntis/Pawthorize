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
    /// <remarks>
    /// Note: IsEmailVerified is initially set to false. For OAuth users, Pawthorize will automatically
    /// set it to true after creation if the OAuth provider has verified the email (Google, Discord, GitHub).
    /// For email/password registrations, users must verify their email through the verification flow.
    /// </remarks>
    public User CreateUser(RegisterRequest request, string passwordHash)
    {
        return new User
        {
            Id = Guid.NewGuid().ToString(),
            Email = request.Email,
            PasswordHash = passwordHash,
            FirstName = request.FirstName,
            LastName = request.LastName,
            Roles = new List<string> { "User" },
            IsEmailVerified = false,  // Auto-verified for OAuth users by Pawthorize
            IsLocked = false,
            CreatedAt = DateTime.UtcNow
        };
    }
}