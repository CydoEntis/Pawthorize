using Pawthorize.Abstractions;

namespace Pawthorize.Sample.MinimalApi.Models;

/// <summary>
/// Sample user entity implementing IAuthenticatedUser.
/// </summary>
public class User : IAuthenticatedUser
{
    /// <summary>
    /// Gets or sets the unique identifier for the user.
    /// </summary>
    public string Id { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Gets or sets the user's email address.
    /// </summary>
    public string Email { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user's hashed password.
    /// </summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user's first name (given name).
    /// </summary>
    public string FirstName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the user's last name (family name).
    /// </summary>
    public string LastName { get; set; } = string.Empty;

    /// <summary>
    /// Gets the user's full name (computed from FirstName and LastName).
    /// </summary>
    public string FullName => $"{FirstName} {LastName}".Trim();

    /// <summary>
    /// Gets or sets the user's assigned roles.
    /// </summary>
    public IEnumerable<string> Roles { get; set; } = new List<string>();

    /// <summary>
    /// Gets or sets additional custom claims for the user.
    /// </summary>
    public IDictionary<string, string>? AdditionalClaims { get; set; } = new Dictionary<string, string>();

    /// <summary>
    /// Gets or sets a value indicating whether the user's email has been verified.
    /// </summary>
    public bool IsEmailVerified { get; set; } = false;

    /// <summary>
    /// Gets or sets a value indicating whether the user account is locked.
    /// </summary>
    public bool IsLocked { get; set; } = false;

    /// <summary>
    /// Gets or sets the date and time until which the account is locked.
    /// </summary>
    public DateTime? LockedUntil { get; set; }

    /// <summary>
    /// Gets or sets the number of consecutive failed login attempts.
    /// </summary>
    public int FailedLoginAttempts { get; set; } = 0;

    /// <summary>
    /// Gets or sets the date and time when the account lockout will end.
    /// </summary>
    public DateTime? LockoutEnd { get; set; }

    /// <summary>
    /// Gets or sets the date and time when the user account was created.
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the date and time of the user's last login.
    /// </summary>
    public DateTime? LastLoginAt { get; set; }
}