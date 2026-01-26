using Pawthorize.Abstractions;

namespace Pawthorize.Tests.Helpers;

public class TestUser : IAuthenticatedUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool IsEmailVerified { get; set; } = false;
    public bool IsLocked { get; set; } = false;
    public DateTime? LockedUntil { get; set; }
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }

    // Helper property for backward compatibility in tests
    public string? Name => !string.IsNullOrEmpty(FirstName) || !string.IsNullOrEmpty(LastName)
        ? $"{FirstName} {LastName}".Trim()
        : null;
}
