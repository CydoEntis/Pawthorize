using Pawthorize.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class TestUser : IAuthenticatedUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Name { get; set; }
    public bool IsEmailVerified { get; set; } = false;
    public bool IsLocked { get; set; } = false;
    public DateTime? LockedUntil { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }
}
