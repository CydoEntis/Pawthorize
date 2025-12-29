using Pawthorize.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class InMemoryUserRepository<TUser> : IUserRepository<TUser>
    where TUser : IAuthenticatedUser
{
    private readonly Dictionary<string, TUser> _users = new();

    public Task<TUser?> FindByIdentifierAsync(string identifier, CancellationToken cancellationToken = default)
    {
        var user = _users.Values.FirstOrDefault(u => u.Email.Equals(identifier, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(user);
    }

    public Task<TUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
    {
        var user = _users.Values.FirstOrDefault(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(user);
    }

    public Task<TUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
    {
        _users.TryGetValue(userId, out var user);
        return Task.FromResult(user);
    }

    public Task<TUser> CreateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        _users[user.Id] = user;
        return Task.FromResult(user);
    }

    public Task<TUser> UpdateAsync(TUser user, CancellationToken cancellationToken = default)
    {
        _users[user.Id] = user;
        return Task.FromResult(user);
    }

    public Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default)
    {
        var exists = _users.Values.Any(u => u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(exists);
    }

    public Task UpdatePasswordAsync(string userId, string newPasswordHash, CancellationToken cancellationToken = default)
    {
        if (_users.TryGetValue(userId, out var user))
        {
            // Since TUser is constrained to IAuthenticatedUser which has PasswordHash,
            // we need to update it via reflection or assume it's mutable
            // For test purposes, we'll just update the stored user
            var userType = user.GetType();
            var passwordProperty = userType.GetProperty("PasswordHash");
            passwordProperty?.SetValue(user, newPasswordHash);
        }
        return Task.CompletedTask;
    }

    public void Clear() => _users.Clear();
}
