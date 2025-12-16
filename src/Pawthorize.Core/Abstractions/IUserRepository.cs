namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Repository for user data access.
/// Consumer must implement this to connect Pawthorize to their database.
/// </summary>
public interface IUserRepository<TUser> where TUser : IAuthenticatedUser
{
    Task<TUser?> FindByEmailAsync(string email, CancellationToken cancellationToken = default);
    Task<TUser?> FindByIdAsync(string id, CancellationToken cancellationToken = default);
    Task<TUser> CreateAsync(TUser user, CancellationToken cancellationToken = default);
    Task<TUser> UpdateAsync(TUser user, CancellationToken cancellationToken = default);
    Task<bool> EmailExistsAsync(string email, CancellationToken cancellationToken = default);
}