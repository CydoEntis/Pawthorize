namespace Pawthorize.Core.Abstractions;

/// <summary>
/// Factory for creating user entities during registration.
/// Consumer implements this to define how to create their User type from registration request.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
/// <typeparam name="TRegisterRequest">Registration request type</typeparam>
public interface IUserFactory<TUser, in TRegisterRequest>
    where TUser : IAuthenticatedUser
{
    /// <summary>
    /// Create a new user entity from registration request.
    /// </summary>
    /// <param name="request">Registration request (may contain custom fields if extended)</param>
    /// <param name="passwordHash">Already-hashed password</param>
    /// <returns>New user entity ready to be saved</returns>
    TUser CreateUser(TRegisterRequest request, string passwordHash);
}