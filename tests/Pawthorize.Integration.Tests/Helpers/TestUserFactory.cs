using Pawthorize.AspNetCore.DTOs;
using Pawthorize.Core.Abstractions;

namespace Pawthorize.Integration.Tests.Helpers;

public class TestUserFactory : IUserFactory<TestUser, RegisterRequest>
{
    public TestUser CreateUser(RegisterRequest request, string passwordHash)
    {
        return new TestUser
        {
            Id = Guid.NewGuid().ToString(),
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name,
            IsEmailVerified = false,
            IsLocked = false
        };
    }
}
