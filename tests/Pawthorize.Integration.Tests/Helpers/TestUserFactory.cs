using Pawthorize.Abstractions;
using Pawthorize.Endpoints.Register;

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
            FirstName = request.FirstName,
            LastName = request.LastName,
            IsEmailVerified = false,
            IsLocked = false
        };
    }
}
