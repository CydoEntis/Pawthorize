# 🐾 Pawthorize

**Pawthorize** is a flexible, reusable authentication package for ASP.NET Core applications. Built with clean architecture principles, it provides JWT authentication, OAuth integration, and comprehensive security features out of the box.

## 🚀 Features

- ✅ **JWT Authentication** - Access + refresh token support
- ✅ **Multi-tenant Ready** - Optional per-tenant JWT secrets
- ✅ **OAuth Integration** - Google and GitHub providers
- ✅ **Password Security** - BCrypt hashing with configurable work factor
- ✅ **Email Verification** - Built-in email verification flow
- ✅ **Password Reset** - Secure password reset with tokens
- ✅ **Account Lockout** - Configurable failed login attempts
- ✅ **Clean Architecture** - Interface-driven, testable design
- ✅ **ErrorHound Integration** - Consistent error handling
- ✅ **SuccessHound Integration** - Standardized success responses

## 📦 Packages

| Package | Description | Status |
|---------|-------------|--------|
| `Pawthorize.Core` | Core abstractions and models | 🚧 In Progress |
| `Pawthorize.Jwt` | JWT token services | 🚧 In Progress |
| `Pawthorize.Security` | Password hashing and encryption | 🚧 In Progress |
| `Pawthorize.AspNetCore` | ASP.NET Core integration | 🚧 In Progress |
| `Pawthorize.OAuth` | OAuth providers (Google, GitHub) | 📅 Planned |
| `Pawthorize.ErrorHandling` | Auth-specific error types | 📅 Planned |

## 🛠️ Installation
```bash
# Core package (required)
dotnet add package Pawthorize.Core

# JWT services (required for token auth)
dotnet add package Pawthorize.Jwt

# Security services (password hashing)
dotnet add package Pawthorize.Security

# ASP.NET Core integration (handlers, middleware)
dotnet add package Pawthorize.AspNetCore

# OAuth providers (optional)
dotnet add package Pawthorize.OAuth
```

## 🚀 Quick Start

### 1. Define Your User Model
```csharp
using Pawthorize.Core.Abstractions;

public class User : IAuthenticatedUser
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string? Name { get; set; }
    public IEnumerable<string> Roles { get; set; }
    public IDictionary<string, string>? AdditionalClaims { get; set; }
}
```

### 2. Configure Services
```csharp
using Pawthorize.Jwt.Extensions;
using Pawthorize.Security.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add Pawthorize services
builder.Services.AddJwtService<User>(builder.Configuration);
builder.Services.AddPasswordHashing();

// Add your repositories
builder.Services.AddScoped<IUserRepository<User>, UserRepository>();

var app = builder.Build();
```

### 3. Use Authentication Endpoints
```csharp
app.MapPost("/auth/login", async (LoginRequest request, JwtService<User> jwt) =>
{
    var user = await AuthenticateUser(request);
    var token = jwt.GenerateAccessToken(user);
    return new { AccessToken = token }.Ok();
});
```

## 📚 Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Multi-Tenant Setup](docs/multi-tenant.md)
- [OAuth Integration](docs/oauth-integration.md)
- [API Reference](docs/api-reference.md)

## 🧪 Development
```bash
# Build solution
dotnet build

# Run tests
dotnet test

# Pack NuGet packages
dotnet pack --configuration Release
```

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🐾 Why "Pawthorize"?

Because authentication should be as reliable as a dog's loyalty! 🐕
```

### 4.3 `LICENSE`
```
MIT License

Copyright (c) 2025 CydoEntis

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.