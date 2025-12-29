<div align="center">
  <img src="assets/logo.png" alt="Pawthorize Logo" width="200"/>

  # Pawthorize

  **Modern, secure authentication for ASP.NET Core** - batteries included.
</div>

Pawthorize is a complete authentication library that provides secure user authentication, JWT token management, password handling, and session management out of the box. Built for ASP.NET Core Minimal APIs and designed to get you up and running in minutes.

## Features

- **Complete Authentication Flow**: Register, login, logout, token refresh
- **Secure Password Handling**: BCrypt hashing with automatic salting
- **JWT Token Management**: Access tokens + refresh token rotation
- **Flexible Token Delivery**: Cookies, response body, or hybrid strategies
- **Email Verification**: Built-in email verification workflow
- **Password Reset**: Secure password reset with token expiration
- **Session Management**: View and revoke active sessions across devices
- **Multi-Tenant Ready**: Optional multi-tenant support
- **Flexible User Identification**: Login via email, username, or phone
- **Account Security**: Account locking, email verification requirements
- **Integrated Error Handling**: ErrorHound integration for consistent API responses
- **OpenAPI/Swagger Support**: Automatic API documentation generation
- **Validation**: FluentValidation for request validation
- **Extensible**: Easy to customize and extend

## Installation

Install via NuGet:

```bash
dotnet add package Pawthorize
```

## Quick Start

### 1. Define Your User Model

```csharp
public class User : IAuthenticatedUser
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Name { get; set; }
    public List<string>? Roles { get; set; }
    public Dictionary<string, string>? AdditionalClaims { get; set; }
    public bool IsEmailVerified { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? LockedUntil { get; set; }
}
```

### 2. Implement Repositories

```csharp
public class UserRepository : IUserRepository<User>
{
    // Implement user storage (Entity Framework, Dapper, etc.)
}

public class RefreshTokenRepository : IRefreshTokenRepository
{
    // Implement token storage
}
```

### 3. Configure Pawthorize

```json
// appsettings.json
{
  "Pawthorize": {
    "RequireEmailVerification": false,
    "TokenDelivery": "ResponseBody",
    "LoginIdentifier": "Email"
  },
  "Jwt": {
    "Secret": "your-super-secret-key-at-least-32-characters-long",
    "Issuer": "YourApp",
    "Audience": "YourApp",
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeDays": 7
  }
}
```

### 4. Register Services

```csharp
var builder = WebApplication.CreateBuilder(args);

// Register Pawthorize
builder.Services.AddPawthorize<User, RegisterRequest>(
    builder.Configuration,
    options =>
    {
        options.EnableErrorHound = true;
        options.EnableSuccessHound = true;
    });

// Register your repositories
builder.Services.AddScoped<IUserRepository<User>, UserRepository>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
```

### 5. Map Endpoints

```csharp
var app = builder.Build();

// Wire up middleware
app.UsePawthorize();

// Map authentication endpoints
app.MapPawthorize<User>();

app.Run();
```

That's it! You now have 10+ authentication endpoints ready to use:

- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout (revoke token)
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (authenticated)
- `POST /api/auth/verify-email` - Verify email address
- `GET /api/auth/me` - Get current user info
- `GET /api/auth/sessions` - Get active sessions
- `POST /api/auth/sessions/revoke-others` - Revoke all other sessions

## Token Delivery Strategies

Pawthorize supports three token delivery strategies:

### ResponseBody (Default)
Tokens are returned in the response body. Client manages token storage.

```json
{
  "accessToken": "eyJhbGc...",
  "refreshToken": "d8f7a6b5...",
  "accessTokenExpiresAt": "2025-12-20T12:15:00Z",
  "refreshTokenExpiresAt": "2025-12-27T12:00:00Z"
}
```

### HttpOnlyCookies
Tokens are set as secure, HttpOnly cookies. Best for browser-based apps.

```csharp
"Pawthorize": {
  "TokenDelivery": "HttpOnlyCookies"
}
```

### Hybrid
Access token in response body, refresh token in HttpOnly cookie. Balance of flexibility and security.

```csharp
"Pawthorize": {
  "TokenDelivery": "Hybrid"
}
```

## Configuration Options

### Pawthorize Settings

```json
{
  "Pawthorize": {
    "BasePath": "/api/auth",
    "RequireEmailVerification": true,
    "TokenDelivery": "ResponseBody",
    "LoginIdentifier": "Email",
    "EmailVerification": {
      "BaseUrl": "https://yourapp.com",
      "TokenLifetimeHours": 24
    },
    "PasswordReset": {
      "TokenLifetimeMinutes": 60
    }
  }
}
```

### JWT Settings

```json
{
  "Jwt": {
    "Secret": "your-secret-key-min-32-chars",
    "Issuer": "YourApp",
    "Audience": "YourApp",
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeDays": 7
  }
}
```

## Email Verification

Enable email verification to require users to verify their email before accessing protected resources:

```csharp
// 1. Enable in configuration
"RequireEmailVerification": true,
"EmailVerification": {
  "BaseUrl": "https://yourapp.com",
  "TokenLifetimeHours": 24
}

// 2. Implement email service
public class EmailService : IEmailVerificationService
{
    public async Task SendVerificationEmailAsync(string email, string token)
    {
        var verifyUrl = $"https://yourapp.com/verify?token={token}";
        // Send email with verifyUrl
    }
}

// 3. Register service
builder.Services.AddScoped<IEmailVerificationService, EmailService>();
```

## Password Reset

Password reset is built-in and ready to use:

```csharp
// 1. Implement email service for reset emails
public class EmailService : IPasswordResetService
{
    public async Task SendPasswordResetEmailAsync(string email, string token)
    {
        var resetUrl = $"https://yourapp.com/reset-password?token={token}";
        // Send email with resetUrl
    }
}

// 2. Register service
builder.Services.AddScoped<IPasswordResetService, EmailService>();
```

**Flow:**
1. User requests password reset: `POST /api/auth/forgot-password`
2. System generates secure token and sends email
3. User clicks link and submits new password: `POST /api/auth/reset-password`
4. Password is updated, token is invalidated

## Session Management

Users can view and manage their active sessions across devices:

```csharp
// Get all active sessions
GET /api/auth/sessions
Authorization: Bearer {accessToken}

// Response
{
  "sessions": [
    {
      "deviceInfo": "Chrome on Windows",
      "ipAddress": "192.168.1.1",
      "lastActiveAt": "2025-12-29T10:30:00Z",
      "createdAt": "2025-12-20T08:00:00Z",
      "expiresAt": "2025-12-27T08:00:00Z",
      "isCurrent": true
    }
  ]
}

// Revoke all other sessions (logout other devices)
POST /api/auth/sessions/revoke-others
Authorization: Bearer {accessToken}
```

## Custom User Model

Extend `RegisterRequest` to capture additional user data during registration:

```csharp
public class CustomRegisterRequest : RegisterRequest
{
    public string PhoneNumber { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
}

// Register with custom request
builder.Services.AddPawthorize<User, CustomRegisterRequest>(configuration);

// Map with custom request
app.MapPawthorize<User, CustomRegisterRequest>();
```

## Error Handling

Pawthorize integrates with [ErrorHound](https://github.com/yourusername/errorhound) for consistent error responses:

```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid Credentials",
    "details": "The email or password provided is incorrect."
  },
  "meta": {
    "timestamp": "2025-12-29T10:30:00Z",
    "version": "v1.0"
  }
}
```

Common error codes:
- `INVALID_CREDENTIALS` - Wrong email/password
- `DUPLICATE_EMAIL` - Email already registered
- `INVALID_REFRESH_TOKEN` - Token expired or revoked
- `EMAIL_NOT_VERIFIED` - Email verification required
- `ACCOUNT_LOCKED` - Account temporarily locked
- `VALIDATION_ERROR` - Request validation failed

## Validation

All requests are validated using FluentValidation. Custom validation rules are easy to add:

```csharp
public class CustomRegisterValidator : AbstractValidator<CustomRegisterRequest>
{
    public CustomRegisterValidator()
    {
        Include(new RegisterRequestValidator());

        RuleFor(x => x.PhoneNumber)
            .NotEmpty()
            .Matches(@"^\+?[1-9]\d{1,14}$")
            .WithMessage("Invalid phone number format");
    }
}

builder.Services.AddScoped<IValidator<CustomRegisterRequest>, CustomRegisterValidator>();
```

## Examples

Check out the [sample applications](./samples):

- **MinimalApi Sample**: Complete working example with all features
- **Postman Collection**: Pre-configured requests for testing

## Requirements

- .NET 8.0 or later
- ASP.NET Core

## Dependencies

- ErrorHound (2.0.0+)
- SuccessHound (1.0.0+)
- FluentValidation (11.9.0+)
- BCrypt.Net-Next (4.0.3+)
- JWT Bearer Authentication

## Documentation

- [Quick Start Guide](./POSTMAN_QUICK_START.md) - Get started with Postman
- [Release Testing](./RELEASE_TESTING_v0.1.0.md) - Testing checklist
- [Sample README](./samples/Pawthorize.Sample.MinimalApi/README.md) - Detailed sample documentation

## Roadmap

- OAuth2 provider support (Google, GitHub, etc.)
- Two-factor authentication (2FA)
- Magic link authentication
- WebAuthn/Passkey support
- Rate limiting
- Advanced session management
- Audit logging

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/pawthorize/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/pawthorize/discussions)

---

Built with care by the Pawthorize team
