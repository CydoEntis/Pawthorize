<div align="center">
  <img src="assets/logo.png" alt="Pawthorize Logo" width="200"/>

  # Pawthorize

  **Modern, secure authentication for ASP.NET Core** - batteries included.

  [![NuGet](https://img.shields.io/nuget/v/Pawthorize.svg)](https://www.nuget.org/packages/Pawthorize)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
</div>

> **🎉 Version 1.1.0 Release**
>
> **New in v1.1.0:**
> - **Enhanced Security**: All tokens (email verification, password reset, refresh) are now hashed using SHA256 before storage
> - **Immutable Token Models**: TokenInfo and RefreshTokenInfo are now immutable records for better safety
> - **Atomic Token Consumption**: New `ConsumeTokenAsync` method prevents token reuse bugs
> - **Constant-Time Validation**: Protection against timing attacks
>
> **⚠️ Breaking Changes**: v1.1.0 includes breaking changes to `ITokenRepository` and `IRefreshTokenRepository`. See the [Migration Guide](#migration-from-v02-to-v11) below.
>
> While Pawthorize is thoroughly tested with 158 passing tests, please test thoroughly with your specific use case before deploying to production.

---

Pawthorize is a complete authentication library that provides secure user authentication, JWT token management, password handling, session management, and CSRF protection out of the box. Built for ASP.NET Core Minimal APIs and designed to get you up and running in minutes.

## Features

- **Complete Authentication Flow**: Register, login, logout, token refresh
- **Secure Password Handling**: BCrypt hashing with automatic salting
- **JWT Token Management**: Access tokens + refresh token rotation
- **CSRF Protection**: Built-in Double Submit Cookie pattern with automatic token rotation
- **Flexible Token Delivery**: Cookies, response body, or hybrid strategies with automatic cookie authentication
- **Role-Based Authorization**: Built-in role management with automatic JWT claim injection
- **Email Verification**: Built-in email verification workflow
- **Password Reset**: Secure password reset with token expiration
- **Session Management**: View and revoke active sessions across devices
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
    "TokenDelivery": "Hybrid",
    "LoginIdentifier": "Email",
    "Csrf": {
      "Enabled": true,
      "CookieName": "XSRF-TOKEN",
      "HeaderName": "X-XSRF-TOKEN",
      "TokenLifetimeMinutes": 10080
    }
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

builder.Services.AddPawthorize<User>(builder.Configuration, options =>
{
    options.UseDefaultFormatters();
});

builder.Services.AddScoped<IUserRepository<User>, UserRepository>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
```

### 5. Add Middleware and Map Endpoints

```csharp
var app = builder.Build();

app.UsePawthorize();
app.MapPawthorize();

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

Pawthorize supports three token delivery strategies, each with automatic configuration:

### ResponseBody (Default)
**Best for:** Mobile apps, SPAs with complete control over token storage

Tokens are returned in the response body. Client manages token storage (localStorage, secure storage, etc.).

```json
// Configuration
{
  "Pawthorize": {
    "TokenDelivery": "ResponseBody"
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGc...",
    "refreshToken": "d8f7a6b5...",
    "accessTokenExpiresAt": "2025-12-29T12:15:00Z",
    "refreshTokenExpiresAt": "2026-01-05T12:00:00Z"
  }
}
```

**Frontend Usage:**
```typescript
// Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ identifier: email, password })
});

const { accessToken, refreshToken } = response.data;
localStorage.setItem('accessToken', accessToken);
localStorage.setItem('refreshToken', refreshToken);

// Use access token
await fetch('/api/auth/me', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});

// Refresh
await fetch('/api/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({ refreshToken })
});
```

---

### HttpOnlyCookies
**Best for:** Server-rendered apps, maximum security for browser-based applications

All tokens are set as secure, HttpOnly cookies. Provides maximum protection against XSS attacks. Includes automatic CSRF protection.

```json
// Configuration
{
  "Pawthorize": {
    "TokenDelivery": "HttpOnlyCookies",
    "Csrf": {
      "Enabled": true
    }
  }
}
```

**Backend Setup:**
```csharp
app.UsePawthorize();  // CSRF protection automatically enabled
```

**Frontend Usage:**
```typescript
// Helper to get CSRF token from cookie
function getCsrfToken(): string | null {
  const cookie = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='));
  return cookie ? cookie.split('=')[1] : null;
}

// Login - tokens stored in cookies automatically
await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',  // Required for cookies
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ identifier: email, password })
});

// Authenticated requests
await fetch('/api/auth/me', {
  credentials: 'include'  // Cookies sent automatically
});

// State-changing requests (POST, PUT, DELETE) require CSRF token
const csrfToken = getCsrfToken();
await fetch('/api/auth/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'X-XSRF-TOKEN': csrfToken || '',
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({})
});
```

**Security Features:**
- Access token in HttpOnly cookie (can't be read by JavaScript)
- Refresh token in HttpOnly cookie (can't be read by JavaScript)
- CSRF token in readable cookie (needed for header injection)
- All cookies use `Secure` flag in production (HTTPS only)
- All cookies use `SameSite=Strict`

---

### Hybrid (Recommended)
**Best for:** Modern SPAs, mobile-friendly web apps, balanced security and flexibility

Access token in response body for easy client-side use. Refresh token in HttpOnly cookie for maximum security. Includes automatic CSRF protection.

```json
// Configuration
{
  "Pawthorize": {
    "TokenDelivery": "Hybrid",
    "Csrf": {
      "Enabled": true
    }
  }
}
```

**Backend Setup:**
```csharp
app.UsePawthorize();  // CSRF protection automatically enabled
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGc...",
    "accessTokenExpiresAt": "2025-12-29T12:15:00Z"
  }
}
// + refresh token set in HttpOnly cookie
// + CSRF token set in XSRF-TOKEN cookie
```

**Frontend Usage:**
```typescript
// Helper to get CSRF token
function getCsrfToken(): string | null {
  const cookie = document.cookie
    .split('; ')
    .find(row => row.startsWith('XSRF-TOKEN='));
  return cookie ? cookie.split('=')[1] : null;
}

// Reusable fetch wrapper
async function authenticatedFetch(url: string, options: RequestInit = {}) {
  const csrfToken = getCsrfToken();

  return fetch(url, {
    ...options,
    credentials: 'include',  // Required for cookies
    headers: {
      ...options.headers,
      'X-XSRF-TOKEN': csrfToken || '',
      'Content-Type': 'application/json'
    }
  });
}

// Login
const response = await fetch('/api/auth/login', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ identifier: email, password })
});

const { accessToken } = response.data;
localStorage.setItem('accessToken', accessToken);  // Store access token

// Use access token for API calls
await fetch('/api/auth/me', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});

// Refresh token (uses cookie + CSRF)
const refreshResponse = await authenticatedFetch('/api/auth/refresh', {
  method: 'POST',
  body: JSON.stringify({})
});

const { accessToken: newAccessToken } = refreshResponse.data;
localStorage.setItem('accessToken', newAccessToken);

// Logout (requires CSRF)
await authenticatedFetch('/api/auth/logout', {
  method: 'POST',
  body: JSON.stringify({})
});
```

**Benefits:**
- ✅ Access token easily accessible for API calls
- ✅ Refresh token protected in HttpOnly cookie (XSS protection)
- ✅ CSRF protection for state-changing operations
- ✅ Works seamlessly with mobile and desktop clients
- ✅ Automatic token rotation on refresh

---

## CSRF Protection

Pawthorize includes built-in CSRF protection using the Double Submit Cookie pattern with automatic token rotation.

### Features

- **256-bit Cryptographically Secure Tokens**: Generated using `RandomNumberGenerator`
- **Constant-Time Validation**: Prevents timing attacks using `CryptographicOperations.FixedTimeEquals`
- **Automatic Token Rotation**: CSRF tokens rotate on login, register, and refresh for enhanced security
- **Smart Endpoint Exclusion**: Public endpoints (login, register, password reset) automatically excluded
- **Custom Routing Support**: Works with any endpoint configuration

### Configuration

```json
{
  "Pawthorize": {
    "TokenDelivery": "Hybrid",  // or HttpOnlyCookies
    "Csrf": {
      "Enabled": true,
      "CookieName": "XSRF-TOKEN",
      "HeaderName": "X-XSRF-TOKEN",
      "TokenLifetimeMinutes": 10080,  // 7 days
      "ExcludedPaths": []  // Optional: add custom paths to exclude
    }
  }
}
```

### Backend Setup

CSRF protection is **automatically enabled** by `app.UsePawthorize()` when using Hybrid or HttpOnlyCookies mode:

```csharp
var app = builder.Build();

app.UsePawthorize();
app.MapPawthorize();
app.Run();
```

**Advanced:** You can also explicitly add CSRF middleware for custom scenarios:
```csharp
app.UsePawthorize();
app.UsePawthorizeCsrf();  // Explicit CSRF registration (optional)
```

### When CSRF is Required

CSRF protection is **only active** when using `Hybrid` or `HttpOnlyCookies` token delivery modes.

**Protected Endpoints** (require CSRF token):
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `POST /api/auth/change-password`
- `POST /api/auth/sessions/revoke-others`

**Excluded Endpoints** (no CSRF required):
- `POST /api/auth/login` - User doesn't have token yet
- `POST /api/auth/register` - User doesn't have token yet
- `POST /api/auth/forgot-password` - Public endpoint
- `POST /api/auth/reset-password` - Protected by email token
- `POST /api/auth/verify-email` - Protected by email token
- `GET /api/auth/*` - GET requests don't modify state

### Frontend Integration

See the [Token Delivery Strategies](#token-delivery-strategies) section above for complete frontend examples with CSRF handling.

**Key Points:**
1. CSRF token is stored in a **readable** cookie (`XSRF-TOKEN`)
2. Frontend must read the cookie and send it in the `X-XSRF-TOKEN` header
3. Only required for state-changing requests (POST, PUT, DELETE)
4. GET requests don't need CSRF tokens

---

## Configuration Options

### Pawthorize Settings

```json
{
  "Pawthorize": {
    "BasePath": "/api/auth",
    "RequireEmailVerification": true,
    "TokenDelivery": "Hybrid",
    "LoginIdentifier": "Email",
    "EmailVerification": {
      "BaseUrl": "https://yourapp.com",
      "TokenLifetimeHours": 24
    },
    "PasswordReset": {
      "TokenLifetimeMinutes": 60
    },
    "Csrf": {
      "Enabled": true,
      "CookieName": "XSRF-TOKEN",
      "HeaderName": "X-XSRF-TOKEN",
      "TokenLifetimeMinutes": 10080,
      "ExcludedPaths": []
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

### Cookie Security

When using `Hybrid` or `HttpOnlyCookies` modes, cookies are automatically configured with:

- **HttpOnly**: `true` for refresh tokens (prevents JavaScript access)
- **HttpOnly**: `false` for CSRF tokens (JavaScript needs to read for header injection)
- **Secure**: Automatically set based on `context.Request.IsHttps`
  - Production (HTTPS): `Secure = true`
  - Development (HTTP): `Secure = false`
- **SameSite**: `Strict` (prevents CSRF attacks)
- **Expiration**: Matches token lifetime from configuration

**No manual cookie configuration needed** - Pawthorize handles everything automatically!

---

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

## Role-Based Authorization

Pawthorize automatically includes user roles in JWT tokens and integrates seamlessly with ASP.NET Core's built-in authorization.

### Setting Up Roles

**1. Assign roles in your UserFactory:**

```csharp
public class UserFactory : IUserFactory<User, RegisterRequest>
{
    public User CreateUser(RegisterRequest request, string passwordHash)
    {
        return new User
        {
            Id = Guid.NewGuid().ToString(),
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name ?? string.Empty,
            Roles = new List<string> { "User" },  // Default role
            IsEmailVerified = false
        };
    }
}
```

**2. Use role-based authorization on your endpoints:**

```csharp
// Require any authenticated user
app.MapGet("/api/profile", [Authorize] () =>
{
    return Results.Ok("Profile data");
});

// Require specific role
app.MapGet("/api/admin/dashboard", [Authorize(Roles = "Admin")] () =>
{
    return Results.Ok("Admin dashboard");
});

// Require multiple roles (user must have at least one)
app.MapGet("/api/moderator/panel", [Authorize(Roles = "Admin,Moderator")] () =>
{
    return Results.Ok("Moderator panel");
});

// Require specific policy
app.MapGet("/api/reports", [Authorize(Policy = "RequireAdminRole")] () =>
{
    return Results.Ok("Reports");
});
```

**3. Access user roles in your endpoints:**

```csharp
app.MapGet("/api/me", [Authorize] (ClaimsPrincipal user) =>
{
    var userId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var email = user.FindFirst(ClaimTypes.Email)?.Value;
    var roles = user.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList();

    return Results.Ok(new { userId, email, roles });
});
```

### Managing User Roles

Create your own role management endpoints:

```csharp
// Assign roles to a user (Admin only)
app.MapPost("/api/admin/users/{id}/roles",
    [Authorize(Roles = "Admin")]
    async (string id, string[] roles, IUserRepository<User> userRepo) =>
{
    var user = await userRepo.GetByIdAsync(id);
    if (user == null) return Results.NotFound();

    user.Roles = roles;
    await userRepo.UpdateAsync(user);

    return Results.Ok(new { message = "Roles updated successfully", roles });
});

// Get user roles
app.MapGet("/api/admin/users/{id}/roles",
    [Authorize(Roles = "Admin")]
    async (string id, IUserRepository<User> userRepo) =>
{
    var user = await userRepo.GetByIdAsync(id);
    if (user == null) return Results.NotFound();

    return Results.Ok(user.Roles);
});

// Remove a role from a user
app.MapDelete("/api/admin/users/{id}/roles/{role}",
    [Authorize(Roles = "Admin")]
    async (string id, string role, IUserRepository<User> userRepo) =>
{
    var user = await userRepo.GetByIdAsync(id);
    if (user == null) return Results.NotFound();

    user.Roles = user.Roles.Where(r => r != role).ToList();
    await userRepo.UpdateAsync(user);

    return Results.Ok(new { message = "Role removed successfully" });
});
```

### Policy-Based Authorization

For more complex authorization scenarios, use policies:

```csharp
// In Program.cs
builder.Services.AddAuthorizationBuilder()
    .AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"))
    .AddPolicy("RequireEmailVerified", policy =>
        policy.RequireClaim("email_verified", "true"))
    .AddPolicy("RequireAdminOrModerator", policy =>
        policy.RequireRole("Admin", "Moderator"));

// Use in endpoints
app.MapGet("/api/admin/users", [Authorize(Policy = "RequireAdminRole")] () =>
{
    return Results.Ok("User list");
});
```

**How it works:**
- User roles are stored in the `Roles` property of your User entity
- During login/registration, roles are automatically added to JWT as `ClaimTypes.Role` claims
- ASP.NET Core's `[Authorize(Roles = "...")]` attribute validates these claims
- Roles are available throughout the lifetime of the access token

## Custom Registration Fields

Extend `RegisterRequest` to capture additional user data during registration:

```csharp
public class CustomRegisterRequest : RegisterRequest
{
    public string PhoneNumber { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
}

// Register with custom request type
builder.Services.AddPawthorize<User, CustomRegisterRequest>(builder.Configuration, options =>
{
    options.UseDefaultFormatters();
});

// MapPawthorize() automatically detects types from AddPawthorize
app.MapPawthorize();
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
- `CSRF_VALIDATION_FAILED` - CSRF token missing or invalid (Hybrid/HttpOnlyCookies mode)

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

## Migration from v0.2 to v1.1

Version 1.1.0 introduces important security enhancements that require changes to your repository implementations.

### Breaking Changes

1. **ITokenRepository** - Methods now accept/return token hashes instead of raw tokens
2. **IRefreshTokenRepository** - Methods now accept/return token hashes instead of raw tokens
3. **TokenInfo** - Changed from mutable class to immutable record
4. **RefreshTokenInfo** - Changed from mutable class to immutable record with `TokenHash` property instead of `Token`

### Migration Steps

#### 1. Update ITokenRepository Implementation

**Before (v0.2):**
```csharp
public async Task StoreTokenAsync(string userId, string token, TokenType tokenType, DateTime expiresAt, CancellationToken cancellationToken = default)
{
    await _db.Tokens.AddAsync(new TokenEntity
    {
        UserId = userId,
        Token = token,  // ❌ Storing raw token
        TokenType = tokenType,
        ExpiresAt = expiresAt
    });
}

public async Task<TokenInfo?> ValidateTokenAsync(string token, TokenType tokenType, CancellationToken cancellationToken = default)
{
    var entity = await _db.Tokens
        .FirstOrDefaultAsync(t => t.Token == token && t.TokenType == tokenType);  // ❌ Comparing raw token

    if (entity == null || entity.IsExpired) return null;

    return new TokenInfo  // ❌ Mutable class
    {
        UserId = entity.UserId,
        CreatedAt = entity.CreatedAt,
        ExpiresAt = entity.ExpiresAt
    };
}
```

**After (v1.1):**
```csharp
public async Task StoreTokenAsync(string userId, string tokenHash, TokenType tokenType, DateTime expiresAt, CancellationToken cancellationToken = default)
{
    await _db.Tokens.AddAsync(new TokenEntity
    {
        UserId = userId,
        TokenHash = tokenHash,  // ✅ Framework sends hash
        TokenType = tokenType,
        ExpiresAt = expiresAt
    });
}

public async Task<TokenInfo?> ValidateTokenAsync(string tokenHash, TokenType tokenType, CancellationToken cancellationToken = default)
{
    var entity = await _db.Tokens
        .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.TokenType == tokenType);  // ✅ Compare hash

    if (entity == null || entity.IsExpired) return null;

    return new TokenInfo(  // ✅ Immutable record
        entity.UserId,
        entity.CreatedAt,
        entity.ExpiresAt
    );
}

// ✅ New method - atomic validate + invalidate
public async Task<TokenInfo?> ConsumeTokenAsync(string tokenHash, TokenType tokenType, CancellationToken cancellationToken = default)
{
    var entity = await _db.Tokens
        .FirstOrDefaultAsync(t => t.TokenHash == tokenHash && t.TokenType == tokenType);

    if (entity == null || entity.IsExpired || entity.IsInvalidated) return null;

    entity.IsInvalidated = true;  // Invalidate atomically
    await _db.SaveChangesAsync(cancellationToken);

    return new TokenInfo(entity.UserId, entity.CreatedAt, entity.ExpiresAt);
}
```

#### 2. Update IRefreshTokenRepository Implementation

**Before (v0.2):**
```csharp
public async Task StoreAsync(string token, string userId, DateTime expiresAt, CancellationToken cancellationToken = default)
{
    await _db.RefreshTokens.AddAsync(new RefreshTokenEntity
    {
        Token = token,  // ❌ Raw token
        UserId = userId,
        ExpiresAt = expiresAt
    });
}

public async Task<RefreshTokenInfo?> ValidateAsync(string token, CancellationToken cancellationToken = default)
{
    var entity = await _db.RefreshTokens
        .FirstOrDefaultAsync(t => t.Token == token);  // ❌ Compare raw token

    if (entity == null) return null;

    return new RefreshTokenInfo  // ❌ Mutable class
    {
        Token = entity.Token,
        UserId = entity.UserId,
        ExpiresAt = entity.ExpiresAt,
        IsRevoked = entity.IsRevoked
    };
}
```

**After (v1.1):**
```csharp
public async Task StoreAsync(string tokenHash, string userId, DateTime expiresAt, CancellationToken cancellationToken = default)
{
    await _db.RefreshTokens.AddAsync(new RefreshTokenEntity
    {
        TokenHash = tokenHash,  // ✅ Framework sends hash
        UserId = userId,
        ExpiresAt = expiresAt
    });
}

public async Task<RefreshTokenInfo?> ValidateAsync(string tokenHash, CancellationToken cancellationToken = default)
{
    var entity = await _db.RefreshTokens
        .FirstOrDefaultAsync(t => t.TokenHash == tokenHash);  // ✅ Compare hash

    if (entity == null) return null;

    return new RefreshTokenInfo(  // ✅ Immutable record with TokenHash
        entity.TokenHash,
        entity.UserId,
        entity.ExpiresAt,
        entity.IsRevoked,
        entity.CreatedAt
    );
}
```

#### 3. Update Database Schema

**Add migration to rename columns:**

```csharp
// Entity Framework migration
public partial class RenameTokenToTokenHash : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        // Tokens table
        migrationBuilder.RenameColumn(
            name: "Token",
            table: "Tokens",
            newName: "TokenHash");

        // RefreshTokens table
        migrationBuilder.RenameColumn(
            name: "Token",
            table: "RefreshTokens",
            newName: "TokenHash");

        // Important: Invalidate all existing tokens (they are un-hashed)
        migrationBuilder.Sql("UPDATE Tokens SET IsInvalidated = 1");
        migrationBuilder.Sql("UPDATE RefreshTokens SET IsRevoked = 1");
    }

    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.RenameColumn(
            name: "TokenHash",
            table: "Tokens",
            newName: "Token");

        migrationBuilder.RenameColumn(
            name: "TokenHash",
            table: "RefreshTokens",
            newName: "Token");
    }
}
```

### Key Changes Summary

| Component | v0.2 | v1.1 |
|-----------|------|------|
| **Token Storage** | Raw tokens | SHA256 hashes |
| **TokenInfo** | Mutable class | Immutable record |
| **RefreshTokenInfo** | Mutable class with `Token` property | Immutable record with `TokenHash` property |
| **ITokenRepository.StoreTokenAsync** | `(userId, token, ...)` | `(userId, tokenHash, ...)` |
| **ITokenRepository.ValidateTokenAsync** | `(token, ...)` | `(tokenHash, ...)` |
| **ITokenRepository** | N/A | New: `ConsumeTokenAsync(tokenHash, ...)` |
| **IRefreshTokenRepository.StoreAsync** | `(token, userId, ...)` | `(tokenHash, userId, ...)` |
| **IRefreshTokenRepository.ValidateAsync** | `(token)` | `(tokenHash)` |
| **IRefreshTokenRepository.RevokeAsync** | `(token)` | `(tokenHash)` |

### Security Benefits

After migration, your application will benefit from:

✅ **Defense in depth** - Database compromise doesn't leak usable tokens
✅ **One-way hashing** - Tokens cannot be recovered from storage
✅ **Timing attack protection** - Constant-time token comparison
✅ **Token reuse prevention** - Atomic `ConsumeTokenAsync` method
✅ **Immutability** - Token models can't be accidentally modified

### Testing After Migration

Run your existing tests - they should all pass with the updated repository implementations. The framework handles all token hashing internally, so no changes are needed to your application logic.

## Examples

Check out the [sample applications](./samples):

- **MinimalApi Sample**: Complete working example with Hybrid mode and CSRF protection
- **Postman Collection**: Pre-configured requests with automatic CSRF handling

## Security Best Practices

Pawthorize is designed with security in mind:

1. **Password Security**: BCrypt hashing with automatic salting
2. **Token Hashing**: All tokens (email verification, password reset, refresh) are hashed using SHA256 before storage
   - Database compromise doesn't leak usable tokens
   - One-way hashing prevents token recovery
   - Constant-time comparison prevents timing attacks
3. **Token Rotation**: Refresh tokens rotate on every use
4. **HttpOnly Cookies**: Refresh tokens stored in HttpOnly cookies (Hybrid/HttpOnlyCookies mode)
5. **CSRF Protection**: Built-in Double Submit Cookie pattern with constant-time validation
6. **Secure Cookies**: Automatic `Secure` flag in production environments
7. **SameSite**: All cookies use `SameSite=Strict`
8. **Token Expiration**: Configurable lifetimes for all token types
9. **Session Management**: Users can view and revoke sessions across devices
10. **Account Locking**: Automatic account locking after failed attempts (optional)
11. **Email Verification**: Require email verification before access (optional)

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

- [Sample README](./samples/Pawthorize.Sample.MinimalApi/README.md) - Detailed sample with CSRF examples
- [Publishing Guide](./PUBLISH_AND_MIGRATE.md) - Version updates and migration guide
- [Commit Guide](./COMPLETE_COMMIT_GUIDE.md) - Contribution guidelines

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
