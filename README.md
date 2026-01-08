<div align="center">
  <img src="assets/logo.png" alt="Pawthorize Logo" width="200"/>

  # Pawthorize

  **Modern, production-ready authentication for ASP.NET Core** - batteries included.

  [![NuGet](https://img.shields.io/nuget/v/Pawthorize.svg)](https://www.nuget.org/packages/Pawthorize)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

  [Quick Start](#quick-start) • [Features](#features) • [Documentation](#documentation) • [Examples](#examples) • [OAuth Setup](#oauth-20-setup)
</div>

---

## 📦 What is Pawthorize?

Pawthorize is a complete, production-ready authentication library for ASP.NET Core that handles everything from user registration to OAuth 2.0 social login. Built for **Minimal APIs** and designed to get you from zero to secure authentication in minutes, not hours.

**Stop writing boilerplate auth code.** Pawthorize provides a secure, tested, and extensible foundation so you can focus on building your application.

### 🎯 Perfect For
- ✅ **New projects** that need authentication fast
- ✅ **Minimal API** applications (though it works with MVC too)
- ✅ **SPAs** (React, Vue, Angular) with JWT auth
- ✅ Projects requiring **OAuth 2.0** social login
- ✅ Apps with **session management** needs

---

## ✨ Features

### Core Authentication
- ✅ **User Registration & Login** - Email/password with BCrypt hashing
- ✅ **JWT Token Management** - Access + refresh tokens with automatic rotation
- ✅ **Password Reset Flow** - Secure token-based password recovery
- ✅ **Email Verification** - Optional email confirmation workflow
- ✅ **Session Management** - View and revoke active sessions across devices
- ✅ **Account Security** - Account locking, email verification requirements

### OAuth 2.0 Social Login
- ✅ **Google OAuth** - Sign in with Google
- ✅ **Discord OAuth** - Sign in with Discord
- ✅ **Account Linking** - Connect multiple OAuth providers to one account
- ✅ **Auto-Registration** - Automatically create accounts on first OAuth login
- ✅ **PKCE Support** - Enhanced security for OAuth flows (RFC 7636)
- ✅ **Extensible** - Easy to add more providers (GitHub, Facebook, etc.)

### Security
- ✅ **CSRF Protection** - Double Submit Cookie pattern with automatic token rotation
- ✅ **Secure Password Hashing** - BCrypt with automatic salting
- ✅ **Token Expiration** - Configurable TTLs for all tokens
- ✅ **Constant-Time Comparisons** - Protection against timing attacks
- ✅ **OAuth State Validation** - CSRF protection for OAuth flows

### Developer Experience
- ✅ **Flexible Token Delivery** - Cookies, response body, or hybrid strategies
- ✅ **Role-Based Authorization** - Automatic role claims in JWT (you manage roles)
- ✅ **Customizable Endpoints** - Custom paths or manual endpoint mapping
- ✅ **Integrated Error Handling** - ErrorHound integration for consistent API responses
- ✅ **OpenAPI/Swagger Support** - Automatic API documentation
- ✅ **FluentValidation** - Request validation out of the box
- ✅ **Extensible Architecture** - Easy to customize every aspect

---

## 🚀 Quick Start

### 1. Install Pawthorize

```bash
dotnet add package Pawthorize
```

### 2. Define Your User Model

```csharp
public class User : IAuthenticatedUser
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Name { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }
    public bool IsEmailVerified { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? LockedUntil { get; set; }
}
```

### 3. Implement Required Repositories

Pawthorize uses the repository pattern for data persistence. You need to implement:

```csharp
// User storage (Entity Framework, Dapper, etc.)
public class UserRepository : IUserRepository<User>
{
    public Task<User?> FindByEmailAsync(string email, CancellationToken ct) { /* ... */ }
    public Task<User?> FindByIdAsync(string id, CancellationToken ct) { /* ... */ }
    public Task CreateAsync(User user, CancellationToken ct) { /* ... */ }
    public Task UpdateAsync(User user, CancellationToken ct) { /* ... */ }
}

// Refresh token storage
public class RefreshTokenRepository : IRefreshTokenRepository
{
    public Task StoreAsync(string tokenHash, string userId, DateTime expiresAt, CancellationToken ct) { /* ... */ }
    public Task<string?> ValidateAndConsumeAsync(string tokenHash, CancellationToken ct) { /* ... */ }
    // ... other methods
}

// User factory for creating users from registration
public class UserFactory : IUserFactory<User, RegisterRequest>
{
    public User CreateUser(RegisterRequest request, string passwordHash)
    {
        return new User
        {
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name
        };
    }
}
```

**💡 Tip:** Check the [sample app](samples/Pawthorize.Sample.MinimalApi) for complete in-memory implementations.

### 4. Configure Pawthorize

**appsettings.json:**
```json
{
  "Pawthorize": {
    "RequireEmailVerification": false,
    "TokenDelivery": "Hybrid",
    "LoginIdentifier": "Email",
    "Csrf": {
      "Enabled": true
    }
  },
  "Jwt": {
    "Secret": "your-super-secret-jwt-key-at-least-32-characters-long",
    "Issuer": "YourApp",
    "Audience": "YourApp.Users",
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeDays": 7
  }
}
```

**Program.cs:**
```csharp
var builder = WebApplication.CreateBuilder(args);

// Add Pawthorize services
builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();
});

// Register your repositories
builder.Services.AddScoped<IUserRepository<User>, UserRepository>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUserFactory<User, RegisterRequest>, UserFactory>();

var app = builder.Build();

// Use Pawthorize middleware (ErrorHound, CSRF, Authentication)
app.UsePawthorize();

// Map all Pawthorize endpoints
app.MapPawthorize();

app.Run();
```

**That's it!** You now have a complete authentication system with 10+ endpoints:

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/logout` - Logout (revoke refresh token)
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (requires auth)
- `GET /api/auth/me` - Get current user info
- `GET /api/auth/sessions` - Get active sessions
- `POST /api/auth/sessions/revoke-others` - Revoke other sessions

### 5. Quick Start: Add OAuth (Optional)

Want social login? Add OAuth in minutes:

```csharp
// Program.cs - Add to your AddPawthorize configuration
builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();

    // Enable OAuth providers
    options.AddGoogle();
    options.AddDiscord();
});

// Register OAuth repository
builder.Services.AddScoped<IExternalAuthRepository<User>, ExternalAuthRepository>();
```

**appsettings.json:**
```json
{
  "Pawthorize": {
    "OAuth": {
      "AllowAutoRegistration": true,
      "UsePkce": true,
      "Providers": {
        "Google": {
          "Enabled": true,
          "ClientId": "YOUR_CLIENT_ID.apps.googleusercontent.com",
          "ClientSecret": "YOUR_CLIENT_SECRET",
          "RedirectUri": "http://localhost:5000/api/auth/oauth/google/callback"
        }
      }
    }
  }
}
```

**Frontend:**
```html
<button onclick="window.location.href='/api/auth/oauth/google'">
  Sign in with Google
</button>
```

That's it! See [OAuth 2.0 Setup](#oauth-20-setup) for detailed configuration.

---

## 🔐 OAuth 2.0 Setup

Pawthorize includes built-in support for Google and Discord OAuth. Add social login in 2 simple steps:

### 1. Enable OAuth Providers

Update your `AddPawthorize` configuration to include OAuth providers:

```csharp
builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();

    // Enable OAuth providers (state token storage is handled automatically)
    options.AddGoogle();
    options.AddDiscord();
    // options.AddCustomOAuthProvider<MyProvider>("myprovider"); // Custom providers supported
});

// Register only the external auth repository (state tokens are handled internally)
builder.Services.AddScoped<IExternalAuthRepository<User>, ExternalAuthRepository>();
```

**Note:** State token storage (for CSRF protection) is handled internally by Pawthorize. You only need to implement `IExternalAuthRepository<User>` to store linked OAuth accounts.

### 2. Configure OAuth Credentials

**appsettings.json:**
```json
{
  "Pawthorize": {
    "OAuth": {
      "AllowAutoRegistration": true,
      "UsePkce": true,
      "Providers": {
        "Google": {
          "Enabled": true,
          "ClientId": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
          "ClientSecret": "YOUR_GOOGLE_CLIENT_SECRET",
          "RedirectUri": "https://yourapp.com/api/auth/oauth/google/callback",
          "Scopes": ["openid", "profile", "email"]
        },
        "Discord": {
          "Enabled": true,
          "ClientId": "YOUR_DISCORD_CLIENT_ID",
          "ClientSecret": "YOUR_DISCORD_CLIENT_SECRET",
          "RedirectUri": "https://yourapp.com/api/auth/oauth/discord/callback",
          "Scopes": ["identify", "email"]
        }
      }
    }
  }
}
```

**Done!** OAuth endpoints are automatically mapped when you call `app.MapPawthorize()`. You now have 5 additional endpoints:

- `GET /api/auth/oauth/{provider}` - Initiate OAuth flow
- `GET /api/auth/oauth/{provider}/callback` - OAuth callback handler
- `POST /api/auth/oauth/{provider}/link` - Link provider to account
- `DELETE /api/auth/oauth/{provider}/unlink` - Unlink provider
- `GET /api/auth/oauth/linked` - List linked providers

### Getting OAuth Credentials

**Google:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable "Google+ API"
4. Go to "Credentials" → "Create Credentials" → "OAuth client ID"
5. Application type: "Web application"
6. Add authorized redirect URI: `http://localhost:5000/api/auth/oauth/google/callback`
7. Copy Client ID and Client Secret

**Discord:**
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to "OAuth2" section
4. Add redirect URI: `http://localhost:5000/api/auth/oauth/discord/callback`
5. Copy Client ID and Client Secret

---

## 📚 Documentation

### Token Delivery Strategies

Pawthorize supports three token delivery strategies:

#### 1. **ResponseBody** (Default for APIs)
```json
{
  "accessToken": "eyJhbGci...",
  "refreshToken": "def50200...",
  "tokenType": "Bearer",
  "expiresAt": "2024-01-15T10:30:00Z"
}
```

Best for: SPAs, mobile apps, third-party API consumers

#### 2. **HttpOnlyCookies** (Most Secure)
- Tokens stored in HttpOnly, Secure, SameSite cookies
- No response body tokens
- Automatic cookie authentication
- Best XSS protection

Best for: Server-rendered apps, same-origin SPAs

#### 3. **Hybrid** (Recommended for SPAs)
- Access token in response body
- Refresh token in HttpOnly cookie
- Balance of security and convenience

Best for: SPAs that need access token in JavaScript but want secure refresh

**Configure in appsettings.json:**
```json
{
  "Pawthorize": {
    "TokenDelivery": "Hybrid"  // or "ResponseBody" or "HttpOnlyCookies"
  }
}
```

### CSRF Protection

When using cookies (`Hybrid` or `HttpOnlyCookies`), Pawthorize automatically enables CSRF protection using the Double Submit Cookie pattern.

**How it works:**
1. On login/register, server generates a CSRF token
2. Token sent in both a cookie and response header
3. Client stores token and sends in `X-XSRF-TOKEN` header
4. Server validates token matches cookie

**Client implementation (JavaScript):**
```javascript
// After login, extract CSRF token
const csrfToken = response.headers.get('X-XSRF-TOKEN');
localStorage.setItem('csrfToken', csrfToken);

// Include in subsequent requests
fetch('/api/auth/logout', {
  method: 'POST',
  headers: {
    'X-XSRF-TOKEN': localStorage.getItem('csrfToken')
  },
  credentials: 'include' // Include cookies
});
```

### Role-Based Authorization

Pawthorize automatically adds roles from `IAuthenticatedUser.Roles` to JWT claims. You manage roles yourself:

```csharp
// Your User class
public class User : IAuthenticatedUser
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public string? Name { get; set; }

    // Populate this property based on your role system
    public IEnumerable<string> Roles { get; set; } = new List<string>();

    // ... other properties
}

// When creating/updating users, set their roles
var user = new User
{
    Email = "admin@example.com",
    Roles = new List<string> { "Admin", "Manager" } // Your role management logic
};

// Roles automatically added to JWT claims

// Protect endpoints using standard ASP.NET Core authorization
app.MapGet("/admin/users", () => { /* ... */ })
   .RequireAuthorization(policy => policy.RequireRole("Admin"));
```

**Note:** Pawthorize does not include role management features (creating roles, assigning roles to users). You implement role storage and management in your application, and Pawthorize will include them in JWT tokens.

### Endpoint Customization

Pawthorize offers flexible endpoint mapping options:

#### Option 1: Automatic Mapping (Default)

```csharp
// Maps all endpoints to /api/auth/*
app.MapPawthorize();
```

#### Option 2: Custom Base Path

```csharp
app.MapPawthorize(options =>
{
    options.BasePath = "/myapp/v1/auth";  // Changes base from /api/auth
    options.LoginPath = "/signin";         // Optional: customize individual paths
    options.RegisterPath = "/signup";
});

// Results in: /myapp/v1/auth/signin, /myapp/v1/auth/signup, etc.
```

#### Option 3: Manual Mapping (Full Control)

```csharp
var authGroup = app.MapGroup("/myapp/v1/auth");

// Map only the endpoints you need with custom policies
authGroup.MapPawthorizeLogin<User>()
    .RequireRateLimiting("auth");

authGroup.MapPawthorizeRegister<User, RegisterRequest>()
    .RequireRateLimiting("auth");

authGroup.MapPawthorizeRefresh<User>();
authGroup.MapPawthorizeLogout<User>();

// Available methods:
// - MapPawthorizeLogin<TUser>()
// - MapPawthorizeRegister<TUser, TRegisterRequest>()
// - MapPawthorizeRefresh<TUser>()
// - MapPawthorizeLogout<TUser>()
// - MapPawthorizeOAuth<TUser>() (if OAuth enabled)
```

### Custom Claims

```csharp
public class User : IAuthenticatedUser
{
    // ... other properties

    public IDictionary<string, string>? AdditionalClaims => new Dictionary<string, string>
    {
        ["department"] = "Engineering",
        ["tenant_id"] = "acme-corp"
    };
}

// Claims automatically added to JWT
// Access in endpoints: context.User.FindFirst("department")?.Value
```

### Email Verification

```csharp
// Enable in configuration
{
  "Pawthorize": {
    "RequireEmailVerification": true,
    "EmailVerification": {
      "BaseUrl": "https://yourapp.com",
      "TokenLifetimeMinutes": 1440
    }
  }
}

// Implement IEmailSender
public class EmailSender : IEmailSender
{
    public async Task SendEmailAsync(string to, string subject, string body, CancellationToken ct)
    {
        // Send email via SendGrid, AWS SES, etc.
    }
}

// Register
builder.Services.AddScoped<IEmailSender, EmailSender>();
builder.Services.AddScoped<IEmailVerificationService, EmailVerificationService>();
```

### Session Management

Users can view and revoke active sessions:

```http
GET /api/auth/sessions
Authorization: Bearer {accessToken}

Response:
{
  "sessions": [
    {
      "createdAt": "2024-01-15T10:00:00Z",
      "lastUsedAt": "2024-01-15T10:30:00Z",
      "expiresAt": "2024-01-22T10:00:00Z",
      "isCurrent": true
    }
  ]
}
```

```http
POST /api/auth/sessions/revoke-others
Authorization: Bearer {accessToken}

Revokes all sessions except current one.
```

### Rate Limiting

Pawthorize doesn't include rate limiting, but you can easily add it using ASP.NET Core's built-in rate limiting:

```csharp
// Program.cs
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Configure rate limiting
builder.Services.AddRateLimiter(options =>
{
    // Policy for authentication endpoints
    options.AddFixedWindowLimiter("auth", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 5; // 5 requests per minute
        opt.QueueLimit = 0;
    });

    // Stricter policy for login
    options.AddFixedWindowLimiter("login", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(5);
        opt.PermitLimit = 3; // 3 login attempts per 5 minutes
        opt.QueueLimit = 0;
    });
});

builder.Services.AddPawthorize<User>(/* ... */);

var app = builder.Build();

app.UseRateLimiter(); // Must be before MapPawthorize

// Apply to all auth endpoints
app.MapPawthorize(options => options.BasePath = "/api/auth")
   .RequireRateLimiting("auth");

// Or apply to individual endpoints
var authGroup = app.MapGroup("/api/auth");
authGroup.MapPawthorizeLogin<User>().RequireRateLimiting("login");
authGroup.MapPawthorizeRegister<User, RegisterRequest>().RequireRateLimiting("auth");
```

**Rate limiting by IP address:**

```csharp
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("auth", opt =>
    {
        opt.Window = TimeSpan.FromMinutes(1);
        opt.PermitLimit = 5;
        opt.QueueLimit = 0;
    });

    // Global rate limiter by IP
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(ipAddress, _ => new FixedWindowRateLimiterOptions
        {
            Window = TimeSpan.FromMinutes(1),
            PermitLimit = 100 // 100 requests per minute per IP
        });
    });
});
```

### Custom Validation

Extend built-in validators or create your own:

```csharp
public class CustomRegisterValidator : AbstractValidator<RegisterRequest>
{
    public CustomRegisterValidator()
    {
        RuleFor(x => x.Email).EmailAddress().Must(BeCompanyEmail);
        RuleFor(x => x.Password).MinimumLength(12);
    }

    private bool BeCompanyEmail(string email)
    {
        return email.EndsWith("@yourcompany.com");
    }
}

// Register
builder.Services.AddScoped<IValidator<RegisterRequest>, CustomRegisterValidator>();
```

---

## 💡 Examples

### Example 1: Basic SPA Authentication

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();
});

builder.Services.AddScoped<IUserRepository<User>, UserRepository>();
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IUserFactory<User, RegisterRequest>, UserFactory>();

var app = builder.Build();

app.UsePawthorize();
app.MapPawthorize();

app.Run();
```

```javascript
// client.js
async function register(email, password, name) {
  const response = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name })
  });

  const data = await response.json();
  localStorage.setItem('accessToken', data.accessToken);
  localStorage.setItem('refreshToken', data.refreshToken);
}

async function login(email, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await response.json();
  localStorage.setItem('accessToken', data.accessToken);
  localStorage.setItem('refreshToken', data.refreshToken);
}

async function callProtectedEndpoint() {
  const response = await fetch('/api/auth/me', {
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('accessToken')}`
    }
  });

  return response.json();
}

async function refreshToken() {
  const response = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      refreshToken: localStorage.getItem('refreshToken')
    })
  });

  const data = await response.json();
  localStorage.setItem('accessToken', data.accessToken);
  localStorage.setItem('refreshToken', data.refreshToken);
}
```

### Example 2: Hybrid Mode with CSRF Protection

```javascript
// client.js - Hybrid mode (access token in body, refresh in cookie)
async function login(email, password) {
  const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include' // Important: Include cookies
  });

  const data = await response.json();

  // Store access token
  localStorage.setItem('accessToken', data.accessToken);

  // Extract and store CSRF token from response header
  const csrfToken = response.headers.get('X-XSRF-TOKEN');
  localStorage.setItem('csrfToken', csrfToken);
}

// For state-changing requests, include CSRF token
async function logout() {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: {
      'X-XSRF-TOKEN': localStorage.getItem('csrfToken')
    },
    credentials: 'include'
  });

  localStorage.clear();
}

// Refresh uses cookie automatically
async function refreshAccessToken() {
  const response = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-XSRF-TOKEN': localStorage.getItem('csrfToken')
    },
    credentials: 'include',
    body: JSON.stringify({})
  });

  const data = await response.json();
  localStorage.setItem('accessToken', data.accessToken);

  // Update CSRF token if rotated
  const newCsrfToken = response.headers.get('X-XSRF-TOKEN');
  if (newCsrfToken) {
    localStorage.setItem('csrfToken', newCsrfToken);
  }
}
```

### Example 3: OAuth Social Login

```html
<!-- Login page -->
<button onclick="loginWithGoogle()">Sign in with Google</button>
<button onclick="loginWithDiscord()">Sign in with Discord</button>

<script>
function loginWithGoogle() {
  // Redirect to OAuth initiation endpoint
  window.location.href = '/api/auth/oauth/google?returnUrl=/dashboard';
}

function loginWithDiscord() {
  window.location.href = '/api/auth/oauth/discord?returnUrl=/dashboard';
}

// Link OAuth provider to existing account (user must be logged in)
async function linkGoogleAccount() {
  const response = await fetch('/api/auth/oauth/google/link', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
      'X-XSRF-TOKEN': localStorage.getItem('csrfToken')
    },
    credentials: 'include'
  });

  const data = await response.json();
  if (data.authUrl) {
    // Redirect to OAuth provider
    window.location.href = data.authUrl;
  }
}

// After OAuth callback, tokens are set via cookies or returned in URL
// User is redirected to /dashboard
</script>
```

### Example 4: Custom Endpoint Paths

You can customize the base path and individual endpoint paths:

```csharp
// Program.cs
app.MapPawthorize(options =>
{
    // Change base path from /api/auth to /myapp/v1/auth
    options.BasePath = "/myapp/v1/auth";

    // Or customize individual endpoints
    options.LoginPath = "/signin";
    options.RegisterPath = "/signup";
    options.LogoutPath = "/signout";
});

// Results in endpoints like:
// POST /myapp/v1/auth/signin
// POST /myapp/v1/auth/signup
// POST /myapp/v1/auth/signout
```

### Example 5: Manual Endpoint Mapping

For full control, map endpoints individually:

```csharp
// Program.cs - Don't call MapPawthorize()
var authGroup = app.MapGroup("/myapp/v1/auth");

// Map only the endpoints you want
authGroup.MapPawthorizeLogin<User>()
    .RequireRateLimiting("auth"); // Add custom policies

authGroup.MapPawthorizeRegister<User, RegisterRequest>()
    .RequireRateLimiting("auth");

authGroup.MapPawthorizeRefresh<User>();

authGroup.MapPawthorizeLogout<User>();

// Don't map endpoints you don't need (e.g., password reset)
```

### Example 6: Direct Handler Usage (Maximum Control)

For complete control over endpoint logic, inject handlers directly:

```csharp
// Program.cs
app.MapPost("/api/v1/auth/login", async (
    LoginRequest request,
    LoginHandler<User> handler,
    HttpContext context,
    CancellationToken ct) =>
{
    // Add custom logic before authentication
    Console.WriteLine($"Login attempt from IP: {context.Connection.RemoteIpAddress}");

    // Call Pawthorize handler
    var result = await handler.HandleAsync(request, context, ct);

    // Add custom logic after authentication
    Console.WriteLine("Login successful");

    return result;
})
.RequireRateLimiting("login-limiter");

app.MapPost("/api/v1/auth/register", async (
    RegisterRequest request,
    RegisterHandler<User, RegisterRequest> handler,
    HttpContext context,
    CancellationToken ct) =>
{
    // Add custom validation or business logic
    if (request.Email.EndsWith("@blocked-domain.com"))
    {
        return Results.BadRequest("Email domain not allowed");
    }

    return await handler.HandleAsync(request, context, ct);
});

// Available handlers you can inject:
// - LoginHandler<TUser>
// - RegisterHandler<TUser, TRegisterRequest>
// - RefreshHandler<TUser>
// - LogoutHandler<TUser>
// - ChangePasswordHandler<TUser>
// - ForgotPasswordHandler
// - ResetPasswordHandler
// - GetCurrentUserHandler<TUser>
// - GetActiveSessionsHandler<TUser>
// - RevokeAllOtherSessionsHandler<TUser>
// - OAuthInitiateHandler<TUser> (if OAuth enabled)
// - OAuthCallbackHandler<TUser> (if OAuth enabled)
// - LinkProviderHandler<TUser> (if OAuth enabled)
// - UnlinkProviderHandler<TUser> (if OAuth enabled)
// - ListLinkedProvidersHandler<TUser> (if OAuth enabled)
```

---

## 🏗️ Architecture

Pawthorize follows clean architecture principles:

```
┌─────────────────────────────────────────────┐
│          Your Application Layer             │
│  (Controllers, Minimal API Endpoints)       │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Pawthorize Handlers Layer           │
│  (LoginHandler, RegisterHandler, etc.)      │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Pawthorize Services Layer           │
│  (JwtService, PasswordHasher, etc.)         │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│         Your Repository Layer               │
│  (IUserRepository, IRefreshTokenRepository) │
└─────────────────────────────────────────────┘
                    ↓
┌─────────────────────────────────────────────┐
│            Your Database                    │
│  (SQL Server, PostgreSQL, MongoDB, etc.)    │
└─────────────────────────────────────────────┘
```

**Key Design Principles:**
- **Repository Pattern**: Abstract data access for flexibility
- **Dependency Injection**: Fully DI-compatible
- **Options Pattern**: Configuration via IOptions
- **Handler Pattern**: Each endpoint has a dedicated handler
- **Separation of Concerns**: Authentication, authorization, and data access are separate

---

## 🔧 Troubleshooting

### Common Issues

#### "Invalid or expired token"
- **Cause**: Token expired or clock skew between servers
- **Fix**: Ensure server clocks are synchronized, check token lifetime configuration

#### "CSRF token validation failed"
- **Cause**: Missing or incorrect CSRF token in request
- **Fix**: Include `X-XSRF-TOKEN` header with token from login response
- **Fix**: Ensure `credentials: 'include'` in fetch requests

#### "Duplicate email error" during OAuth
- **Cause**: Email from OAuth provider already exists in database with password-based account
- **Fix Option 1**: User should login with password first, then use `/api/auth/oauth/{provider}/link` to link the OAuth account
- **Fix Option 2**: User can use "forgot password" to reset their password and then link OAuth
- **Prevention**: Enable `AllowAutoRegistration: false` to require manual account linking

#### OAuth redirect not working
- **Cause**: Redirect URI mismatch between config and OAuth provider settings
- **Fix**:
  - Ensure `RedirectUri` in appsettings.json **exactly** matches OAuth provider console
  - Check for trailing slashes, http vs https, port numbers
  - Example: `http://localhost:5000/api/auth/oauth/google/callback` (no trailing slash)
- **Common mistake**: Using `localhost` in appsettings but `127.0.0.1` in OAuth console (or vice versa)

#### "Provider not configured" error
- **Cause**: OAuth provider not enabled or missing credentials
- **Fix**:
  - Check `appsettings.json` - ensure `Enabled: true` and credentials are set
  - Verify `options.AddGoogle()` or `options.AddDiscord()` is called in `Program.cs`
  - Restart the application after config changes

#### "Invalid state" or "State mismatch" error
- **Cause**: OAuth state token expired or tampered with (CSRF protection)
- **Fix**:
  - State tokens are valid for 10 minutes by default
  - User should complete OAuth flow within this time
  - Check server time synchronization if persistent issues
- **Note**: This is a security feature - don't disable it

#### "invalid_grant" from OAuth provider
- **Cause**: Authorization code already used or expired
- **Fix**:
  - Restart OAuth flow from beginning
  - Don't refresh the callback page
  - Authorization codes are single-use and short-lived (typically 10 minutes)

#### OAuth works locally but not in production
- **Cause**: Redirect URI not configured for production domain
- **Fix**:
  - Add production redirect URI to OAuth provider console
  - Example: `https://yourapp.com/api/auth/oauth/google/callback`
  - Update `RedirectUri` in production appsettings.json
  - Ensure HTTPS is enabled in production

#### User email not returned from OAuth provider
- **Cause**: Email scope not requested or user denied email permission
- **Fix**:
  - Verify `Scopes` in appsettings.json includes email scope
  - Google: `["openid", "profile", "email"]`
  - Discord: `["identify", "email"]`
  - If user denied permission, they need to re-authorize

#### Cannot unlink last OAuth provider
- **Cause**: User has no password and trying to unlink their only login method
- **Fix**:
  - Require user to set a password first using `/api/auth/change-password`
  - Or link another OAuth provider before unlinking
  - This prevents account lockout

### Error Response Format

Pawthorize uses ErrorHound for consistent error responses:

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "status": 401,
    "details": null
  }
}
```

### Debug Logging

Enable debug logging for Pawthorize:

```json
{
  "Logging": {
    "LogLevel": {
      "Pawthorize": "Debug"
    }
  }
}
```

---

## 🎯 Roadmap

- [ ] **More OAuth Providers**: GitHub, Microsoft, Facebook, Twitter
- [ ] **Two-Factor Authentication (2FA)**: TOTP, SMS, Email codes
- [ ] **Built-in Rate Limiting**: Configurable rate limiting for auth endpoints (currently users can add their own via ASP.NET Core)
- [ ] **Magic Links**: Passwordless email login
- [ ] **Audit Logging**: Track authentication events
- [ ] **Progressive Account Lockout**: Automatic lockout after failed attempts
- [ ] **WebAuthn Support**: Biometric authentication
- [ ] **OpenID Connect**: Full OIDC compliance

---



---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<div align="center">
  Made by Cydo Entis

  **Star ⭐ this repo if you find it helpful!**
</div>
