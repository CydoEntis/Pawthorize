# Pawthorize Sample - Minimal API

A complete **production-ready reference implementation** demonstrating **Pawthorize** authentication library with ASP.NET Core Minimal APIs.

## Features Demonstrated

- ✅ **Hybrid Token Delivery** - Access tokens in response, refresh tokens in HttpOnly cookies
- ✅ **Built-in CSRF Protection** - Automatic token generation and validation
- ✅ **Enhanced Session Management** - Device tracking, IP addresses, per-session revocation (v0.7.2)
- ✅ **Detailed Validation Errors** - Field-level error reporting (v0.7.2)
- ✅ **Password Policy Enforcement** - Configurable password strength requirements (v0.7.0)
- ✅ **Account Lockout Protection** - Brute force protection with failed attempt tracking (v0.7.0)
- ✅ **Built-in Rate Limiting** - IP-based rate limiting for all endpoints (v0.7.0)
- ✅ **User Registration** - Email/password with validation
- ✅ **User Login** - JWT access tokens with cookie-based refresh tokens
- ✅ **Token Refresh** - Automatic refresh token rotation with CSRF token rotation
- ✅ **Logout** - Token revocation with cookie cleanup
- ✅ **Swagger UI** - Interactive API documentation
- ✅ **Postman Collection** - Automatic CSRF token handling

## What's New - Hybrid Mode + CSRF

This sample demonstrates **best practices** for modern web applications:

### Token Delivery Strategy: **Hybrid**
- **Access Token**: Returned in JSON response (short-lived, 15 minutes)
- **Refresh Token**: Stored in HttpOnly cookie (long-lived, 7 days)
- **CSRF Token**: Stored in readable cookie, validated on state-changing requests

### Why Hybrid Mode?
- ✅ **Secure**: Refresh tokens protected from XSS attacks
- ✅ **Convenient**: Access tokens available for API calls
- ✅ **CSRF Protected**: Built-in protection against cross-site request forgery
- ✅ **Best Practice**: Recommended for SPAs and modern web apps

## Prerequisites

- .NET 8.0 SDK or later
- Postman (for testing with the included collection)

## Getting Started

### 1. Run the Application

From the sample directory:

```bash
cd samples/Pawthorize.Sample.MinimalApi
dotnet run
```

The API will start on `http://localhost:5022` (as configured in `appsettings.json`).

### 2. Access Swagger UI

Open your browser to:
```
http://localhost:5022/swagger
```

You can test all endpoints interactively through Swagger UI.

### 3. Import Postman Collection (Recommended)

The included Postman collection **automatically handles** CSRF tokens and cookies.

1. Open Postman
2. Click **Import** → **Upload Files**
3. Select `Pawthorize-Sample.postman_collection.json`
4. Collection is ready to use!

**Features of the Postman Collection:**
- ✅ Automatic CSRF token extraction from cookies
- ✅ Automatic CSRF token injection into request headers
- ✅ Automatic access token storage and management
- ✅ Pre-configured test scripts
- ✅ Collection variables for easy customization

## Using the Postman Collection

### Automatic CSRF Handling

The collection includes **pre-request scripts** that automatically:

1. **Extract CSRF token** from `XSRF-TOKEN` cookie
2. **Add it to request headers** as `X-XSRF-TOKEN`
3. **Store access tokens** from responses
4. **Inject access tokens** into `Authorization` headers

**You don't need to do anything - it's all automatic!**

### Quick Start with Postman

1. **Run "1. Register"** - Creates a new user
   - Access token saved automatically
   - CSRF token set in cookie
   - Refresh token set in cookie

2. **Run "2. Login"** - Login with credentials
   - New tokens issued
   - Cookies updated

3. **Run "3. Get Current User"** - Get user profile
   - Uses stored access token
   - No CSRF needed (GET request)

4. **Run "4. Refresh Token"** - Get new access token
   - Uses refresh token from cookie
   - CSRF token automatically included
   - New tokens issued

5. **Run "8. Logout"** - Revoke tokens
   - Cookies cleared
   - Access token removed

### Test CSRF Protection

Run **"Test - CSRF Protection (Should Fail)"**:
- Deliberately removes CSRF token
- Should return **403 Forbidden**
- Proves CSRF protection is working

### Postman Collection Variables

Edit these in the collection variables:

- `baseUrl`: `http://localhost:5022` (default)
- `testEmail`: `test@example.com` (default)
- `testPassword`: `Test123!` (default)

## API Endpoints

### Base URL
```
http://localhost:5022
```

### Authentication Endpoints

All authentication endpoints are prefixed with `/auth`.

---

#### 1. Register

**POST** `/auth/register`

Creates a new user account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "name": "John Doe"
}
```

**Success Response (200 OK) - Hybrid Mode:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": null,
    "accessTokenExpiresAt": "2025-12-29T12:15:00Z",
    "refreshTokenExpiresAt": "2026-01-05T12:00:00Z",
    "tokenType": "Bearer"
  },
  "meta": {
    "timestamp": "2025-12-29T12:00:00Z",
    "version": "v0.3"
  }
}
```

**Cookies Set:**
- `refresh_token` (HttpOnly, Secure, SameSite=Strict)
- `XSRF-TOKEN` (Secure, SameSite=Strict, readable by JS)

**Error Response (400 Bad Request) - Validation Error:**
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION",
    "message": "Validation failed",
    "details": {
      "Email": [
        "Email must be a valid email address"
      ],
      "Password": [
        "Password must be at least 8 characters",
        "Password must contain at least one uppercase letter"
      ]
    }
  },
  "meta": {
    "timestamp": "2025-12-29T12:00:00Z",
    "version": "v0.3"
  }
}
```

**Error Response (409 Conflict) - Duplicate Email:**
```json
{
  "success": false,
  "error": {
    "code": "USER_ALREADY_EXISTS",
    "message": "A user with this email already exists",
    "details": null
  },
  "meta": {
    "timestamp": "2025-12-29T12:00:00Z",
    "version": "v0.3"
  }
}
```

---

#### 2. Login

**POST** `/auth/login`

Authenticate with email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": null,
    "accessTokenExpiresAt": "2025-12-29T12:15:00Z",
    "refreshTokenExpiresAt": "2026-01-05T12:00:00Z",
    "tokenType": "Bearer"
  }
}
```

**Cookies Set:**
- `refresh_token` (HttpOnly)
- `XSRF-TOKEN` (readable)

---

#### 3. Get Current User

**GET** `/auth/me`

Get authenticated user profile.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response:**
```json
{
  "success": true,
  "data": {
    "id": "user-id-123",
    "email": "user@example.com",
    "name": "John Doe",
    "isEmailVerified": false
  }
}
```

**Note:** GET requests don't require CSRF token.

---

#### 4. Refresh Token

**POST** `/auth/refresh`

Get new access token using refresh token cookie.

**Headers:**
```
X-XSRF-TOKEN: <csrf_token>
Cookie: refresh_token=<token>
```

**Request Body:**
```json
{
  "refreshToken": ""
}
```

**Note:** `refreshToken` in body is optional - automatically read from cookie.

**Success Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": null,
    "accessTokenExpiresAt": "2025-12-29T12:30:00Z",
    "refreshTokenExpiresAt": "2026-01-05T12:15:00Z",
    "tokenType": "Bearer"
  }
}
```

**Cookies Updated:**
- New `refresh_token` (rotated)
- New `XSRF-TOKEN` (rotated)

---

#### 5. Change Password

**POST** `/auth/change-password`

Change password for authenticated user.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

**Request:**
```json
{
  "currentPassword": "SecureP@ssw0rd",
  "newPassword": "NewSecureP@ssw0rd",
  "confirmPassword": "NewSecureP@ssw0rd"
}
```

---

#### 6. Get Active Sessions

**GET** `/auth/sessions`

List all active sessions (refresh tokens) for current user with detailed device and IP information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response:**
```json
{
  "success": true,
  "data": [
    {
      "sessionId": "abc123...",
      "userId": "user-123",
      "deviceInfo": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
      "ipAddress": "192.168.1.100",
      "createdAt": "2024-01-15T10:00:00Z",
      "expiresAt": "2024-01-22T10:00:00Z",
      "lastActivityAt": "2024-01-15T10:30:00Z",
      "isExpired": false,
      "isCurrentSession": true
    },
    {
      "sessionId": "def456...",
      "userId": "user-123",
      "deviceInfo": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0)",
      "ipAddress": "10.0.0.50",
      "createdAt": "2024-01-14T08:00:00Z",
      "expiresAt": "2024-01-21T08:00:00Z",
      "lastActivityAt": "2024-01-14T09:15:00Z",
      "isExpired": false,
      "isCurrentSession": false
    }
  ]
}
```

---

#### 7. Revoke Specific Session (v0.7.2+)

**POST** `/auth/sessions/revoke`

Revoke a specific session by its session ID.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

**Request:**
```json
{
  "sessionId": "def456..."
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Session revoked successfully."
}
```

---

#### 8. Revoke Other Sessions

**POST** `/auth/sessions/revoke-others`

Revoke all other sessions except the current one.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

---

#### 9. Logout

**POST** `/auth/logout`

Revoke refresh token and clear cookies.

**Headers:**
```
X-XSRF-TOKEN: <csrf_token>
Cookie: refresh_token=<token>
```

**Request:**
```json
{
  "refreshToken": ""
}
```

**Success Response:**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

**Cookies Cleared:**
- `refresh_token`
- `XSRF-TOKEN`

---

## OAuth 2.0 Social Login

The sample app includes full OAuth support for Google and Discord. Follow these steps to enable social login.

### OAuth Endpoints

#### 1. Initiate OAuth Flow

**GET** `/auth/oauth/{provider}`

Redirects user to OAuth provider (Google, Discord, etc.) for authentication.

**Parameters:**
- `provider` (path): `google` or `discord`
- `returnUrl` (query, optional): URL to redirect after successful authentication

**Example:**
```
http://localhost:5022/auth/oauth/google?returnUrl=/dashboard
```

**What happens:**
1. Server generates secure state token (CSRF protection)
2. Redirects to OAuth provider's authorization page
3. User authorizes the app
4. Provider redirects back to callback URL

---

#### 2. OAuth Callback (Automatic)

**GET** `/auth/oauth/{provider}/callback`

OAuth provider redirects here after user authorization. **This endpoint is called automatically by the OAuth provider** - you don't call it directly.

**Query Parameters (from OAuth provider):**
- `code`: Authorization code
- `state`: State token for CSRF protection

**Success Flow:**
1. Validates state token
2. Exchanges authorization code for access token with OAuth provider
3. Fetches user info from OAuth provider
4. Creates or links user account
5. Issues JWT tokens (access + refresh)
6. Redirects to `returnUrl` or default page

---

#### 3. Link OAuth Provider to Account

**POST** `/auth/oauth/{provider}/link`

Links an OAuth provider to an existing authenticated account.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

**Request Body:**
```json
{}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "authUrl": "https://accounts.google.com/o/oauth2/v2/auth?..."
  }
}
```

**What to do:**
Redirect user to `authUrl` to complete OAuth flow. After authorization, the provider will be linked to their account.

---

#### 4. Unlink OAuth Provider

**DELETE** `/auth/oauth/{provider}/unlink`

Removes OAuth provider link from authenticated account.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Provider unlinked successfully"
}
```

**Note:** Cannot unlink if it's the user's only login method and they have no password.

---

#### 5. List Linked Providers

**GET** `/auth/oauth/linked`

Gets all OAuth providers linked to authenticated account.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Success Response:**
```json
{
  "success": true,
  "data": {
    "providers": ["google", "discord"]
  }
}
```

---

### Enabling OAuth in Sample App

By default, OAuth is **not enabled** in the sample app. To enable it:

#### Step 1: Update appsettings.json

Add OAuth configuration:

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
          "RedirectUri": "http://localhost:5022/auth/oauth/google/callback",
          "Scopes": ["openid", "profile", "email"]
        },
        "Discord": {
          "Enabled": true,
          "ClientId": "YOUR_DISCORD_CLIENT_ID",
          "ClientSecret": "YOUR_DISCORD_CLIENT_SECRET",
          "RedirectUri": "http://localhost:5022/auth/oauth/discord/callback",
          "Scopes": ["identify", "email"]
        }
      }
    }
  }
}
```

#### Step 2: Update Program.cs

Enable OAuth providers:

```csharp
builder.Services.AddPawthorize<User>(options =>
{
    options.UseConfiguration(builder.Configuration);
    options.UseDefaultFormatters();

    // Enable OAuth providers
    options.AddGoogle();
    options.AddDiscord();
});

// Register OAuth repository
builder.Services.AddScoped<IExternalAuthRepository<User>, InMemoryExternalAuthRepository>();
```

#### Step 3: Get OAuth Credentials

**For Google:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable "Google+ API"
4. Go to "Credentials" → "Create Credentials" → "OAuth client ID"
5. Application type: "Web application"
6. Add redirect URI: `http://localhost:5022/auth/oauth/google/callback`
7. Copy Client ID and Client Secret to appsettings.json

**For Discord:**
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to "OAuth2" section
4. Add redirect URI: `http://localhost:5022/auth/oauth/discord/callback`
5. Copy Client ID and Client Secret to appsettings.json

#### Step 4: Restart and Test

Restart the app and test OAuth:

```
http://localhost:5022/auth/oauth/google
```

You'll be redirected to Google's login page. After authorizing, you'll be redirected back with tokens.

---

### OAuth Testing with Postman

If you updated the Postman collection to include OAuth endpoints:

**1. Initiate OAuth (Manual)**
- Cannot test directly in Postman (requires browser redirect)
- Open in browser: `http://localhost:5022/auth/oauth/google`

**2. Link Provider to Account**
- Request: `POST http://localhost:5022/auth/oauth/google/link`
- Headers: Authorization + X-XSRF-TOKEN
- Response includes `authUrl` - open in browser

**3. List Linked Providers**
- Request: `GET http://localhost:5022/auth/oauth/linked`
- Headers: Authorization Bearer token

**4. Unlink Provider**
- Request: `DELETE http://localhost:5022/auth/oauth/google/unlink`
- Headers: Authorization + X-XSRF-TOKEN

---

### OAuth Frontend Example

```html
<!DOCTYPE html>
<html>
<head>
  <title>OAuth Login Example</title>
</head>
<body>
  <h1>Login</h1>

  <!-- Traditional login -->
  <form id="loginForm">
    <input type="email" id="email" placeholder="Email" required />
    <input type="password" id="password" placeholder="Password" required />
    <button type="submit">Login</button>
  </form>

  <hr>

  <!-- OAuth buttons -->
  <button onclick="loginWithGoogle()">Sign in with Google</button>
  <button onclick="loginWithDiscord()">Sign in with Discord</button>

  <script>
    // Traditional login
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      const response = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();
      if (data.success) {
        localStorage.setItem('accessToken', data.data.accessToken);
        const csrfToken = response.headers.get('X-XSRF-TOKEN');
        localStorage.setItem('csrfToken', csrfToken);
        window.location.href = '/dashboard';
      }
    });

    // OAuth login
    function loginWithGoogle() {
      window.location.href = '/auth/oauth/google?returnUrl=/dashboard';
    }

    function loginWithDiscord() {
      window.location.href = '/auth/oauth/discord?returnUrl=/dashboard';
    }

    // Link OAuth provider (user must be logged in)
    async function linkGoogleAccount() {
      const response = await fetch('/auth/oauth/google/link', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('accessToken')}`,
          'X-XSRF-TOKEN': localStorage.getItem('csrfToken')
        },
        credentials: 'include',
        body: JSON.stringify({})
      });

      const data = await response.json();
      if (data.success && data.data.authUrl) {
        // Redirect to OAuth provider
        window.location.href = data.data.authUrl;
      }
    }
  </script>
</body>
</html>
```

---

### OAuth Flow Diagram

```
User clicks "Sign in with Google"
         ↓
GET /auth/oauth/google
         ↓
Server generates state token
         ↓
Redirect to Google OAuth page
         ↓
User authorizes app
         ↓
Google redirects to /auth/oauth/google/callback?code=...&state=...
         ↓
Server validates state token
         ↓
Server exchanges code for access token with Google
         ↓
Server fetches user info from Google
         ↓
Server creates/links user account
         ↓
Server issues JWT tokens
         ↓
Redirect to returnUrl with tokens
```

---

### OAuth Configuration Options

**In appsettings.json:**

```json
{
  "Pawthorize": {
    "OAuth": {
      // Allow creating accounts via OAuth without password
      "AllowAutoRegistration": true,

      // Use PKCE for enhanced security (recommended)
      "UsePkce": true,

      // State token lifetime (for CSRF protection)
      "StateTokenLifetimeMinutes": 10,

      "Providers": {
        "Google": {
          "Enabled": true,
          "ClientId": "...",
          "ClientSecret": "...",

          // Must match OAuth provider console exactly
          "RedirectUri": "http://localhost:5022/auth/oauth/google/callback",

          // Scopes determine what data you can access
          "Scopes": ["openid", "profile", "email"],

          // Optional: Override default authorization endpoint
          "AuthorizationEndpoint": "https://accounts.google.com/o/oauth2/v2/auth",

          // Optional: Override default token endpoint
          "TokenEndpoint": "https://oauth2.googleapis.com/token",

          // Optional: Override default user info endpoint
          "UserInfoEndpoint": "https://www.googleapis.com/oauth2/v2/userinfo"
        }
      }
    }
  }
}
```

---

### OAuth Troubleshooting

#### Redirect URI Mismatch
**Error:** `redirect_uri_mismatch` from OAuth provider

**Fix:**
- Ensure `RedirectUri` in appsettings.json **exactly** matches OAuth provider console
- Check for: trailing slashes, http vs https, port numbers, localhost vs 127.0.0.1

#### Invalid State Token
**Error:** `Invalid or expired state token`

**Causes:**
- User took longer than 10 minutes to authorize
- Browser cleared cookies
- PKCE code verifier mismatch

**Fix:**
- Restart OAuth flow
- Check browser allows cookies

#### Email Already Exists
**Error:** `Email already registered`

**Scenario:** User tries to login via OAuth but email exists with password-based account

**Fix:**
- User should login with password first
- Then use `/auth/oauth/{provider}/link` to link OAuth account
- Or enable `AllowAutoRegistration: false` to prevent auto-registration

#### Provider Not Configured
**Error:** `OAuth provider 'google' is not configured or disabled`

**Fix:**
- Check `Enabled: true` in appsettings.json
- Verify `options.AddGoogle()` is called in Program.cs
- Restart application after config changes

#### PKCE Verification Failed
**Error:** `PKCE code verification failed`

**Causes:**
- Code verifier doesn't match code challenge
- State token storage issue

**Fix:**
- Ensure `UsePkce: true` is set if provider requires it
- Check state token storage implementation
- Verify browser allows cookies

---

## Customizing Endpoint Paths

The sample uses the default endpoint paths (`/auth/*`), but Pawthorize supports customization:

### Option 1: Custom Base Path

```csharp
// Program.cs
app.MapPawthorize(options =>
{
    options.BasePath = "/myapp/v1/auth";  // Change from /auth to /myapp/v1/auth
});

// Endpoints become:
// POST /myapp/v1/auth/login
// POST /myapp/v1/auth/register
// etc.
```

### Option 2: Custom Individual Paths

```csharp
app.MapPawthorize(options =>
{
    options.BasePath = "/auth";
    options.LoginPath = "/signin";
    options.RegisterPath = "/signup";
    options.LogoutPath = "/signout";
});

// Endpoints become:
// POST /auth/signin
// POST /auth/signup
// POST /auth/signout
```

### Option 3: Manual Mapping

```csharp
// Don't call MapPawthorize()
var authGroup = app.MapGroup("/myapp/v1/auth");

// Map only the endpoints you need
authGroup.MapPawthorizeLogin<User>();
authGroup.MapPawthorizeRegister<User, RegisterRequest>();
authGroup.MapPawthorizeRefresh<User>();
authGroup.MapPawthorizeLogout<User>();

// Available methods:
// - MapPawthorizeLogin<TUser>()
// - MapPawthorizeRegister<TUser, TRegisterRequest>()
// - MapPawthorizeRefresh<TUser>()
// - MapPawthorizeLogout<TUser>()
// - MapPawthorizeOAuth<TUser>() (if OAuth enabled)
```

This gives you full control over which endpoints to expose and lets you add custom policies like rate limiting.

### Option 4: Direct Handler Injection (Maximum Control)

For complete control, inject handlers directly into your own endpoints:

```csharp
// Don't call MapPawthorize() at all
app.MapPost("/api/v1/auth/login", async (
    LoginRequest request,
    LoginHandler<User> handler,
    HttpContext context,
    CancellationToken ct) =>
{
    // Add custom logic before authentication
    var ip = context.Connection.RemoteIpAddress?.ToString();
    Console.WriteLine($"Login attempt from IP: {ip}");

    // Call Pawthorize handler
    var result = await handler.HandleAsync(request, context, ct);

    // Add custom logic after authentication
    Console.WriteLine("Login successful");

    return result;
});

// Available handlers:
// - LoginHandler<TUser>
// - RegisterHandler<TUser, TRegisterRequest>
// - RefreshHandler<TUser>
// - LogoutHandler<TUser>
// - ChangePasswordHandler<TUser>
// - ForgotPasswordHandler, ResetPasswordHandler
// - GetCurrentUserHandler<TUser>, GetActiveSessionsHandler<TUser>
// - OAuth handlers (if enabled): OAuthInitiateHandler<TUser>, OAuthCallbackHandler<TUser>, etc.
```

This approach gives you maximum flexibility to add logging, custom validation, rate limiting, or any other middleware logic around Pawthorize's core authentication functionality.

---

## Configuration

Configuration in `appsettings.json`:

```json
{
  "Pawthorize": {
    "RequireEmailVerification": false,
    "TokenDelivery": "Hybrid",
    "LoginIdentifier": "Email",
    "PasswordReset": {
      "BaseUrl": "http://localhost:5022",
      "ApplicationName": "Pawthorize Sample"
    },
    "Csrf": {
      "Enabled": true,
      "CookieName": "XSRF-TOKEN",
      "HeaderName": "X-XSRF-TOKEN",
      "TokenLifetimeMinutes": 10080
    },
    "PasswordPolicy": {
      "MinLength": 8,
      "MaxLength": 128,
      "RequireUppercase": true,
      "RequireLowercase": true,
      "RequireDigit": true,
      "RequireSpecialChar": true,
      "BlockCommonPasswords": true
    },
    "AccountLockout": {
      "Enabled": true,
      "MaxFailedAttempts": 5,
      "LockoutMinutes": 30,
      "ResetOnSuccessfulLogin": true
    },
    "RateLimiting": {
      "Enabled": true,
      "PermitLimit": 100,
      "WindowMinutes": 1,
      "EndpointSpecificLimits": {
        "Login": {
          "PermitLimit": 5,
          "WindowMinutes": 5
        },
        "Register": {
          "PermitLimit": 3,
          "WindowMinutes": 10
        },
        "ForgotPassword": {
          "PermitLimit": 3,
          "WindowMinutes": 15
        }
      }
    }
  },
  "Jwt": {
    "Secret": "this-is-a-super-secret-key-for-jwt-tokens-min-32-chars",
    "Issuer": "PawthorizeSample",
    "Audience": "PawthorizeSample",
    "AccessTokenLifetimeMinutes": 15,
    "RefreshTokenLifetimeDays": 7
  }
}
```

### Key Settings

**Pawthorize:**
- `TokenDelivery`: `"Hybrid"` - Access token in body, refresh in cookie
- `RequireEmailVerification`: `false` - Disabled for easier testing
- `LoginIdentifier`: `"Email"` - Login with email

**CSRF:**
- `Enabled`: `true` - CSRF protection enabled
- `CookieName`: `"XSRF-TOKEN"` - Cookie name for CSRF token
- `HeaderName`: `"X-XSRF-TOKEN"` - Header name for CSRF token
- `TokenLifetimeMinutes`: `10080` - 7 days

**JWT:**
- `AccessTokenLifetimeMinutes`: `15` - Short-lived access tokens
- `RefreshTokenLifetimeDays`: `7` - Long-lived refresh tokens

**Password Policy (v0.7.0):**
- `MinLength`: `8` - Minimum password length
- `RequireUppercase`: `true` - Require at least one uppercase letter
- `RequireLowercase`: `true` - Require at least one lowercase letter
- `RequireDigit`: `true` - Require at least one digit
- `RequireSpecialChar`: `true` - Require at least one special character
- `BlockCommonPasswords`: `true` - Block top 1000 common passwords

**Account Lockout (v0.7.0):**
- `Enabled`: `true` - Account lockout enabled
- `MaxFailedAttempts`: `5` - Lock account after 5 failed login attempts
- `LockoutMinutes`: `30` - Lock account for 30 minutes
- `ResetOnSuccessfulLogin`: `true` - Reset failed attempts counter on successful login

**Rate Limiting (v0.7.0):**
- `Enabled`: `true` - Rate limiting enabled
- `PermitLimit`: `100` - 100 requests per minute (global default)
- `WindowMinutes`: `1` - 1-minute window
- Endpoint-specific limits for Login (5/5min), Register (3/10min), ForgotPassword (3/15min)

## Testing with cURL

### Register
```bash
curl -X POST http://localhost:5022/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!",
    "name": "Test User"
  }' \
  -c cookies.txt
```

### Login
```bash
curl -X POST http://localhost:5022/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "Test123!"
  }' \
  -c cookies.txt
```

### Extract CSRF Token
```bash
# On Linux/Mac
CSRF_TOKEN=$(grep XSRF-TOKEN cookies.txt | awk '{print $7}')

# On Windows (PowerShell)
$CSRF_TOKEN = (Select-String -Path cookies.txt -Pattern "XSRF-TOKEN").ToString().Split()[-1]
```

### Refresh with CSRF Token
```bash
curl -X POST http://localhost:5022/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-XSRF-TOKEN: $CSRF_TOKEN" \
  -b cookies.txt \
  -c cookies.txt \
  -d '{}'
```

## Troubleshooting

### CSRF Token Issues

**Problem:** 403 Forbidden on POST/PUT/DELETE requests

**Solution:**
1. Verify CSRF cookie is present: Check browser DevTools → Application → Cookies
2. Ensure `X-XSRF-TOKEN` header is included
3. Check cookie name matches `appsettings.json` configuration
4. In Postman, ensure cookies are enabled (Settings → Cookies)

### Postman Cookies Not Working

**Problem:** Cookies not being sent/received

**Solution:**
1. Enable cookies in Postman: Settings → General → Allow cookies
2. Check Postman console (View → Show Postman Console) for cookie logs
3. Manually manage cookies: Cookies → Manage Cookies → Add Domain

### Access Token Expired

**Problem:** 401 Unauthorized after 15 minutes

**Solution:**
Use the refresh endpoint to get a new access token. The Postman collection handles this automatically.

## Architecture

### Key Components

**Models:**
- `User` - Implements `IAuthenticatedUser`
- `UserFactory` - Creates User from RegisterRequest

**Repositories (In-Memory):**
- `InMemoryUserRepository` - User storage
- `InMemoryRefreshTokenRepository` - Refresh token storage
- `InMemoryTokenRepository` - Email/password reset tokens

**Services:**
- `InMemoryEmailSender` - Logs emails to console

### How CSRF Protection Works

1. **Login/Register**: Server generates CSRF token, sets it in cookie
2. **Client**: Reads CSRF token from cookie (JavaScript can access it)
3. **Subsequent Requests**: Client sends token in `X-XSRF-TOKEN` header
4. **Server**: Validates header matches cookie (Double Submit Cookie pattern)
5. **Token Refresh**: CSRF token rotated with new tokens

**Security:**
- Uses Double Submit Cookie pattern
- 256-bit cryptographically secure tokens
- Constant-time validation (prevents timing attacks)
- SameSite=Strict on all cookies

## Production Considerations

This sample uses in-memory storage for simplicity. For production:

**Database:**
- ✅ Use Entity Framework with SQL Server/PostgreSQL/MySQL
- ✅ Implement proper user repositories with database persistence
- ✅ Store refresh tokens in database with indexes
- ✅ Store password reset tokens securely

**Security:**
- ✅ Enable email verification (`RequireEmailVerification: true`)
- ✅ Configure password policy based on your security requirements
- ✅ Adjust account lockout settings (max attempts, lockout duration)
- ✅ Configure rate limiting thresholds for your traffic patterns
- ✅ Use environment variables for secrets (never commit credentials to source control)
- ✅ Enable HTTPS in production
- ✅ Configure CORS properly for your frontend domains
- ✅ Consider adding security headers (HSTS, Content-Security-Policy, etc.)

**Monitoring:**
- ✅ Add structured logging
- ✅ Monitor failed login attempts
- ✅ Track token refresh rates
- ✅ Alert on unusual patterns

**Email:**
- ✅ Use real email provider (SendGrid, AWS SES, etc.)
- ✅ Customize email templates
- ✅ Add unsubscribe links

## Next Steps

- ✅ Explore other token delivery modes (`ResponseBody`, `HttpOnlyCookies`)
- ✅ Implement email verification flow
- ✅ Add password reset functionality
- ✅ Integrate with Entity Framework
- ✅ Build a frontend that uses this API
- ✅ Deploy to production

## Resources

- **Pawthorize Documentation**: See main README


**Happy coding! 🐾**
