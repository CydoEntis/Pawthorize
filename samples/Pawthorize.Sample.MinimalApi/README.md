# Pawthorize Sample - Minimal API

A complete **production-ready reference implementation** demonstrating **Pawthorize** authentication library with ASP.NET Core Minimal APIs.

## Features Demonstrated

- ✅ **Hybrid Token Delivery** - Access tokens in response, refresh tokens in HttpOnly cookies
- ✅ **Built-in CSRF Protection** - Automatic token generation and validation
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

**Error Response (400 Bad Request):**
```json
{
  "success": false,
  "error": {
    "code": "DUPLICATE_EMAIL",
    "message": "Email Already Registered",
    "details": "A user with email 'user@example.com' already exists."
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
  "identifier": "user@example.com",
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

List all active sessions (refresh tokens) for current user.

**Headers:**
```
Authorization: Bearer <access_token>
```

---

#### 7. Revoke Other Sessions

**POST** `/auth/revoke-other-sessions`

Revoke all other sessions except the current one.

**Headers:**
```
Authorization: Bearer <access_token>
X-XSRF-TOKEN: <csrf_token>
```

---

#### 8. Logout

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
    "identifier": "test@example.com",
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
- ✅ Implement rate limiting (login attempts, registration)
- ✅ Use environment variables for secrets
- ✅ Enable HTTPS in production
- ✅ Configure CORS properly

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
- **Token Delivery Guide**: `TOKEN_DELIVERY_STRATEGIES.md`
- **Migration Guide**: `MIGRATION_GUIDE.md`
- **Full Change Log**: `CHANGES.md`

## Support

For issues or questions:
- **GitHub Issues**: [Create an issue](https://github.com/your-repo/pawthorize/issues)
- **Documentation**: See repository root README

---

**Happy coding! 🐾**
