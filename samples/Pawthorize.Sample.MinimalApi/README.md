# Pawthorize Sample - Minimal API

A complete working example demonstrating **Pawthorize** authentication library with ASP.NET Core Minimal APIs.

## Features Demonstrated

- User registration with email/password
- User login with JWT access tokens
- Refresh token rotation
- Logout (token revocation)
- In-memory user and token storage (for demo purposes)
- Swagger UI for API exploration

## Prerequisites

- .NET 8.0 SDK or later
- Postman, curl, or any HTTP client for testing

## Getting Started

### 1. Run the Application

From the sample directory:

```bash
cd samples/Pawthorize.Sample.MinimalApi
dotnet run
```

The API will start on a port shown in the console output (typically `https://localhost:7086`).

Check the console for the line: `Now listening on: https://localhost:XXXX`

### 2. Access Swagger UI

Open your browser to the Swagger UI (replace the port with your actual port):
```
https://localhost:7086/swagger
```

You can test all endpoints interactively through the Swagger UI.

## API Endpoints

### Base URL
```
https://localhost:7086
```
(Replace with the actual port shown when you run `dotnet run`)

### Authentication Endpoints

All authentication endpoints are prefixed with `/api/auth`.

#### 1. Register a New User

**POST** `/api/auth/register`

Creates a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecureP@ssw0rd",
  "name": "John Doe"
}
```

**Success Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "d8f7a6b5c4e3d2c1b0a9f8e7d6c5b4a3",
  "accessTokenExpiresAt": "2025-12-20T12:15:00Z",
  "refreshTokenExpiresAt": "2025-12-27T12:00:00Z",
  "tokenType": "Bearer"
}
```

**Error Response (400 Bad Request):**
```json
{
  "type": "DuplicateEmailError",
  "title": "Email Already Registered",
  "status": 400,
  "detail": "A user with email 'user@example.com' already exists.",
  "errors": {}
}
```

---

#### 2. Login

**POST** `/api/auth/login`

Authenticate with email and password.

**Request Body:**
```json
{
  "identifier": "user@example.com",
  "password": "SecureP@ssw0rd"
}
```

**Success Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "d8f7a6b5c4e3d2c1b0a9f8e7d6c5b4a3",
  "accessTokenExpiresAt": "2025-12-20T12:15:00Z",
  "refreshTokenExpiresAt": "2025-12-27T12:00:00Z",
  "tokenType": "Bearer"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "type": "InvalidCredentialsError",
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The email or password provided is incorrect.",
  "errors": {}
}
```

---

#### 3. Refresh Access Token

**POST** `/api/auth/refresh`

Get a new access token using a refresh token.

**Request Body:**
```json
{
  "refreshToken": "d8f7a6b5c4e3d2c1b0a9f8e7d6c5b4a3"
}
```

**Success Response (200 OK):**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8",
  "accessTokenExpiresAt": "2025-12-20T12:30:00Z",
  "refreshTokenExpiresAt": "2025-12-27T12:15:00Z",
  "tokenType": "Bearer"
}
```

**Error Response (401 Unauthorized):**
```json
{
  "type": "InvalidRefreshTokenError",
  "title": "Invalid Refresh Token",
  "status": 401,
  "detail": "The refresh token is invalid, expired, or has been revoked.",
  "errors": {}
}
```

---

#### 4. Logout

**POST** `/api/auth/logout`

Revoke a refresh token (logout).

**Request Body:**
```json
{
  "refreshToken": "d8f7a6b5c4e3d2c1b0a9f8e7d6c5b4a3"
}
```

**Success Response (200 OK):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

## Configuration

Configuration is in `appsettings.json`:

```json
{
  "Pawthorize": {
    "RequireEmailVerification": false,
    "TokenDelivery": "Hybrid",
    "LoginIdentifier": "Email"
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

- **AccessTokenLifetimeMinutes**: How long access tokens are valid (15 minutes)
- **RefreshTokenLifetimeDays**: How long refresh tokens are valid (7 days)
- **RequireEmailVerification**: Whether users must verify email before login (disabled for demo)
- **LoginIdentifier**: What users login with (Email, Username, or Phone)

## Testing Scenarios

### Success Scenarios

1. **Complete Authentication Flow**
   - Register a new user
   - Login with credentials
   - Refresh the access token
   - Logout

2. **Token Refresh**
   - Login to get tokens
   - Wait 1 minute (or change AccessTokenLifetimeMinutes to 1)
   - Use refresh token to get new access token

### Failure Scenarios

1. **Duplicate Registration**
   - Register a user with email `test@example.com`
   - Try to register again with same email
   - Should receive `DuplicateEmailError`

2. **Invalid Login Credentials**
   - Try to login with wrong password
   - Should receive `InvalidCredentialsError`
   - Try to login with non-existent email
   - Should receive `InvalidCredentialsError`

3. **Invalid Refresh Token**
   - Use a fake/random refresh token
   - Should receive `InvalidRefreshTokenError`
   - Use a refresh token after logout
   - Should receive `InvalidRefreshTokenError`

4. **Validation Errors**
   - Try to register with invalid email format
   - Try to register with empty password
   - Should receive validation errors

## Using the Postman Collection

A Postman collection is included for easy testing:

1. Import `Pawthorize-Sample.postman_collection.json` into Postman
2. The collection includes all success and failure scenarios
3. Variables are automatically set (access token, refresh token)
4. Run the entire collection to test all scenarios

## Architecture

### Key Components

- **User Model**: Implements `IAuthenticatedUser` with required properties
- **UserFactory**: Creates User instances from RegisterRequest
- **InMemoryUserRepository**: Stores users in memory (not for production)
- **InMemoryRefreshTokenRepository**: Stores refresh tokens in memory (not for production)

### Production Considerations

This sample uses in-memory storage for simplicity. In production:

- Use Entity Framework with SQL Server, PostgreSQL, or MySQL
- Implement proper user repositories with database persistence
- Store refresh tokens in database with proper indexes
- Add password complexity requirements
- Enable email verification
- Implement rate limiting
- Add logging and monitoring
- Use environment variables for secrets

## Next Steps

- Check out the Multi-Tenant sample for multi-tenant scenarios
- Explore OAuth integration samples
- Read the Pawthorize documentation for advanced features
- Implement your own user repository with Entity Framework

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-repo/pawthorize/issues
- Documentation: See main README in repository root
