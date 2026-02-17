# CLAUDE.md - Pawthorize Context

> Quick reference for Claude AI when working with this codebase. For detailed agent instructions, see [AGENTS.md](AGENTS.md).

## What is Pawthorize?

A production-ready authentication library for ASP.NET Core Minimal APIs. Provides email/password auth, OAuth 2.0 social login, session management, and security features out of the box.

**Current Version:** 1.0.0
**Framework:** .NET 8.0

## Architecture

Pawthorize uses **vertical slice architecture** where each feature is self-contained:

```
src/Pawthorize/
├── Abstractions/         # Consumer-implemented interfaces ONLY
│   ├── IUserRepository.cs
│   ├── IRefreshTokenRepository.cs
│   ├── IAuthenticatedUser.cs
│   └── ...
├── Configuration/        # All configuration/options classes
│   ├── PawthorizeOptions.cs
│   ├── JwtSettings.cs
│   └── ...
├── Endpoints/            # Vertical slices - each feature folder contains:
│   ├── Login/            #   Handler, Request, Validator, EndpointMapping
│   ├── Register/
│   ├── Refresh/
│   ├── Logout/
│   ├── ChangePassword/
│   ├── ForgotPassword/
│   ├── ResetPassword/
│   ├── SetPassword/
│   ├── VerifyEmail/
│   ├── ChangeEmail/
│   ├── Sessions/
│   ├── User/
│   └── OAuth/
├── Services/             # Shared business logic + internal interfaces
│   ├── AuthenticationService.cs
│   ├── JwtService.cs
│   ├── IPasswordHasher.cs      # Internal interface
│   ├── PasswordHasher.cs
│   ├── Models/                 # Auth-related DTOs
│   │   ├── AuthResult.cs
│   │   └── RefreshTokenInfo.cs
│   └── OAuth/
│       ├── Models/             # OAuth-specific DTOs
│       ├── Providers/          # Google, Discord, etc.
│       └── Repositories/
├── Internal/             # Private utilities (not public API)
│   ├── TokenHasher.cs
│   ├── TokenGenerator.cs
│   ├── ValidationHelper.cs
│   └── TokenDeliveryHelper.cs
├── Errors/               # Custom error types (ErrorHound)
├── Extensions/           # DI and endpoint registration
├── Middleware/           # HTTP middleware
└── Templates/            # Email HTML templates
```

## Key Namespaces

| Namespace | Purpose |
|-----------|---------|
| `Pawthorize.Abstractions` | Interfaces consumers implement (IUserRepository, etc.) |
| `Pawthorize.Configuration` | All options/settings classes |
| `Pawthorize.Endpoints.{Feature}` | Feature-specific handlers, requests, validators |
| `Pawthorize.Services` | Business logic services + internal interfaces |
| `Pawthorize.Services.Models` | Auth DTOs (AuthResult, RefreshTokenInfo) |
| `Pawthorize.Services.OAuth.Models` | OAuth DTOs (OAuthToken, ExternalUserInfo, etc.) |
| `Pawthorize.Internal` | Internal utilities (not public API) |
| `Pawthorize.Errors` | Error types extending ErrorHound's ApiError |
| `Pawthorize.Extensions` | AddPawthorize(), MapPawthorize() |

## Quick Commands

```bash
# Build everything
dotnet build

# Run all tests (266 tests)
dotnet test

# Run sample app
dotnet run --project samples/Pawthorize.Sample.MinimalApi

# Pack for NuGet
dotnet pack src/Pawthorize/Pawthorize.csproj -c Release -o ./nupkg
```

## Consumer Integration Pattern

```csharp
// Program.cs
builder.Services.AddPawthorize<User>(options =>
{
    options.Configuration = builder.Configuration;
    options.EnableOAuth = true;
    options.AddGoogleProvider();
    options.AddDiscordProvider();
});

app.UsePawthorize();
app.MapPawthorize();
```

Consumers must implement:
- `IUserRepository<TUser>` - User CRUD
- `IRefreshTokenRepository` - Token storage
- `IUserFactory<TUser, TRegisterRequest>` - User creation
- `IAuthenticatedUser` - User model interface

## Changes in v1.0.0 (from v0.10.1)

### Bug Fixes
- `IncorrectPasswordError` now returns 400 Bad Request (was 401 Unauthorized)
- OAuth login on locked accounts now redirects with `error=account_locked` and a clear message (was generic "unexpected error")
- Admin-locked accounts are now detected before password verification in LoginHandler
- `AccountLockedError` details always include `unlockAt` (null for permanent locks) for consistent frontend handling

### Improvements
- Added error handling to `OAuthInitiateHandler`, `LinkProviderHandler`, `UnlinkProviderHandler`, `ListLinkedProvidersHandler`
- Normalized error message punctuation (no trailing periods) across all 21 error classes

## Adding a New Endpoint

1. Create folder: `Endpoints/NewFeature/`
2. Add files:
   - `NewFeatureRequest.cs` - DTO
   - `NewFeatureRequestValidator.cs` - FluentValidation
   - `NewFeatureHandler.cs` - Business logic
   - `EndpointMapping.cs` - ASP.NET route mapping
3. Register in `ServiceCollectionExtensions.cs`:
   - Add handler: `services.AddScoped<NewFeatureHandler<TUser>>();`
   - Add validator: `services.AddScoped<IValidator<NewFeatureRequest>, NewFeatureRequestValidator>();`
4. Add to `WebApplicationExtensions.cs`:
   - Call `group.MapNewFeature<TUser>(options, isRateLimitingEnabled);`
5. Add path to `PawthorizeEndpointOptions`

## Error Handling

All errors extend `ApiError` from ErrorHound:

```csharp
public sealed class SomeError : ApiError
{
    public SomeError() : base(
        code: "SOME_ERROR",
        message: "Human readable message",
        status: 400,
        details: null)
    { }
}
```

Throw errors in handlers; ErrorHound middleware formats them.

## Testing

- Tests are in `tests/Pawthorize.Tests/` (258 tests)
- Integration tests in `tests/Pawthorize.Integration.Tests/` (8 tests)
- Use `TestUser` from `Pawthorize.Tests.Helpers`
- All 266 tests must pass before committing

## Files That Change Together

**New Endpoint:**
- `Endpoints/{Feature}/*.cs`
- `ServiceCollectionExtensions.cs`
- `WebApplicationExtensions.cs`
- `PawthorizeEndpointOptions` (for path)

**OAuth State Token:**
- `IStateToken.cs` (interface)
- `StateToken.cs`, `InternalStateToken.cs`, `StateTokenData.cs`
- `StateTokenService.cs`
- Sample app's `StateToken.cs`

**Version Bump:**
- `Pawthorize.csproj` (`<Version>`)
- `README.md` (if documenting)
- Create upgrade guide if breaking changes

## Security Considerations

- Never log passwords/tokens
- Use constant-time comparison for tokens (`TokenHasher`)
- Rate limit auth endpoints
- Validate all input with FluentValidation
- CSRF protection for state-changing requests

## Dependencies

- `FluentValidation` - Request validation
- `ErrorHound` / `SuccessHound` - Response formatting
- `Microsoft.AspNetCore.Authentication.JwtBearer` - JWT auth
- `BCrypt.Net-Next` - Password hashing
- `System.IdentityModel.Tokens.Jwt` - JWT handling
