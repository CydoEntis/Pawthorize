# AGENTS.md - Pawthorize

> AI agent instructions for working with this codebase. For human documentation, see [README.md](README.md).

## Project Overview

**Pawthorize** is a production-ready authentication library for ASP.NET Core Minimal APIs. It provides:

- Email/password authentication with JWT tokens
- OAuth 2.0 social login (Google, Discord)
- Session management with device tracking
- CSRF protection (Double Submit Cookie pattern)
- Rate limiting, account lockout, password policies
- Email change functionality

**Current Version:** 1.0.0
**Target Framework:** .NET 8.0
**Package ID:** `Pawthorize` (NuGet)

## Repository Structure

Pawthorize uses **vertical slice architecture** where each feature is self-contained with its Handler, Request DTO, Validator, and EndpointMapping in one folder.

```
Pawthorize/
├── src/
│   └── Pawthorize/                    # Main library (published to NuGet)
│       ├── Abstractions/              # Consumer-implemented interfaces ONLY
│       │   ├── IUserRepository.cs
│       │   ├── IRefreshTokenRepository.cs
│       │   ├── IAuthenticatedUser.cs
│       │   ├── IUserFactory.cs
│       │   ├── IExternalAuthRepository.cs
│       │   ├── IStateTokenRepository.cs
│       │   ├── IStateToken.cs
│       │   ├── IEmailSender.cs
│       │   └── IEmailTemplateProvider.cs
│       ├── Configuration/             # ALL configuration/options classes
│       │   ├── PawthorizeOptions.cs
│       │   ├── JwtSettings.cs
│       │   ├── EmailVerificationOptions.cs
│       │   ├── PasswordResetOptions.cs
│       │   ├── EmailChangeOptions.cs
│       │   ├── PasswordHashingOptions.cs
│       │   ├── OAuthOptions.cs
│       │   └── ...
│       ├── Endpoints/                 # Vertical slices by feature
│       │   ├── Login/
│       │   │   ├── LoginHandler.cs
│       │   │   ├── LoginRequest.cs
│       │   │   ├── LoginRequestValidator.cs
│       │   │   └── EndpointMapping.cs
│       │   ├── Register/
│       │   ├── Refresh/
│       │   ├── Logout/
│       │   ├── ChangePassword/
│       │   ├── ForgotPassword/
│       │   ├── ResetPassword/
│       │   ├── SetPassword/
│       │   ├── VerifyEmail/
│       │   ├── ChangeEmail/
│       │   ├── Sessions/
│       │   ├── User/
│       │   └── OAuth/
│       ├── Services/                  # Shared business logic + internal interfaces
│       │   ├── AuthenticationService.cs
│       │   ├── JwtService.cs
│       │   ├── PasswordHasher.cs
│       │   ├── EmailVerificationService.cs
│       │   ├── PasswordResetService.cs
│       │   ├── EmailChangeService.cs
│       │   ├── StateTokenService.cs
│       │   ├── ExternalAuthenticationService.cs
│       │   ├── CsrfTokenService.cs
│       │   ├── PasswordValidationService.cs
│       │   ├── RateLimitingService.cs
│       │   ├── OAuthProviderFactory.cs
│       │   ├── IPasswordHasher.cs          # Internal interface
│       │   ├── IAuthenticationService.cs   # Internal interface
│       │   ├── IEmailVerificationService.cs
│       │   ├── IPasswordResetService.cs
│       │   ├── IEmailChangeService.cs
│       │   ├── IStateTokenService.cs
│       │   ├── IExternalAuthProvider.cs
│       │   ├── IOAuthProviderFactory.cs
│       │   ├── Models/                     # Auth-related DTOs
│       │   │   ├── AuthResult.cs
│       │   │   └── RefreshTokenInfo.cs
│       │   └── OAuth/
│       │       ├── Models/                 # OAuth-specific DTOs
│       │       │   ├── OAuthToken.cs
│       │       │   ├── ExternalUserInfo.cs
│       │       │   ├── StateToken.cs
│       │       │   ├── StateTokenData.cs
│       │       │   ├── InternalStateToken.cs
│       │       │   └── ExternalIdentity.cs
│       │       ├── Providers/              # OAuth provider implementations
│       │       │   ├── OAuthProviderBase.cs
│       │       │   ├── GoogleOAuthProvider.cs
│       │       │   └── DiscordOAuthProvider.cs
│       │       └── Repositories/
│       │           └── InternalStateTokenRepository.cs
│       ├── Internal/                  # Private utilities (not public API)
│       │   ├── TokenHasher.cs
│       │   ├── TokenGenerator.cs
│       │   ├── TokenDeliveryHelper.cs
│       │   ├── ValidationHelper.cs
│       │   ├── PkceHelper.cs
│       │   └── PawthorizeTypeMetadata.cs
│       ├── Errors/                    # Error types (extend ErrorHound)
│       ├── Extensions/                # DI registration and endpoint mapping
│       │   ├── ServiceCollectionExtensions.cs
│       │   ├── WebApplicationExtensions.cs
│       │   └── PasswordHashingExtensions.cs
│       ├── Middleware/                # HTTP middleware
│       │   └── CsrfProtectionMiddleware.cs
│       ├── Formatters/                # Response formatters
│       └── Templates/                 # Email HTML templates
│           └── EmailTemplates/
├── samples/
│   └── Pawthorize.Sample.MinimalApi/  # Reference implementation
├── tests/
│   ├── Pawthorize.Tests/              # Unit tests (258 tests)
│   │   ├── Endpoints/                 # Handler tests by feature
│   │   ├── Services/                  # Service tests
│   │   ├── Middleware/                # Middleware tests
│   │   └── Helpers/                   # Test utilities
│   └── Pawthorize.Integration.Tests/  # E2E tests (8 tests)
└── docs/                              # Additional documentation
```

## Key Namespaces

| Namespace | Purpose | Example Types |
|-----------|---------|---------------|
| `Pawthorize.Abstractions` | Consumer-implemented interfaces | `IUserRepository`, `IAuthenticatedUser` |
| `Pawthorize.Configuration` | All config/options classes | `PawthorizeOptions`, `JwtSettings` |
| `Pawthorize.Endpoints.{Feature}` | Feature handlers/requests/validators | `LoginHandler`, `LoginRequest` |
| `Pawthorize.Services` | Business logic + internal interfaces | `AuthenticationService`, `IPasswordHasher` |
| `Pawthorize.Services.Models` | Auth DTOs | `AuthResult`, `RefreshTokenInfo` |
| `Pawthorize.Services.OAuth.Models` | OAuth DTOs | `OAuthToken`, `ExternalUserInfo` |
| `Pawthorize.Internal` | Private utilities | `TokenHasher`, `ValidationHelper` |
| `Pawthorize.Errors` | Error types | `InvalidCredentialsError` |
| `Pawthorize.Extensions` | DI/endpoint registration | `AddPawthorize`, `MapPawthorize` |

## Build Commands

```bash
# Build main library
dotnet build src/Pawthorize/Pawthorize.csproj

# Build everything (library + tests + sample)
dotnet build

# Build release
dotnet build -c Release

# Create NuGet package
dotnet pack src/Pawthorize/Pawthorize.csproj -c Release -o ./nupkg
```

## Test Commands

```bash
# Run all tests (266 total)
dotnet test

# Run unit tests only
dotnet test tests/Pawthorize.Tests/

# Run integration tests only
dotnet test tests/Pawthorize.Integration.Tests/

# Run tests without rebuilding
dotnet test --no-build

# Run specific test by name
dotnet test --filter "FullyQualifiedName~LoginHandler"
```

**Test expectations:** All 266 tests must pass before committing.

## Key Abstractions

### User Model

Consumers implement `IAuthenticatedUser`:

```csharp
public interface IAuthenticatedUser
{
    string Id { get; set; }
    string Email { get; set; }
    string PasswordHash { get; set; }
    string? Name { get; set; }
    IEnumerable<string> Roles { get; set; }
    IDictionary<string, string>? AdditionalClaims { get; set; }
    bool IsEmailVerified { get; set; }
    bool IsLocked { get; set; }
    DateTime? LockedUntil { get; set; }
    int FailedLoginAttempts { get; set; }
    DateTime? LockoutEnd { get; set; }
}
```

### Required Repositories

Consumers must implement:

| Interface | Purpose |
|-----------|---------|
| `IUserRepository<TUser>` | User CRUD operations |
| `IRefreshTokenRepository` | Refresh token storage |
| `IUserFactory<TUser, TRegisterRequest>` | Create users from registration |

Optional (for OAuth):
| Interface | Purpose |
|-----------|---------|
| `IExternalAuthRepository<TUser>` | OAuth provider links |
| `IStateTokenRepository<TStateToken>` | OAuth state tokens |

### Endpoint Handler Pattern

Each feature folder contains all related files:

```csharp
// Endpoints/SomeFeature/SomeHandler.cs
namespace Pawthorize.Endpoints.SomeFeature;

public class SomeHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly ISomeService _service;  // Shared service
    private readonly IValidator<SomeRequest> _validator;

    public async Task<IResult> HandleAsync(
        SomeRequest request,
        HttpContext context,
        CancellationToken ct)
    {
        // 1. Validate
        await ValidationHelper.ValidateAndThrowAsync(request, _validator, ct);

        // 2. Endpoint-specific logic
        // 3. Delegate to shared services
        var result = await _service.DoSomethingAsync(request, ct);

        // 4. Return HTTP result
        return Results.Ok(result);
    }
}
```

### Error Handling

All errors extend `ApiError` from ErrorHound:

```csharp
public sealed class SomeError : ApiError
{
    public SomeError()
        : base(
            code: "ERROR_CODE",
            message: "Human readable message",
            status: (int)HttpStatusCode.BadRequest,
            details: null)
    {
    }
}
```

## Adding New Features

### Adding a New Endpoint

1. **Create endpoint folder** `src/Pawthorize/Endpoints/NewFeature/`

2. **Create Request DTO**:
   ```csharp
   // Endpoints/NewFeature/NewFeatureRequest.cs
   namespace Pawthorize.Endpoints.NewFeature;

   public class NewFeatureRequest
   {
       public string SomeField { get; set; } = string.Empty;
   }
   ```

3. **Create Validator**:
   ```csharp
   // Endpoints/NewFeature/NewFeatureRequestValidator.cs
   namespace Pawthorize.Endpoints.NewFeature;

   public class NewFeatureRequestValidator : AbstractValidator<NewFeatureRequest>
   {
       public NewFeatureRequestValidator()
       {
           RuleFor(x => x.SomeField).NotEmpty();
       }
   }
   ```

4. **Create Handler**:
   ```csharp
   // Endpoints/NewFeature/NewFeatureHandler.cs
   namespace Pawthorize.Endpoints.NewFeature;

   public class NewFeatureHandler<TUser> where TUser : IAuthenticatedUser
   {
       public async Task<IResult> HandleAsync(
           NewFeatureRequest request,
           HttpContext context,
           CancellationToken ct)
       {
           await ValidationHelper.ValidateAndThrowAsync(request, _validator, ct);
           // Business logic
           return Results.Ok(result);
       }
   }
   ```

5. **Create Endpoint Mapping**:
   ```csharp
   // Endpoints/NewFeature/EndpointMapping.cs
   namespace Pawthorize.Endpoints.NewFeature;

   public static class EndpointMapping
   {
       public static RouteHandlerBuilder MapNewFeature<TUser>(
           this RouteGroupBuilder group,
           PawthorizeEndpointOptions options,
           bool isRateLimitingEnabled)
           where TUser : IAuthenticatedUser
       {
           var endpoint = group.MapPost(options.NewFeaturePath, async (...) => ...)
               .WithName("NewFeature")
               .WithOpenApi();

           if (isRateLimitingEnabled)
               endpoint.RequireRateLimiting("pawthorize-global");

           return endpoint;
       }
   }
   ```

6. **Register in DI** (`ServiceCollectionExtensions.cs`):
   ```csharp
   services.AddScoped<NewFeatureHandler<TUser>>();
   services.AddScoped<IValidator<NewFeatureRequest>, NewFeatureRequestValidator>();
   ```

7. **Register mapping** (`WebApplicationExtensions.cs`):
   ```csharp
   group.MapNewFeature<TUser>(options, isRateLimitingEnabled);
   ```

8. **Add path option** to `PawthorizeEndpointOptions`:
   ```csharp
   public string NewFeaturePath { get; set; } = "/new-feature";
   ```

### Adding a New Error Type

Create in `src/Pawthorize/Errors/`:

```csharp
public sealed class NewError : ApiError
{
    public NewError()
        : base(
            code: "NEW_ERROR_CODE",
            message: "Description of the error",
            status: (int)HttpStatusCode.BadRequest,
            details: null)
    {
    }
}
```

## Code Conventions

### Naming

- Handlers: `{Action}Handler<TUser>`
- Validators: `{RequestType}Validator`
- Errors: `{Description}Error`
- DTOs: `{Action}Request`, `{Action}Response`

### Logging

```csharp
_logger.LogInformation("Action completed for UserId: {UserId}", userId);
_logger.LogWarning("Action failed: {Reason}", reason);
_logger.LogError(ex, "Unexpected error during {Action}", action);
```

- Never log sensitive data
- Use placeholders `{Name}` not string interpolation

### Async Pattern

- All I/O operations are async
- Accept `CancellationToken` in all async methods
- Pass tokens to all downstream calls

## Testing Guidelines

### Unit Tests

```csharp
[Fact]
public async Task Handler_WithValidInput_ReturnsSuccess()
{
    // Arrange
    var mockRepo = new Mock<IUserRepository<TestUser>>();
    var handler = new SomeHandler<TestUser>(mockRepo.Object, ...);

    // Act
    var result = await handler.HandleAsync(request, context, CancellationToken.None);

    // Assert
    result.Should().BeOfType<Ok<SomeResponse>>();
}
```

### Test Naming

`{Method}_{Scenario}_{ExpectedResult}`

### Test Data

Use `TestUser` from `Pawthorize.Tests.Helpers`.

## Security Considerations

### Never Do

- Log passwords, tokens, or secrets
- Store passwords in plain text
- Use string comparison for tokens (use `TokenHasher`)
- Return detailed error messages about why auth failed

### Always Do

- Hash passwords with BCrypt (`IPasswordHasher`)
- Validate all input with FluentValidation
- Apply rate limiting to auth endpoints
- Validate OAuth state tokens

## Version Bumping

Version is in `src/Pawthorize/Pawthorize.csproj`:

```xml
<Version>1.0.0</Version>
```

When bumping:
1. Update version in csproj
2. Update README.md if needed
3. Create upgrade guide if breaking changes

## Common Tasks

### Run Sample App

```bash
cd samples/Pawthorize.Sample.MinimalApi
dotnet run
# Swagger UI: http://localhost:5022/swagger
```

### Publish to NuGet

```bash
dotnet pack src/Pawthorize/Pawthorize.csproj -c Release -o ./nupkg
dotnet nuget push ./nupkg/Pawthorize.1.0.0.nupkg --api-key {KEY} --source https://api.nuget.org/v3/index.json
```

## Files to Update Together

**OAuth State Token:**
- `IStateToken.cs`, `IStateTokenService.cs`
- `StateToken.cs`, `InternalStateToken.cs`, `StateTokenData.cs`
- `StateTokenService.cs`
- `samples/.../Models/StateToken.cs`

**New Endpoint:**
- Create folder `Endpoints/{Feature}/`
- All files in the feature folder
- `ServiceCollectionExtensions.cs`
- `WebApplicationExtensions.cs`
- `PawthorizeEndpointOptions`

**Version Bump:**
- `Pawthorize.csproj`
- `README.md`
- Create upgrade guide if breaking changes

## Git Workflow

### Commit Messages

Format: `type: description`

Types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation only
- `chore:` - Build, version bumps
- `refactor:` - Code restructure
- `test:` - Adding or updating tests

### Before Committing

```bash
dotnet build
dotnet test
```

All tests must pass. No exceptions.
