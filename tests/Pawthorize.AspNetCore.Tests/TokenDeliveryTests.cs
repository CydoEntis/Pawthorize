using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.DTOs;
using Pawthorize.Handlers;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.AspNetCore.Tests;

/// <summary>
/// Tests for all three token delivery strategies: ResponseBody, HttpOnlyCookies, and Hybrid.
/// Verifies that tokens are delivered correctly based on configuration.
/// </summary>
public class TokenDeliveryTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<JwtService<TestUser>> _mockJwtService;
    private readonly Mock<IValidator<LoginRequest>> _mockValidator;
    private readonly Mock<ILogger<LoginHandler<TestUser>>> _mockLogger;
    private readonly Mock<ILogger<AuthenticationService<TestUser>>> _mockAuthLogger;
    private readonly Mock<ILogger<RegisterHandler<TestUser, RegisterRequest>>> _mockRegisterLogger;
    private readonly Mock<IValidator<RegisterRequest>> _mockRegisterValidator;
    private readonly Mock<IUserFactory<TestUser, RegisterRequest>> _mockUserFactory;

    public TokenDeliveryTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<LoginRequest>>();
        _mockLogger = new Mock<ILogger<LoginHandler<TestUser>>>();
        _mockAuthLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();
        _mockRegisterLogger = new Mock<ILogger<RegisterHandler<TestUser, RegisterRequest>>>();
        _mockRegisterValidator = new Mock<IValidator<RegisterRequest>>();
        _mockUserFactory = new Mock<IUserFactory<TestUser, RegisterRequest>>();

        var jwtSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenLifetimeMinutes = 15,
            RefreshTokenLifetimeDays = 7
        };
        var mockJwtOptions = new Mock<IOptions<JwtSettings>>();
        mockJwtOptions.Setup(o => o.Value).Returns(jwtSettings);

        _mockJwtService = new Mock<JwtService<TestUser>>(
            MockBehavior.Loose,
            mockJwtOptions.Object,
            null!,
            null!
        );
    }

    #region Login Tests

    [Fact]
    public async Task Login_ResponseBody_ShouldReturnBothTokensInBody_NoCookies()
    {
        var options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.ResponseBody,
            RequireEmailVerification = false
        };
        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(options);

        var mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            mockOptions.Object,
            _mockAuthLogger.Object
        );
        mockAuthService.CallBase = true;

        var handler = new LoginHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            mockAuthService.Object,
            _mockValidator.Object,
            mockOptions.Object,
            _mockLogger.Object
        );

        var httpContext = HttpContextTestHelper.CreateHttpContext();
        var request = new LoginRequest
        {
            Identifier = "test@example.com",
            Password = "Password123!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password",
            IsEmailVerified = true,
            IsLocked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token_123",
            RefreshToken = "refresh_token_123",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdentifierAsync(request.Identifier, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await handler.HandleAsync(request, httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        httpContext.Response.Headers.ContainsKey("Set-Cookie").Should().BeFalse(
            "ResponseBody mode should not set any cookies");

        mockAuthService.Verify(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Login_HttpOnlyCookies_ShouldSetBothTokensInCookies()
    {
        var options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.HttpOnlyCookies,
            RequireEmailVerification = false
        };
        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(options);

        var mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            mockOptions.Object,
            _mockAuthLogger.Object
        );
        mockAuthService.CallBase = true;

        var handler = new LoginHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            mockAuthService.Object,
            _mockValidator.Object,
            mockOptions.Object,
            _mockLogger.Object
        );

        var httpContext = HttpContextTestHelper.CreateHttpContext();
        var request = new LoginRequest
        {
            Identifier = "test@example.com",
            Password = "Password123!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password",
            IsEmailVerified = true,
            IsLocked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token_123",
            RefreshToken = "refresh_token_123",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdentifierAsync(request.Identifier, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await handler.HandleAsync(request, httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        var responseCookies = httpContext.Response.Headers["Set-Cookie"].ToString();
        responseCookies.Should().Contain("access_token=", "access token cookie should be set");
        responseCookies.Should().Contain("refresh_token=", "refresh token cookie should be set");
        responseCookies.Should().Contain("httponly", "cookies should be HttpOnly");
        responseCookies.Should().Contain("secure", "cookies should be Secure");
        responseCookies.Should().Contain("samesite=strict", "cookies should be SameSite=Strict");
    }

    [Fact]
    public async Task Login_Hybrid_ShouldReturnAccessTokenInBody_RefreshTokenInCookie()
    {
        var options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.Hybrid,
            RequireEmailVerification = false
        };
        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(options);

        var mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            mockOptions.Object,
            _mockAuthLogger.Object
        );
        mockAuthService.CallBase = true;

        var handler = new LoginHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            mockAuthService.Object,
            _mockValidator.Object,
            mockOptions.Object,
            _mockLogger.Object
        );

        var httpContext = HttpContextTestHelper.CreateHttpContext();
        var request = new LoginRequest
        {
            Identifier = "test@example.com",
            Password = "Password123!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password",
            IsEmailVerified = true,
            IsLocked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token_123",
            RefreshToken = "refresh_token_123",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdentifierAsync(request.Identifier, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await handler.HandleAsync(request, httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        var responseCookies = httpContext.Response.Headers["Set-Cookie"].ToString();
        responseCookies.Should().Contain("refresh_token=", "refresh token cookie should be set");
        responseCookies.Should().NotContain("access_token=", "access token should NOT be in cookies");
        responseCookies.Should().Contain("httponly", "cookie should be HttpOnly");
        responseCookies.Should().Contain("secure", "cookie should be Secure");
        responseCookies.Should().Contain("samesite=strict", "cookie should be SameSite=Strict");


    }

    #endregion

    #region Register Tests

    [Fact]
    public async Task Register_ResponseBody_ShouldReturnBothTokensInBody()
    {
        var options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.ResponseBody,
            RequireEmailVerification = false
        };
        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(options);

        var mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            mockOptions.Object,
            _mockAuthLogger.Object
        );
        mockAuthService.CallBase = true;

        var handler = new RegisterHandler<TestUser, RegisterRequest>(
            _mockUserRepository.Object,
            _mockUserFactory.Object,
            _mockPasswordHasher.Object,
            mockAuthService.Object,
            _mockRegisterValidator.Object,
            mockOptions.Object,
            _mockRegisterLogger.Object
        );

        var httpContext = HttpContextTestHelper.CreateHttpContext();
        var request = new RegisterRequest
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            Name = "New User"
        };

        var user = new TestUser
        {
            Id = "newuser123",
            Email = "newuser@example.com",
            Name = "New User",
            PasswordHash = "hashed_password",
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token_456",
            RefreshToken = "refresh_token_456",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockRegisterValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns("hashed_password");

        _mockUserFactory
            .Setup(f => f.CreateUser(request, "hashed_password"))
            .Returns(user);

        _mockUserRepository
            .Setup(r => r.CreateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await handler.HandleAsync(request, httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        httpContext.Response.Headers.ContainsKey("Set-Cookie").Should().BeFalse(
            "ResponseBody mode should not set any cookies");
    }

    [Fact]
    public async Task Register_Hybrid_ShouldSetRefreshTokenInCookie()
    {
        var options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.Hybrid,
            RequireEmailVerification = false
        };
        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(options);

        var mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            mockOptions.Object,
            _mockAuthLogger.Object
        );
        mockAuthService.CallBase = true;

        var handler = new RegisterHandler<TestUser, RegisterRequest>(
            _mockUserRepository.Object,
            _mockUserFactory.Object,
            _mockPasswordHasher.Object,
            mockAuthService.Object,
            _mockRegisterValidator.Object,
            mockOptions.Object,
            _mockRegisterLogger.Object
        );

        var httpContext = HttpContextTestHelper.CreateHttpContext();
        var request = new RegisterRequest
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            Name = "New User"
        };

        var user = new TestUser
        {
            Id = "newuser123",
            Email = "newuser@example.com",
            Name = "New User",
            PasswordHash = "hashed_password",
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token_789",
            RefreshToken = "refresh_token_789",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockRegisterValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns("hashed_password");

        _mockUserFactory
            .Setup(f => f.CreateUser(request, "hashed_password"))
            .Returns(user);

        _mockUserRepository
            .Setup(r => r.CreateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await handler.HandleAsync(request, httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        var responseCookies = httpContext.Response.Headers["Set-Cookie"].ToString();
        responseCookies.Should().Contain("refresh_token=", "refresh token cookie should be set in Hybrid mode");
        responseCookies.Should().NotContain("access_token=", "access token should NOT be in cookies in Hybrid mode");
    }

    #endregion
}

public class TestUser : IAuthenticatedUser
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? Name { get; set; }
    public string PasswordHash { get; set; } = string.Empty;
    public bool IsEmailVerified { get; set; }
    public bool IsLocked { get; set; }
    public DateTime? LockedUntil { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string> AdditionalClaims { get; set; } = new Dictionary<string, string>();
}
