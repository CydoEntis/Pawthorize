using ErrorHound.BuiltIn;
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
using Pawthorize.Errors;
using Pawthorize.Handlers;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Handlers;

public class LoginHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<JwtService<TestUser>> _mockJwtService;
    private readonly Mock<AuthenticationService<TestUser>> _mockAuthService;
    private readonly Mock<IValidator<LoginRequest>> _mockValidator;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<CsrfTokenService> _mockCsrfService;
    private readonly Mock<ILogger<LoginHandler<TestUser>>> _mockLogger;
    private readonly Mock<ILogger<AuthenticationService<TestUser>>> _mockAuthLogger;
    private readonly Mock<ILogger<CsrfTokenService>> _mockCsrfLogger;
    private readonly LoginHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;
    private readonly PawthorizeOptions _options;

    public LoginHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<LoginRequest>>();
        _mockLogger = new Mock<ILogger<LoginHandler<TestUser>>>();
        _mockAuthLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();
        _mockCsrfLogger = new Mock<ILogger<CsrfTokenService>>();
        _mockCsrfService = new Mock<CsrfTokenService>(_mockCsrfLogger.Object);

        _options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.ResponseBody,
            RequireEmailVerification = false
        };
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

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
            null
        );

        _mockAuthService = new Mock<AuthenticationService<TestUser>>(
            _mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            _mockOptions.Object,
            _mockAuthLogger.Object
        );
        _mockAuthService.CallBase = true; // Call real implementation for unmocked methods

        _handler = new LoginHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            _mockAuthService.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockCsrfService.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidCredentials_ShouldReturnTokens()
    {
        var request = new LoginRequest
        {
            Email = "test@example.com",
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
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockUserRepository.Verify(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()), Times.Once);
        _mockPasswordHasher.Verify(h => h.VerifyPassword(request.Password, user.PasswordHash), Times.Once);
        _mockAuthService.Verify(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithInvalidPassword_ShouldThrowInvalidCredentialsError()
    {
        var request = new LoginRequest
        {
            Email = "test@example.com",
            Password = "WrongPassword!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(false);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidCredentialsError>();
        _mockAuthService.Verify(s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentUser_ShouldThrowInvalidCredentialsError()
    {
        var request = new LoginRequest
        {
            Email = "nonexistent@example.com",
            Password = "Password123!"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidCredentialsError>();
        _mockPasswordHasher.Verify(h => h.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithUnverifiedEmail_ShouldThrowEmailNotVerifiedError()
    {
        _options.RequireEmailVerification = true;

        var request = new LoginRequest
        {
            Email = "test@example.com",
            Password = "Password123!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password",
            IsEmailVerified = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockAuthService
            .Setup(s => s.ValidateAccountStatus(user))
            .Throws(new EmailNotVerifiedError());

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<EmailNotVerifiedError>();
    }

    [Fact]
    public async Task HandleAsync_WithLockedAccount_ShouldThrowAccountLockedError()
    {
        var request = new LoginRequest
        {
            Email = "test@example.com",
            Password = "Password123!"
        };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hashed_password",
            IsLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockAuthService
            .Setup(s => s.ValidateAccountStatus(user))
            .Throws(new AccountLockedError());

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<AccountLockedError>();
    }

    [Fact]
    public async Task HandleAsync_WithInvalidRequest_ShouldThrowValidationException()
    {
        var request = new LoginRequest
        {
            Email = "",
            Password = "Password123!"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Identifier", "Identifier is required")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.FindByEmailAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
