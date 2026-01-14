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

public class RegisterHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IUserFactory<TestUser, RegisterRequest>> _mockUserFactory;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<AuthenticationService<TestUser>> _mockAuthService;
    private readonly Mock<IEmailVerificationService> _mockEmailVerificationService;
    private readonly Mock<IValidator<RegisterRequest>> _mockValidator;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<CsrfTokenService> _mockCsrfService;
    private readonly Mock<ILogger<RegisterHandler<TestUser, RegisterRequest>>> _mockLogger;
    private readonly RegisterHandler<TestUser, RegisterRequest> _handler;
    private readonly HttpContext _httpContext;
    private readonly PawthorizeOptions _options;

    public RegisterHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockUserFactory = new Mock<IUserFactory<TestUser, RegisterRequest>>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockEmailVerificationService = new Mock<IEmailVerificationService>();
        _mockValidator = new Mock<IValidator<RegisterRequest>>();
        _mockLogger = new Mock<ILogger<RegisterHandler<TestUser, RegisterRequest>>>();
        var mockCsrfLogger = new Mock<ILogger<CsrfTokenService>>();
        _mockCsrfService = new Mock<CsrfTokenService>(mockCsrfLogger.Object);

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

        var mockJwtService = new Mock<JwtService<TestUser>>(
            MockBehavior.Loose,
            mockJwtOptions.Object,
            null);
        var mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        var mockAuthLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();

        _mockAuthService = new Mock<AuthenticationService<TestUser>>(
            mockJwtService.Object,
            mockRefreshTokenRepository.Object,
            _mockOptions.Object,
            mockAuthLogger.Object);
        _mockAuthService.CallBase = true; // Call real implementation for unmocked methods

        _handler = new RegisterHandler<TestUser, RegisterRequest>(
            _mockUserRepository.Object,
            _mockUserFactory.Object,
            _mockPasswordHasher.Object,
            _mockAuthService.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockCsrfService.Object,
            _mockLogger.Object,
            _mockEmailVerificationService.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidRequest_ShouldCreateUserAndReturnTokens()
    {
        var request = new RegisterRequest
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            Name = "Test User"
        };

        var passwordHash = "hashed_password";
        var createdUser = new TestUser
        {
            Id = "user123",
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name,
            IsEmailVerified = true
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
            .Setup(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns(passwordHash);

        _mockUserFactory
            .Setup(f => f.CreateUser(request, passwordHash))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(createdUser, It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(createdUser, It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockUserRepository.Verify(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()), Times.Once);
        _mockPasswordHasher.Verify(h => h.HashPassword(request.Password), Times.Once);
        _mockUserFactory.Verify(f => f.CreateUser(request, passwordHash), Times.Once);
        _mockUserRepository.Verify(r => r.CreateAsync(createdUser, It.IsAny<CancellationToken>()), Times.Once);
        _mockAuthService.Verify(s => s.GenerateTokensAsync(createdUser, It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        _mockEmailVerificationService.Verify(
            s => s.SendVerificationEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never
        );
    }

    [Fact]
    public async Task HandleAsync_WithEmailVerificationEnabled_ShouldSendEmailAndNotReturnTokens()
    {
        _options.RequireEmailVerification = true;

        var request = new RegisterRequest
        {
            Email = "newuser@example.com",
            Password = "Password123!",
            Name = "Test User"
        };

        var passwordHash = "hashed_password";
        var createdUser = new TestUser
        {
            Id = "user123",
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name,
            IsEmailVerified = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns(passwordHash);

        _mockUserFactory
            .Setup(f => f.CreateUser(request, passwordHash))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(createdUser, It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockEmailVerificationService
            .Setup(s => s.SendVerificationEmailAsync(createdUser.Id, createdUser.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync("verification-token-123");

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockEmailVerificationService.Verify(
            s => s.SendVerificationEmailAsync(createdUser.Id, createdUser.Email, It.IsAny<CancellationToken>()),
            Times.Once
        );
        _mockAuthService.Verify(
            s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()),
            Times.Never
        );
    }

    [Fact]
    public async Task HandleAsync_WithDuplicateEmail_ShouldThrowDuplicateEmailError()
    {
        var request = new RegisterRequest
        {
            Email = "existing@example.com",
            Password = "Password123!",
            Name = "Test User"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<DuplicateEmailError>();
        _mockPasswordHasher.Verify(h => h.HashPassword(It.IsAny<string>()), Times.Never);
        _mockUserRepository.Verify(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithInvalidEmail_ShouldThrowValidationException()
    {
        var request = new RegisterRequest
        {
            Email = "invalid-email",
            Password = "Password123!",
            Name = "Test User"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Email", "Email must be a valid email address")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.EmailExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithWeakPassword_ShouldThrowValidationException()
    {
        var request = new RegisterRequest
        {
            Email = "user@example.com",
            Password = "weak",
            Name = "Test User"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Password", "Password must be at least 8 characters"),
            new ValidationFailure("Password", "Password must contain at least one uppercase letter"),
            new ValidationFailure("Password", "Password must contain at least one number"),
            new ValidationFailure("Password", "Password must contain at least one special character")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.EmailExistsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithPasswordMissingUppercase_ShouldThrowValidationException()
    {
        var request = new RegisterRequest
        {
            Email = "user@example.com",
            Password = "password123!",
            Name = "Test User"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Password", "Password must contain at least one uppercase letter")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
    }

    [Fact]
    public async Task HandleAsync_WithPasswordMissingSpecialChar_ShouldThrowValidationException()
    {
        var request = new RegisterRequest
        {
            Email = "user@example.com",
            Password = "Password123",
            Name = "Test User"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Password", "Password must contain at least one special character")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
    }

    [Fact]
    public async Task HandleAsync_WithEmailVerificationRequiredButServiceNotConfigured_ShouldThrowInvalidOperationException()
    {
        _options.RequireEmailVerification = true;

        var request = new RegisterRequest
        {
            Email = "user@example.com",
            Password = "Password123!",
            Name = "Test User"
        };

        var passwordHash = "hashed_password";
        var createdUser = new TestUser
        {
            Id = "user123",
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name
        };

        var handlerWithoutEmailService = new RegisterHandler<TestUser, RegisterRequest>(
            _mockUserRepository.Object,
            _mockUserFactory.Object,
            _mockPasswordHasher.Object,
            _mockAuthService.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockCsrfService.Object,
            _mockLogger.Object,
            null
        );

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns(passwordHash);

        _mockUserFactory
            .Setup(f => f.CreateUser(request, passwordHash))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(createdUser, It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        Func<Task> act = async () => await handlerWithoutEmailService.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*IEmailVerificationService*");
    }

    [Fact]
    public async Task HandleAsync_WithEmptyEmail_ShouldThrowValidationException()
    {
        var request = new RegisterRequest
        {
            Email = string.Empty,
            Password = "Password123!",
            Name = "Test User"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Email", "Email is required")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
    }

    [Fact]
    public async Task HandleAsync_ShouldCallUserFactoryWithCorrectParameters()
    {
        var request = new RegisterRequest
        {
            Email = "user@example.com",
            Password = "Password123!",
            Name = "Test User"
        };

        var passwordHash = "hashed_password";
        var createdUser = new TestUser
        {
            Id = "user123",
            Email = request.Email,
            PasswordHash = passwordHash,
            Name = request.Name
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.EmailExistsAsync(request.Email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(false);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.Password))
            .Returns(passwordHash);

        _mockUserFactory
            .Setup(f => f.CreateUser(request, passwordHash))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(createdUser, It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(createdUser, It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        _mockUserFactory.Verify(
            f => f.CreateUser(
                It.Is<RegisterRequest>(r => r.Email == request.Email && r.Password == request.Password && r.Name == request.Name),
                passwordHash
            ),
            Times.Once
        );
    }
}
