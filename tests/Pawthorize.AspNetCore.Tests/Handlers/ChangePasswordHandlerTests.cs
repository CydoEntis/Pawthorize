using System.Security.Claims;
using ErrorHound.BuiltIn;
using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.DTOs;
using Pawthorize.Errors;
using Pawthorize.Handlers;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Handlers;

public class ChangePasswordHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<IValidator<ChangePasswordRequest>> _mockValidator;
    private readonly Mock<ILogger<ChangePasswordHandler<TestUser>>> _mockLogger;
    private readonly ChangePasswordHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;

    public ChangePasswordHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<ChangePasswordRequest>>();
        _mockLogger = new Mock<ILogger<ChangePasswordHandler<TestUser>>>();

        _handler = new ChangePasswordHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            _mockRefreshTokenRepository.Object,
            _mockValidator.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidRequest_ShouldChangePassword()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "current_password_hash"
        };

        var newPasswordHash = "new_password_hash";

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            .Returns(true);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.NewPassword))
            .Returns(newPasswordHash);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockPasswordHasher.Verify(h => h.VerifyPassword(request.CurrentPassword, user.PasswordHash), Times.Once);
        _mockUserRepository.Verify(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()), Times.Once);
        _mockRefreshTokenRepository.Verify(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithIncorrectCurrentPassword_ShouldThrowIncorrectPasswordError()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "WrongPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "current_password_hash"
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            .Returns(false);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<IncorrectPasswordError>();
        _mockUserRepository.Verify(r => r.UpdatePasswordAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNoAuthenticatedUser_ShouldThrowInvalidCredentialsError()
    {
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        _httpContext.User = new ClaimsPrincipal();

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidCredentialsError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentUser_ShouldThrowUserNotFoundError()
    {
        var userId = "nonexistent_user";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<UserNotFoundError>();
        _mockPasswordHasher.Verify(h => h.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithPasswordMismatch_ShouldThrowValidationException()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "DifferentPassword123!" // Mismatch
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("ConfirmPassword", "Passwords must match")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithWeakNewPassword_ShouldThrowValidationException()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "weak",
            ConfirmPassword = "weak"
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("NewPassword", "Password must be at least 8 characters"),
            new ValidationFailure("NewPassword", "Password must contain at least one uppercase letter"),
            new ValidationFailure("NewPassword", "Password must contain at least one number"),
            new ValidationFailure("NewPassword", "Password must contain at least one special character")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNewPasswordSameAsCurrent_ShouldThrowValidationException()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "SamePassword123!",
            NewPassword = "SamePassword123!",
            ConfirmPassword = "SamePassword123!"
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("NewPassword", "New password must be different from current password")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_ShouldRevokeAllRefreshTokensForSecurity()
    {
        var userId = "user123";
        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "current_password_hash"
        };

        var newPasswordHash = "new_password_hash";

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            .Returns(true);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.NewPassword))
            .Returns(newPasswordHash);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        _mockRefreshTokenRepository.Verify(
            r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task HandleAsync_ShouldHashNewPasswordBeforeUpdating()
    {
        var userId = "user123";
        var plainPassword = "NewPassword123!";
        var hashedPassword = "hashed_new_password";

        var request = new ChangePasswordRequest
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = plainPassword,
            ConfirmPassword = plainPassword
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "current_password_hash"
        };

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, userId)
        };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        var principal = new ClaimsPrincipal(identity);
        _httpContext.User = principal;

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.CurrentPassword, user.PasswordHash))
            .Returns(true);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(plainPassword))
            .Returns(hashedPassword);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, hashedPassword, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        _mockPasswordHasher.Verify(h => h.HashPassword(plainPassword), Times.Once);
        _mockUserRepository.Verify(
            r => r.UpdatePasswordAsync(userId, hashedPassword, It.IsAny<CancellationToken>()),
            Times.Once
        );
    }
}
