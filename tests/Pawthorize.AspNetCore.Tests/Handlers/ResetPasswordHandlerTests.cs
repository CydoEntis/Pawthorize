using ErrorHound.BuiltIn;
using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Handlers;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Handlers;

public class ResetPasswordHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordResetService> _mockPasswordResetService;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<IValidator<ResetPasswordRequest>> _mockValidator;
    private readonly Mock<ILogger<ResetPasswordHandler<TestUser>>> _mockLogger;
    private readonly ResetPasswordHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;

    public ResetPasswordHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordResetService = new Mock<IPasswordResetService>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<ResetPasswordRequest>>();
        _mockLogger = new Mock<ILogger<ResetPasswordHandler<TestUser>>>();

        _handler = new ResetPasswordHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordResetService.Object,
            _mockPasswordHasher.Object,
            _mockRefreshTokenRepository.Object,
            _mockValidator.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidToken_ShouldResetPassword()
    {
        var token = "valid_reset_token";
        var userId = "user123";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "old_hash"
        };

        var newPasswordHash = "new_password_hash";

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.NewPassword))
            .Returns(newPasswordHash);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockPasswordResetService
            .Setup(s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockPasswordResetService.Verify(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()), Times.Once);
        _mockUserRepository.Verify(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()), Times.Once);
        _mockPasswordResetService.Verify(s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()), Times.Once);
        _mockRefreshTokenRepository.Verify(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithInvalidToken_ShouldThrowInvalidResetTokenError()
    {
        var token = "invalid_token";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidResetTokenError>();
        _mockUserRepository.Verify(r => r.UpdatePasswordAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithExpiredToken_ShouldThrowInvalidResetTokenError()
    {
        var token = "expired_token";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string?)null); // Service returns null for expired tokens

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidResetTokenError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentUser_ShouldThrowUserNotFoundError()
    {
        var token = "valid_token";
        var userId = "nonexistent_user";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<UserNotFoundError>();
        _mockUserRepository.Verify(r => r.UpdatePasswordAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithPasswordMismatch_ShouldThrowValidationException()
    {
        var request = new ResetPasswordRequest
        {
            Token = "valid_token",
            NewPassword = "NewPassword123!",
            ConfirmPassword = "DifferentPassword123!"
        };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("ConfirmPassword", "Passwords must match")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockPasswordResetService.Verify(s => s.ValidateResetTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithWeakPassword_ShouldThrowValidationException()
    {
        var request = new ResetPasswordRequest
        {
            Token = "valid_token",
            NewPassword = "weak",
            ConfirmPassword = "weak"
        };

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
        _mockPasswordResetService.Verify(s => s.ValidateResetTokenAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_ShouldRevokeAllRefreshTokensForSecurity()
    {
        var token = "valid_reset_token";
        var userId = "user123";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "old_hash"
        };

        var newPasswordHash = "new_password_hash";

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.NewPassword))
            .Returns(newPasswordHash);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockPasswordResetService
            .Setup(s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
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
    public async Task HandleAsync_ShouldInvalidateResetTokenAfterUse()
    {
        var token = "valid_reset_token";
        var userId = "user123";
        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = "NewPassword123!",
            ConfirmPassword = "NewPassword123!"
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "old_hash"
        };

        var newPasswordHash = "new_password_hash";

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(request.NewPassword))
            .Returns(newPasswordHash);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, newPasswordHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockPasswordResetService
            .Setup(s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAllForUserAsync(userId, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        _mockPasswordResetService.Verify(
            s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task HandleAsync_ShouldHashNewPasswordBeforeUpdating()
    {
        var token = "valid_reset_token";
        var userId = "user123";
        var plainPassword = "NewPassword123!";
        var hashedPassword = "hashed_new_password";

        var request = new ResetPasswordRequest
        {
            Token = token,
            NewPassword = plainPassword,
            ConfirmPassword = plainPassword
        };

        var user = new TestUser
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = "old_hash"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockPasswordResetService
            .Setup(s => s.ValidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
            .ReturnsAsync(userId);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.HashPassword(plainPassword))
            .Returns(hashedPassword);

        _mockUserRepository
            .Setup(r => r.UpdatePasswordAsync(userId, hashedPassword, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockPasswordResetService
            .Setup(s => s.InvalidateResetTokenAsync(token, It.IsAny<CancellationToken>()))
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
