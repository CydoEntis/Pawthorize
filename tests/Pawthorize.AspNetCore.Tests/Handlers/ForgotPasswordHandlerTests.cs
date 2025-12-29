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
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Handlers;

/// <summary>
/// Unit tests for ForgotPasswordHandler.
/// Tests forgot password flow with mocked dependencies.
/// </summary>
public class ForgotPasswordHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordResetService> _mockPasswordResetService;
    private readonly Mock<IValidator<ForgotPasswordRequest>> _mockValidator;
    private readonly Mock<ILogger<ForgotPasswordHandler<TestUser>>> _mockLogger;
    private readonly ForgotPasswordHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;

    public ForgotPasswordHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordResetService = new Mock<IPasswordResetService>();
        _mockValidator = new Mock<IValidator<ForgotPasswordRequest>>();
        _mockLogger = new Mock<ILogger<ForgotPasswordHandler<TestUser>>>();

        _handler = new ForgotPasswordHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordResetService.Object,
            _mockValidator.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithExistingUser_ShouldSendResetEmail()
    {
        var email = "test@example.com";
        var request = new ForgotPasswordRequest { Email = email };

        var user = new TestUser
        {
            Id = "user123",
            Email = email,
            PasswordHash = "hash"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordResetService
            .Setup(s => s.SendPasswordResetEmailAsync(user.Id, email, It.IsAny<CancellationToken>()))
            .ReturnsAsync("reset-token-123");

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        _mockPasswordResetService.Verify(
            s => s.SendPasswordResetEmailAsync(user.Id, email, It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentUser_ShouldNotSendEmailButStillReturnSuccess()
    {
        var email = "nonexistent@example.com";
        var request = new ForgotPasswordRequest { Email = email };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(email, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();

        _mockPasswordResetService.Verify(
            s => s.SendPasswordResetEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never
        );
    }

    [Fact]
    public async Task HandleAsync_WithInvalidEmail_ShouldThrowValidationException()
    {
        var request = new ForgotPasswordRequest { Email = "invalid-email" };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("Email", "Invalid email format")
        };
        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
    }

    [Fact]
    public async Task HandleAsync_WithEmptyEmail_ShouldThrowValidationException()
    {
        var request = new ForgotPasswordRequest { Email = string.Empty };

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
    public async Task HandleAsync_WhenEmailServiceFails_ShouldThrowException()
    {
        var email = "test@example.com";
        var request = new ForgotPasswordRequest { Email = email };

        var user = new TestUser
        {
            Id = "user123",
            Email = email,
            PasswordHash = "hash"
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(email, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordResetService
            .Setup(s => s.SendPasswordResetEmailAsync(user.Id, email, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Email service unavailable"));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Email service unavailable");
    }
}

/// <summary>
/// Test user model for testing purposes.
/// </summary>
public class TestUser : IAuthenticatedUser
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Name { get; set; }
    public bool IsEmailVerified { get; set; } = true;
    public bool IsLocked { get; set; } = false;
    public DateTime? LockedUntil { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }
}
