using ErrorHound.BuiltIn;
using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Endpoints.ChangeEmail;
using Pawthorize.Errors;
using Pawthorize.Services;
using Pawthorize.Tests.Helpers;
using System.Security.Claims;
using Xunit;

namespace Pawthorize.Tests.Endpoints.ChangeEmail;

public class ChangeEmailHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IPasswordHasher> _mockPasswordHasher;
    private readonly Mock<IEmailChangeService> _mockEmailChangeService;
    private readonly Mock<IEmailSender> _mockEmailSender;
    private readonly Mock<IEmailTemplateProvider> _mockTemplateProvider;
    private readonly Mock<IValidator<ChangeEmailRequest>> _mockValidator;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<ILogger<ChangeEmailHandler<TestUser>>> _mockLogger;
    private readonly PawthorizeOptions _options;
    private readonly ChangeEmailHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;

    public ChangeEmailHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockPasswordHasher = new Mock<IPasswordHasher>();
        _mockEmailChangeService = new Mock<IEmailChangeService>();
        _mockEmailSender = new Mock<IEmailSender>();
        _mockTemplateProvider = new Mock<IEmailTemplateProvider>();
        _mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        _mockLogger = new Mock<ILogger<ChangeEmailHandler<TestUser>>>();

        _options = new PawthorizeOptions
        {
            RequireEmailVerification = false,
            EmailChange = new EmailChangeOptions
            {
                RequirePasswordConfirmation = true,
                SendNotificationToOldEmail = false,
                ApplicationName = "TestApp"
            }
        };
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _handler = new ChangeEmailHandler<TestUser>(
            _mockUserRepository.Object,
            _mockPasswordHasher.Object,
            _mockEmailChangeService.Object,
            _mockEmailSender.Object,
            _mockTemplateProvider.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    #region Authentication

    [Fact]
    public async Task HandleAsync_WithNoAuthenticatedUser_ShouldThrowNotAuthenticatedError()
    {
        var request = new ChangeEmailRequest { NewEmail = "new@test.com", Password = "Password123!" };
        _httpContext.User = new ClaimsPrincipal(new ClaimsIdentity());

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<NotAuthenticatedError>();
    }

    [Fact]
    public async Task HandleAsync_WithEmptyUserId_ShouldThrowNotAuthenticatedError()
    {
        var request = new ChangeEmailRequest { NewEmail = "new@test.com", Password = "Password123!" };
        var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, "") }, "TestAuth");
        _httpContext.User = new ClaimsPrincipal(identity);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<NotAuthenticatedError>();
    }

    #endregion

    #region Validation

    [Fact]
    public async Task HandleAsync_WithValidationFailure_ShouldThrowValidationError()
    {
        var userId = "user123";
        var request = new ChangeEmailRequest { NewEmail = "new@test.com" };
        SetupAuthentication(userId);

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("Password", "Password is required for security confirmation")
            }));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        var exception = await act.Should().ThrowAsync<ValidationError>();
        exception.Which.FieldErrors.Should().ContainKey("password");
        exception.Which.FieldErrors["password"].Should().Contain("Password is required for security confirmation");
    }

    #endregion

    #region User lookup

    [Fact]
    public async Task HandleAsync_WithUserNotFound_ShouldThrowUserNotFoundError()
    {
        var userId = "user123";
        var request = new ChangeEmailRequest { NewEmail = "new@test.com", Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<UserNotFoundError>();
    }

    #endregion

    #region Email conflict checks

    [Fact]
    public async Task HandleAsync_WithSameEmail_ShouldThrowSameEmailError()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var request = new ChangeEmailRequest { NewEmail = currentEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hash" });

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<SameEmailError>();
    }

    [Fact]
    public async Task HandleAsync_WithSameEmailCaseInsensitive_ShouldThrowSameEmailError()
    {
        var userId = "user123";
        var request = new ChangeEmailRequest { NewEmail = "Current@Test.COM", Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser { Id = userId, Email = "current@test.com", PasswordHash = "hash" });

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<SameEmailError>();
    }

    [Fact]
    public async Task HandleAsync_WithDuplicateEmail_ShouldReturnSuccessWithoutChangingEmail()
    {
        var userId = "user123";
        var newEmail = "taken@test.com";
        var currentEmail = "current@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hash" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser { Id = "other-user", Email = newEmail });

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _options.RequireEmailVerification = false;

        var result = await _handler.HandleAsync(request, _httpContext);

        // Should return success to prevent email enumeration
        result.Should().NotBeNull();

        // Email should NOT be changed
        user.Email.Should().Be(currentEmail);

        // UpdateAsync should NOT be called
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithDuplicateEmail_AndVerificationRequired_ShouldReturnSuccessWithoutSendingEmail()
    {
        var userId = "user123";
        var newEmail = "taken@test.com";
        var currentEmail = "current@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hash" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new TestUser { Id = "other-user", Email = newEmail });

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _options.RequireEmailVerification = true;

        var result = await _handler.HandleAsync(request, _httpContext);

        // Should return success to prevent email enumeration
        result.Should().NotBeNull();

        // Verification email should NOT be sent
        _mockEmailChangeService.Verify(
            s => s.InitiateEmailChangeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithEmailMatchingOwnAccount_ShouldNotThrowDuplicateEmailError()
    {
        var userId = "user123";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        var user = new TestUser { Id = userId, Email = "current@test.com", PasswordHash = "hash" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        // FindByEmailAsync returns the same user — should not be treated as duplicate
        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _options.RequireEmailVerification = true;
        _mockEmailChangeService
            .Setup(s => s.InitiateEmailChangeAsync(userId, user.Email, newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
    }

    #endregion

    #region Password confirmation

    [Fact]
    public async Task HandleAsync_WithPasswordConfirmationRequired_AndNoPasswordSet_ShouldThrowPasswordNotSetError()
    {
        var userId = "user123";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        // PasswordHash defaults to string.Empty — simulates OAuth-only account
        var user = new TestUser { Id = userId, Email = "current@test.com" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<PasswordNotSetError>();
        _mockPasswordHasher.Verify(h => h.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithPasswordConfirmationRequired_AndIncorrectPassword_ShouldThrowIncorrectPasswordError()
    {
        var userId = "user123";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "wrongpassword" };
        SetupAuthentication(userId);
        SetupValidation(request);

        var user = new TestUser { Id = userId, Email = "current@test.com", PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(false);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext);

        await act.Should().ThrowAsync<IncorrectPasswordError>();
    }

    [Fact]
    public async Task HandleAsync_WithPasswordConfirmationDisabled_ShouldSkipPasswordCheck()
    {
        var userId = "user123";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.EmailChange.RequirePasswordConfirmation = false;
        _options.RequireEmailVerification = true;

        var user = new TestUser { Id = userId, Email = "current@test.com", PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockEmailChangeService
            .Setup(s => s.InitiateEmailChangeAsync(userId, user.Email, newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        _mockPasswordHasher.Verify(h => h.VerifyPassword(It.IsAny<string>(), It.IsAny<string>()), Times.Never);
    }

    #endregion

    #region Email change with verification

    [Fact]
    public async Task HandleAsync_WithEmailVerificationRequired_ShouldInitiateEmailChange()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.RequireEmailVerification = true;

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockEmailChangeService
            .Setup(s => s.InitiateEmailChangeAsync(userId, currentEmail, newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync(true);

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        _mockEmailChangeService.Verify(
            s => s.InitiateEmailChangeAsync(userId, currentEmail, newEmail, It.IsAny<CancellationToken>()),
            Times.Once);
        // Email should NOT be updated directly when verification is required
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    #endregion

    #region Email change without verification (direct update)

    [Fact]
    public async Task HandleAsync_WithoutEmailVerification_ShouldUpdateEmailDirectly()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.RequireEmailVerification = false;

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockUserRepository
            .Setup(r => r.UpdateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        user.Email.Should().Be(newEmail);
        user.IsEmailVerified.Should().BeFalse();
        _mockUserRepository.Verify(
            r => r.UpdateAsync(user, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithoutEmailVerification_AndNotificationEnabled_ShouldSendNotificationToOldEmail()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.RequireEmailVerification = false;
        _options.EmailChange.SendNotificationToOldEmail = true;

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockUserRepository
            .Setup(r => r.UpdateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockTemplateProvider
            .Setup(t => t.GetEmailChangeNotificationTemplate(currentEmail, newEmail, "TestApp"))
            .Returns("<html>Notification</html>");

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        _mockEmailSender.Verify(
            s => s.SendEmailAsync(currentEmail, It.IsAny<string>(), "<html>Notification</html>", It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithoutEmailVerification_AndNotificationDisabled_ShouldNotSendNotification()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.RequireEmailVerification = false;
        _options.EmailChange.SendNotificationToOldEmail = false;

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockUserRepository
            .Setup(r => r.UpdateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        _mockEmailSender.Verify(
            s => s.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithoutEmailVerification_AndNotificationFails_ShouldNotFailRequest()
    {
        var userId = "user123";
        var currentEmail = "current@test.com";
        var newEmail = "new@test.com";
        var request = new ChangeEmailRequest { NewEmail = newEmail, Password = "Password123!" };
        SetupAuthentication(userId);
        SetupValidation(request);

        _options.RequireEmailVerification = false;
        _options.EmailChange.SendNotificationToOldEmail = true;

        var user = new TestUser { Id = userId, Email = currentEmail, PasswordHash = "hashedpassword" };
        _mockUserRepository
            .Setup(r => r.FindByIdAsync(userId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(newEmail, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockPasswordHasher
            .Setup(h => h.VerifyPassword(request.Password, user.PasswordHash))
            .Returns(true);

        _mockUserRepository
            .Setup(r => r.UpdateAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockTemplateProvider
            .Setup(t => t.GetEmailChangeNotificationTemplate(currentEmail, newEmail, "TestApp"))
            .Returns("<html>Notification</html>");

        // Notification email send fails — should be swallowed, not propagated
        _mockEmailSender
            .Setup(s => s.SendEmailAsync(currentEmail, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("SMTP connection failed"));

        var result = await _handler.HandleAsync(request, _httpContext);

        result.Should().NotBeNull();
        user.Email.Should().Be(newEmail);
    }

    #endregion

    #region Helpers

    private void SetupAuthentication(string userId)
    {
        var claims = new List<Claim> { new Claim(ClaimTypes.NameIdentifier, userId) };
        var identity = new ClaimsIdentity(claims, "TestAuth");
        _httpContext.User = new ClaimsPrincipal(identity);
    }

    private void SetupValidation(ChangeEmailRequest request)
    {
        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());
    }

    #endregion
}
