using ErrorHound.BuiltIn;
using FluentAssertions;
using FluentValidation;
using FluentValidation.Results;
using Microsoft.Extensions.Logging;
using Moq;
using Pawthorize.Endpoints.ChangeEmail;
using Pawthorize.Internal;
using Xunit;

namespace Pawthorize.Tests.Internal;

public class ValidationHelperTests
{
    [Fact]
    public async Task ValidateAndThrowAsync_WithValidRequest_ShouldNotThrow()
    {
        var request = new ChangeEmailRequest { NewEmail = "test@test.com", Password = "Password123!" };
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithSingleError_ShouldThrowValidationErrorWithFieldError()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("Password", "Password is required")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object);

        var exception = await act.Should().ThrowAsync<ValidationError>();
        exception.Which.FieldErrors.Should().ContainKey("password");
        exception.Which.FieldErrors["password"].Should().Contain("Password is required");
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithMultipleFields_ShouldThrowValidationErrorWithAllFields()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("NewEmail", "Email is required"),
                new ValidationFailure("Password", "Password is required")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object);

        var exception = await act.Should().ThrowAsync<ValidationError>();
        exception.Which.FieldErrors.Should().ContainKey("newEmail");
        exception.Which.FieldErrors.Should().ContainKey("password");
        exception.Which.FieldErrors["newEmail"].Should().Contain("Email is required");
        exception.Which.FieldErrors["password"].Should().Contain("Password is required");
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithMultipleErrorsSameField_ShouldIncludeAllMessages()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("Password", "Password is required"),
                new ValidationFailure("Password", "Password must be at least 8 characters")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object);

        var exception = await act.Should().ThrowAsync<ValidationError>();
        exception.Which.FieldErrors.Should().ContainKey("password");
        exception.Which.FieldErrors["password"].Should().HaveCount(2);
        exception.Which.FieldErrors["password"].Should().Contain("Password is required");
        exception.Which.FieldErrors["password"].Should().Contain("Password must be at least 8 characters");
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithPascalCasePropertyName_ShouldConvertToCamelCase()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("NewEmail", "New email is required")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object);

        var exception = await act.Should().ThrowAsync<ValidationError>();
        exception.Which.FieldErrors.Should().ContainKey("newEmail");
        exception.Which.FieldErrors.Should().NotContainKey("NewEmail");
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithLogger_ShouldLogWarningWithFieldDetails()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        var mockLogger = new Mock<ILogger>();
        mockLogger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);

        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("Password", "Password is required")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object, logger: mockLogger.Object);

        await act.Should().ThrowAsync<ValidationError>();

        mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, _) => v.ToString()!.Contains("[password] Password is required")),
                It.IsAny<Exception?>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task ValidateAndThrowAsync_WithNullLogger_ShouldNotThrow()
    {
        var request = new ChangeEmailRequest();
        var mockValidator = new Mock<IValidator<ChangeEmailRequest>>();
        mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(new[]
            {
                new ValidationFailure("Password", "Password is required")
            }));

        Func<Task> act = async () =>
            await ValidationHelper.ValidateAndThrowAsync(request, mockValidator.Object, logger: null);

        await act.Should().ThrowAsync<ValidationError>();
    }
}
