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
using Pawthorize.Utilities;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Handlers;

public class LogoutHandlerTests
{
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<IValidator<LogoutRequest>> _mockValidator;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<ILogger<LogoutHandler<TestUser>>> _mockLogger;
    private readonly LogoutHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;
    private readonly PawthorizeOptions _options;

    public LogoutHandlerTests()
    {
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<LogoutRequest>>();
        _mockLogger = new Mock<ILogger<LogoutHandler<TestUser>>>();

        _options = new PawthorizeOptions
        {
            TokenDelivery = TokenDeliveryStrategy.ResponseBody,
            RequireEmailVerification = false
        };
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        _mockOptions.Setup(o => o.Value).Returns(_options);

        _handler = new LogoutHandler<TestUser>(
            _mockRefreshTokenRepository.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidRefreshToken_ShouldRevokeToken()
    {
        var refreshToken = "valid_refresh_token_123";
        var refreshTokenHash = TokenHasher.HashToken(refreshToken);
        var request = new LogoutRequest { RefreshToken = refreshToken };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshTokenHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockRefreshTokenRepository.Verify(r => r.RevokeAsync(refreshTokenHash, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithEmptyRefreshToken_ShouldThrowInvalidRefreshTokenError()
    {
        var request = new LogoutRequest { RefreshToken = string.Empty };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidRefreshTokenError>();
        _mockRefreshTokenRepository.Verify(r => r.RevokeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithInvalidRequest_ShouldThrowValidationException()
    {
        var request = new LogoutRequest { RefreshToken = "" };

        var validationFailures = new List<ValidationFailure>
        {
            new ValidationFailure("RefreshToken", "Refresh token is required")
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult(validationFailures));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<ValidationError>();
        _mockRefreshTokenRepository.Verify(r => r.RevokeAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithCookieToken_ShouldExtractFromCookie()
    {
        _options.TokenDelivery = TokenDeliveryStrategy.HttpOnlyCookies;
        var refreshToken = "cookie_refresh_token";
        var refreshTokenHash = TokenHasher.HashToken(refreshToken);
        var request = new LogoutRequest { RefreshToken = "" }; // Empty body

        _httpContext.Request.Headers["Cookie"] = $"refresh_token={refreshToken}";

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshTokenHash, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockRefreshTokenRepository.Verify(r => r.RevokeAsync(refreshTokenHash, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WhenRepositoryThrowsError_ShouldPropagateException()
    {
        var refreshToken = "valid_refresh_token";
        var refreshTokenHash = TokenHasher.HashToken(refreshToken);
        var request = new LogoutRequest { RefreshToken = refreshToken };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshTokenHash, It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("Database error"));

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("Database error");
    }
}
