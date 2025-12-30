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

public class RefreshHandlerTests
{
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<AuthenticationService<TestUser>> _mockAuthService;
    private readonly Mock<IValidator<RefreshTokenRequest>> _mockValidator;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<CsrfTokenService> _mockCsrfService;
    private readonly Mock<ILogger<RefreshHandler<TestUser>>> _mockLogger;
    private readonly RefreshHandler<TestUser> _handler;
    private readonly HttpContext _httpContext;
    private readonly PawthorizeOptions _options;

    public RefreshHandlerTests()
    {
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();
        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockValidator = new Mock<IValidator<RefreshTokenRequest>>();
        _mockLogger = new Mock<ILogger<RefreshHandler<TestUser>>>();
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
            null,
            null);
        var mockAuthLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();

        _mockAuthService = new Mock<AuthenticationService<TestUser>>(
            mockJwtService.Object,
            _mockRefreshTokenRepository.Object,
            _mockOptions.Object,
            mockAuthLogger.Object);
        _mockAuthService.CallBase = true; // Call real implementation for unmocked methods

        _handler = new RefreshHandler<TestUser>(
            _mockUserRepository.Object,
            _mockRefreshTokenRepository.Object,
            _mockAuthService.Object,
            _mockValidator.Object,
            _mockOptions.Object,
            _mockCsrfService.Object,
            _mockLogger.Object
        );

        _httpContext = HttpContextTestHelper.CreateHttpContext();
    }

    [Fact]
    public async Task HandleAsync_WithValidRefreshToken_ShouldReturnNewTokens()
    {
        var refreshToken = "valid_refresh_token_123";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hash",
            IsEmailVerified = true,
            IsLocked = false
        };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "new_access_token",
            RefreshToken = "new_refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshToken, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockRefreshTokenRepository.Verify(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()), Times.Once);
        _mockUserRepository.Verify(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()), Times.Once);
        _mockRefreshTokenRepository.Verify(r => r.RevokeAsync(refreshToken, It.IsAny<CancellationToken>()), Times.Once);
        _mockAuthService.Verify(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task HandleAsync_WithExpiredRefreshToken_ShouldThrowInvalidRefreshTokenError()
    {
        var refreshToken = "expired_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = "user123",
            ExpiresAt = DateTime.UtcNow.AddDays(-1),
            IsRevoked = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidRefreshTokenError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        _mockAuthService.Verify(s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithInvalidRefreshToken_ShouldThrowInvalidRefreshTokenError()
    {
        var refreshToken = "invalid_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync((RefreshTokenInfo?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidRefreshTokenError>();
        _mockUserRepository.Verify(r => r.FindByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithNonExistentUser_ShouldThrowInvalidRefreshTokenError()
    {
        var refreshToken = "valid_token_for_deleted_user";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = "deleted_user_id",
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(tokenInfo.UserId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidRefreshTokenError>();
        _mockAuthService.Verify(s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithLockedAccount_ShouldThrowAccountLockedError()
    {
        var refreshToken = "valid_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hash",
            IsLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<AccountLockedError>();
        _mockAuthService.Verify(s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_WithUnverifiedEmail_ShouldThrowEmailNotVerifiedError()
    {
        _options.RequireEmailVerification = true;

        var refreshToken = "valid_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hash",
            IsEmailVerified = false
        };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        try
        {
                Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

                await act.Should().ThrowAsync<EmailNotVerifiedError>();
            _mockAuthService.Verify(s => s.GenerateTokensAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
        }
        finally
        {
            _options.RequireEmailVerification = false;
        }
    }

    [Fact]
    public async Task HandleAsync_WithEmptyRefreshToken_ShouldThrowInvalidRefreshTokenError()
    {
        var request = new RefreshTokenRequest { RefreshToken = string.Empty };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        Func<Task> act = async () => await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidRefreshTokenError>();
        _mockRefreshTokenRepository.Verify(r => r.ValidateAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task HandleAsync_ShouldRevokeOldTokenBeforeGeneratingNew()
    {
        var refreshToken = "valid_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = refreshToken };

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hash",
            IsEmailVerified = true,
            IsLocked = false
        };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "new_access_token",
            RefreshToken = "new_refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        var callSequence = new List<string>();

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshToken, It.IsAny<CancellationToken>()))
            .Callback(() => callSequence.Add("Revoke"))
            .Returns(Task.CompletedTask);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .Callback(() => callSequence.Add("GenerateTokens"))
            .ReturnsAsync(authResult);

        await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        callSequence.Should().HaveCount(2);
        callSequence[0].Should().Be("Revoke");
        callSequence[1].Should().Be("GenerateTokens");
    }

    [Fact]
    public async Task HandleAsync_WithCookieToken_ShouldExtractFromCookie()
    {
        _options.TokenDelivery = TokenDeliveryStrategy.HttpOnlyCookies;
        var refreshToken = "cookie_refresh_token";
        var request = new RefreshTokenRequest { RefreshToken = "" }; // Empty body

        _httpContext.Request.Headers["Cookie"] = $"refresh_token={refreshToken}";

        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            PasswordHash = "hash",
            IsEmailVerified = true,
            IsLocked = false
        };

        var tokenInfo = new RefreshTokenInfo
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            IsRevoked = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "new_access_token",
            RefreshToken = "new_refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockValidator
            .Setup(v => v.ValidateAsync(request, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ValidationResult());

        _mockRefreshTokenRepository
            .Setup(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        _mockUserRepository
            .Setup(r => r.FindByIdAsync(user.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(user);

        _mockRefreshTokenRepository
            .Setup(r => r.RevokeAsync(refreshToken, It.IsAny<CancellationToken>()))
            .Returns(Task.CompletedTask);

        _mockAuthService
            .Setup(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _handler.HandleAsync(request, _httpContext, CancellationToken.None);

        result.Should().NotBeNull();
        _mockRefreshTokenRepository.Verify(r => r.ValidateAsync(refreshToken, It.IsAny<CancellationToken>()), Times.Once);
        _mockAuthService.Verify(s => s.GenerateTokensAsync(user, It.IsAny<CancellationToken>()), Times.Once);
    }
}
