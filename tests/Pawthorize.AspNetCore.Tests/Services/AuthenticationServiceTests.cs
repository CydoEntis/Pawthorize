using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.AspNetCore.Tests.Services;

public class AuthenticationServiceTests
{
    private readonly JwtService<TestUser> _jwtService;
    private readonly Mock<IRefreshTokenRepository> _mockRefreshTokenRepository;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly Mock<ILogger<AuthenticationService<TestUser>>> _mockLogger;
    private readonly PawthorizeOptions _options;
    private readonly AuthenticationService<TestUser> _service;

    public AuthenticationServiceTests()
    {
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

        // Use real JwtService instead of mock since methods are not virtual
        _jwtService = new JwtService<TestUser>(mockJwtOptions.Object);

        _mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        _mockLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();

        _options = new PawthorizeOptions
        {
            RequireEmailVerification = false,
            Jwt = jwtSettings
        };

        _mockOptions.Setup(o => o.Value).Returns(_options);

        _service = new AuthenticationService<TestUser>(
            _jwtService,
            _mockRefreshTokenRepository.Object,
            _mockOptions.Object,
            _mockLogger.Object
        );
    }

    #region GenerateTokensAsync Tests

    [Fact]
    public async Task GenerateTokensAsync_ShouldGenerateAccessToken()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var result = await _service.GenerateTokensAsync(user);

        result.AccessToken.Should().NotBeNullOrEmpty();
        result.TokenType.Should().Be("Bearer");
    }

    [Fact]
    public async Task GenerateTokensAsync_ShouldGenerateRefreshToken()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var result = await _service.GenerateTokensAsync(user);

        result.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GenerateTokensAsync_ShouldStoreRefreshTokenInRepository()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var cancellationToken = CancellationToken.None;

        var result = await _service.GenerateTokensAsync(user, cancellationToken);

        // The service hashes the token before storing it, so we verify with It.IsAny<string>()
        _mockRefreshTokenRepository.Verify(
            r => r.StoreAsync(
                It.IsAny<string>(),  // Token hash
                user.Id,
                It.Is<DateTime>(dt => dt > DateTime.UtcNow),
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task GenerateTokensAsync_ShouldSetCorrectExpirationTimes()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var beforeGeneration = DateTime.UtcNow;

        var result = await _service.GenerateTokensAsync(user);

        result.AccessTokenExpiresAt.Should().BeCloseTo(
            beforeGeneration.AddMinutes(15),
            TimeSpan.FromSeconds(2));

        result.RefreshTokenExpiresAt.Should().BeCloseTo(
            beforeGeneration.AddDays(7),
            TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task GenerateTokensAsync_WithCancellationToken_ShouldPassItToRepository()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var cancellationToken = new CancellationToken();

        await _service.GenerateTokensAsync(user, cancellationToken);

        _mockRefreshTokenRepository.Verify(
            r => r.StoreAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<DateTime>(),
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task GenerateTokensAsync_ShouldLogSuccessfully()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        await _service.GenerateTokensAsync(user);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Token pair generated successfully")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    #endregion

    #region ValidateAccountStatus Tests

    [Fact]
    public void ValidateAccountStatus_WithValidAccount_ShouldNotThrow()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = true
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAccountStatus_WithLockedAccountIndefinitely_ShouldThrowAccountLockedError()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = true,
            LockedUntil = null
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().Throw<AccountLockedError>();
    }

    [Fact]
    public void ValidateAccountStatus_WithLockedAccountUntilFuture_ShouldThrowAccountLockedError()
    {
        var lockUntil = DateTime.UtcNow.AddHours(1);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = true,
            LockedUntil = lockUntil
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().Throw<AccountLockedError>();
    }

    [Fact]
    public void ValidateAccountStatus_WithExpiredLock_ShouldNotThrow()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(-1)
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAccountStatus_WithUnverifiedEmailWhenRequired_ShouldThrowEmailNotVerifiedError()
    {
        _options.RequireEmailVerification = true;
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = false
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().Throw<EmailNotVerifiedError>();
    }

    [Fact]
    public void ValidateAccountStatus_WithUnverifiedEmailWhenNotRequired_ShouldNotThrow()
    {
        _options.RequireEmailVerification = false;
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = false
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAccountStatus_WithVerifiedEmailWhenRequired_ShouldNotThrow()
    {
        _options.RequireEmailVerification = true;
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = true
        };

        var act = () => _service.ValidateAccountStatus(user);

        act.Should().NotThrow();
    }

    [Fact]
    public void ValidateAccountStatus_ShouldLogValidationSteps()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = true
        };

        _service.ValidateAccountStatus(user);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Validating account status")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.AtLeastOnce);
    }

    [Fact]
    public void ValidateAccountStatus_WithLockedAccount_ShouldLogWarning()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = true,
            LockedUntil = null
        };

        try
        {
            _service.ValidateAccountStatus(user);
        }
        catch
        {
        }

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Account validation failed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void ValidateAccountStatus_WithUnverifiedEmail_ShouldLogWarning()
    {
        _options.RequireEmailVerification = true;
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = false
        };

        try
        {
            _service.ValidateAccountStatus(user);
        }
        catch
        {
        }

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Email not verified")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    #endregion

    #region Integration Tests

    [Fact]
    public async Task FullAuthFlow_ShouldGenerateTokensAfterValidation()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = false,
            IsEmailVerified = true
        };

        _service.ValidateAccountStatus(user); // Should not throw
        var result = await _service.GenerateTokensAsync(user);

        result.Should().NotBeNull();
        result.AccessToken.Should().NotBeNullOrEmpty();
        result.RefreshToken.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void FullAuthFlow_WithLockedAccount_ShouldNotGenerateTokens()
    {
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            IsLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };

        var act = () => _service.ValidateAccountStatus(user);
        act.Should().Throw<AccountLockedError>();

        _mockRefreshTokenRepository.Verify(
            r => r.StoreAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<DateTime>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    #endregion
}

public class TestUser : IAuthenticatedUser
{
    public string Id { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string? Name { get; set; }
    public bool IsEmailVerified { get; set; } = true;
    public bool IsLocked { get; set; } = false;
    public DateTime? LockedUntil { get; set; }
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }
}
