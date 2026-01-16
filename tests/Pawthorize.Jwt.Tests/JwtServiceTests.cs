using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.Jwt.Tests;

public class JwtServiceTests
{
    private readonly JwtSettings _validSettings;
    private readonly Mock<IOptions<JwtSettings>> _mockOptions;

    public JwtServiceTests()
    {
        _validSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenLifetimeMinutes = 15,
            RefreshTokenLifetimeDaysRemembered = 30,
            RefreshTokenLifetimeHoursDefault = 24
        };
        _mockOptions = new Mock<IOptions<JwtSettings>>();
        _mockOptions.Setup(o => o.Value).Returns(_validSettings);
    }

    #region Token Generation Tests

    [Fact]
    public void GenerateAccessToken_WithMinimalUserInfo_ShouldGenerateValidToken()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var token = service.GenerateAccessToken(user);

        token.Should().NotBeNullOrEmpty();
        var handler = new JwtSecurityTokenHandler();
        handler.CanReadToken(token).Should().BeTrue();

        var jwtToken = handler.ReadJwtToken(token);
        jwtToken.Claims.Should().Contain(c => c.Type == ClaimTypes.NameIdentifier && c.Value == "user123");
        jwtToken.Claims.Should().Contain(c => c.Type == ClaimTypes.Email && c.Value == "test@example.com");
        jwtToken.Claims.Should().Contain(c => c.Type == JwtRegisteredClaimNames.Jti);
        jwtToken.Issuer.Should().Be("test-issuer");
        jwtToken.Audiences.Should().Contain("test-audience");
    }

    [Fact]
    public void GenerateAccessToken_WithFullUserInfo_ShouldIncludeAllClaims()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            Name = "John Doe",
            Roles = new List<string> { "Admin", "User" },
            AdditionalClaims = new Dictionary<string, string>
            {
                { "department", "Engineering" },
                { "level", "Senior" }
            }
        };

        var token = service.GenerateAccessToken(user);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.Claims.Should().Contain(c => c.Type == ClaimTypes.Name && c.Value == "John Doe");
        jwtToken.Claims.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == "Admin");
        jwtToken.Claims.Should().Contain(c => c.Type == ClaimTypes.Role && c.Value == "User");
        jwtToken.Claims.Should().Contain(c => c.Type == "department" && c.Value == "Engineering");
        jwtToken.Claims.Should().Contain(c => c.Type == "level" && c.Value == "Senior");
    }

    [Fact]
    public void GenerateAccessToken_WithoutName_ShouldNotIncludeNameClaim()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            Name = null
        };

        var token = service.GenerateAccessToken(user);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.Claims.Should().NotContain(c => c.Type == ClaimTypes.Name);
    }

    [Fact]
    public void GenerateAccessToken_WithEmptyRoles_ShouldNotIncludeRoleClaims()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            Roles = new List<string>()
        };

        var token = service.GenerateAccessToken(user);

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        jwtToken.Claims.Should().NotContain(c => c.Type == ClaimTypes.Role);
    }

    [Fact]
    public void GenerateAccessToken_ShouldSetCorrectExpiration()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var beforeGeneration = DateTime.UtcNow;

        var token = service.GenerateAccessToken(user);

        var afterGeneration = DateTime.UtcNow;

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(token);

        var expectedExpiration = beforeGeneration.AddMinutes(15);
        jwtToken.ValidTo.Should().BeCloseTo(expectedExpiration, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public void GenerateAccessToken_MultipleCallsForSameUser_ShouldGenerateDifferentTokens()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var token1 = service.GenerateAccessToken(user);
        Thread.Sleep(10);
        var token2 = service.GenerateAccessToken(user);

        token1.Should().NotBe(token2, "each token should have a unique JTI and timestamp");
    }

    #endregion

    #region Refresh Token Generation Tests

    [Fact]
    public void GenerateRefreshToken_ShouldReturnBase64String()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);

        var refreshToken = service.GenerateRefreshToken();

        refreshToken.Should().NotBeNullOrEmpty();

        var act = () => Convert.FromBase64String(refreshToken);
        act.Should().NotThrow();
    }

    [Fact]
    public void GenerateRefreshToken_ShouldGenerateUniqueTokens()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);

        var tokens = new HashSet<string>();
        for (int i = 0; i < 100; i++)
        {
            tokens.Add(service.GenerateRefreshToken());
        }

        tokens.Should().HaveCount(100, "all 100 tokens should be unique");
    }

    [Fact]
    public void GenerateRefreshToken_ShouldGenerate64ByteToken()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);

        var refreshToken = service.GenerateRefreshToken();
        var bytes = Convert.FromBase64String(refreshToken);

        bytes.Should().HaveCount(64, "token should be 64 bytes as specified in implementation");
    }

    #endregion

    #region Token Validation Tests

    [Fact]
    public void ValidateToken_WithValidToken_ShouldReturnClaimsPrincipal()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com",
            Name = "John Doe"
        };
        var token = service.GenerateAccessToken(user);

        var principal = service.ValidateToken(token);

        principal.Should().NotBeNull();
        principal!.FindFirst(ClaimTypes.NameIdentifier)?.Value.Should().Be("user123");
        principal!.FindFirst(ClaimTypes.Email)?.Value.Should().Be("test@example.com");
        principal!.FindFirst(ClaimTypes.Name)?.Value.Should().Be("John Doe");
    }

    [Fact]
    public void ValidateToken_WithExpiredToken_ShouldReturnNull()
    {
        var expiredSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenLifetimeMinutes = 0
        };
        var mockExpiredOptions = new Mock<IOptions<JwtSettings>>();
        mockExpiredOptions.Setup(o => o.Value).Returns(expiredSettings);

        var service = new JwtService<TestUser>(mockExpiredOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service.GenerateAccessToken(user);

        Thread.Sleep(1100);

        var principal = service.ValidateToken(token);

        principal.Should().BeNull("token is expired");
    }

    [Fact]
    public void ValidateToken_WithInvalidSignature_ShouldReturnNull()
    {
        var service1 = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service1.GenerateAccessToken(user);

        var differentSettings = new JwtSettings
        {
            Secret = "different-secret-key-that-is-also-32-characters-long-or-more",
            Issuer = "test-issuer",
            Audience = "test-audience"
        };
        var mockDifferentOptions = new Mock<IOptions<JwtSettings>>();
        mockDifferentOptions.Setup(o => o.Value).Returns(differentSettings);
        var service2 = new JwtService<TestUser>(mockDifferentOptions.Object);

        var principal = service2.ValidateToken(token);

        principal.Should().BeNull("token was signed with a different secret");
    }

    [Fact]
    public void ValidateToken_WithInvalidIssuer_ShouldReturnNull()
    {
        var service1 = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service1.GenerateAccessToken(user);

        var differentSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "different-issuer",
            Audience = "test-audience"
        };
        var mockDifferentOptions = new Mock<IOptions<JwtSettings>>();
        mockDifferentOptions.Setup(o => o.Value).Returns(differentSettings);
        var service2 = new JwtService<TestUser>(mockDifferentOptions.Object);

        var principal = service2.ValidateToken(token);

        principal.Should().BeNull("token has a different issuer");
    }

    [Fact]
    public void ValidateToken_WithInvalidAudience_ShouldReturnNull()
    {
        var service1 = new JwtService<TestUser>(_mockOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service1.GenerateAccessToken(user);

        var differentSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "different-audience"
        };
        var mockDifferentOptions = new Mock<IOptions<JwtSettings>>();
        mockDifferentOptions.Setup(o => o.Value).Returns(differentSettings);
        var service2 = new JwtService<TestUser>(mockDifferentOptions.Object);

        var principal = service2.ValidateToken(token);

        principal.Should().BeNull("token has a different audience");
    }

    [Fact]
    public void ValidateToken_WithMalformedToken_ShouldReturnNull()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);

        var principal = service.ValidateToken("this-is-not-a-valid-jwt-token");

        principal.Should().BeNull();
    }

    [Fact]
    public void ValidateToken_WithEmptyToken_ShouldReturnNull()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);

        var principal = service.ValidateToken("");

        principal.Should().BeNull();
    }

    #endregion

    #region Expiration Tests

    [Fact]
    public void GetAccessTokenExpiration_ShouldReturnCorrectExpiration()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var beforeCall = DateTime.UtcNow;

        var expiration = service.GetAccessTokenExpiration();

        var afterCall = DateTime.UtcNow;

        var expectedExpiration = beforeCall.AddMinutes(15);
        expiration.Should().BeCloseTo(expectedExpiration, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void GetRefreshTokenExpiration_WhenNotRemembered_ShouldReturnDefaultExpiration()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var beforeCall = DateTime.UtcNow;

        var expiration = service.GetRefreshTokenExpiration(rememberMe: false);

        var expectedExpiration = beforeCall.AddHours(24);
        expiration.Should().BeCloseTo(expectedExpiration, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void GetRefreshTokenExpiration_WhenRemembered_ShouldReturnLongerExpiration()
    {
        var service = new JwtService<TestUser>(_mockOptions.Object);
        var beforeCall = DateTime.UtcNow;

        var expiration = service.GetRefreshTokenExpiration(rememberMe: true);

        var expectedExpiration = beforeCall.AddDays(30);
        expiration.Should().BeCloseTo(expectedExpiration, TimeSpan.FromSeconds(1));
    }

    #endregion

    #region Secret Handling Tests

    [Fact]
    public void GenerateAccessToken_WithMissingSecret_ShouldThrowInvalidOperationException()
    {
        var invalidSettings = new JwtSettings
        {
            Secret = null,
            Issuer = "test-issuer",
            Audience = "test-audience"
        };
        var mockInvalidOptions = new Mock<IOptions<JwtSettings>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidSettings);

        var service = new JwtService<TestUser>(mockInvalidOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var act = () => service.GenerateAccessToken(user);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*JWT Secret is not configured*");
    }

    [Fact]
    public void GenerateAccessToken_WithShortSecret_ShouldThrowInvalidOperationException()
    {
        var invalidSettings = new JwtSettings
        {
            Secret = "too-short",
            Issuer = "test-issuer",
            Audience = "test-audience"
        };
        var mockInvalidOptions = new Mock<IOptions<JwtSettings>>();
        mockInvalidOptions.Setup(o => o.Value).Returns(invalidSettings);

        var service = new JwtService<TestUser>(mockInvalidOptions.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var act = () => service.GenerateAccessToken(user);

        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*JWT Secret must be at least 32 characters*");
    }

    #endregion

    #region Logging Tests

    [Fact]
    public void GenerateAccessToken_WithLogger_ShouldLogSuccessfully()
    {
        var mockLogger = new Mock<ILogger<JwtService<TestUser>>>();
        var service = new JwtService<TestUser>(_mockOptions.Object, mockLogger.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };

        var token = service.GenerateAccessToken(user);

        token.Should().NotBeNullOrEmpty();
        mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Access token generated successfully")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void ValidateToken_WithValidTokenAndLogger_ShouldLogSuccessfully()
    {
        var mockLogger = new Mock<ILogger<JwtService<TestUser>>>();
        var service = new JwtService<TestUser>(_mockOptions.Object, mockLogger.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service.GenerateAccessToken(user);

        mockLogger.Invocations.Clear();

        var principal = service.ValidateToken(token);

        principal.Should().NotBeNull();
        mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("JWT token validated successfully")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public void ValidateToken_WithExpiredTokenAndLogger_ShouldLogWarning()
    {
        var mockLogger = new Mock<ILogger<JwtService<TestUser>>>();
        var expiredSettings = new JwtSettings
        {
            Secret = "this-is-a-test-secret-key-that-is-at-least-32-characters-long",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenLifetimeMinutes = 0
        };
        var mockExpiredOptions = new Mock<IOptions<JwtSettings>>();
        mockExpiredOptions.Setup(o => o.Value).Returns(expiredSettings);

        var service = new JwtService<TestUser>(mockExpiredOptions.Object, mockLogger.Object);
        var user = new TestUser
        {
            Id = "user123",
            Email = "test@example.com"
        };
        var token = service.GenerateAccessToken(user);

        Thread.Sleep(1100);
        mockLogger.Invocations.Clear();

        var principal = service.ValidateToken(token);

        principal.Should().BeNull();
        mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Token validation failed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    #endregion
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
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LockoutEnd { get; set; }
    public IEnumerable<string> Roles { get; set; } = new List<string>();
    public IDictionary<string, string>? AdditionalClaims { get; set; }
}
