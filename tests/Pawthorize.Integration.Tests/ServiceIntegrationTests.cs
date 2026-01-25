using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Integration.Tests.Helpers;
using Pawthorize.Configuration;
using Pawthorize.Services.Models;
using Pawthorize.Services;
using Pawthorize.Internal;
using Xunit;

namespace Pawthorize.Integration.Tests;

/// <summary>
/// Integration tests that verify services work together correctly with real implementations.
/// Tests use in-memory repositories (not mocks) to verify complete data flows.
/// </summary>
public class ServiceIntegrationTests : IDisposable
{
    private readonly InMemoryUserRepository<TestUser> _userRepository;
    private readonly InMemoryTokenRepository _tokenRepository;
    private readonly InMemoryRefreshTokenRepository _refreshTokenRepository;
    private readonly InMemoryEmailSender _emailSender;
    private readonly TestEmailTemplateProvider _templateProvider;
    private readonly PasswordHasher _passwordHasher;
    private readonly JwtService<TestUser> _jwtService;
    private readonly AuthenticationService<TestUser> _authService;
    private readonly EmailVerificationService _emailVerificationService;
    private readonly PasswordResetService _passwordResetService;
    private readonly PawthorizeOptions _options;

    public ServiceIntegrationTests()
    {
        _userRepository = new InMemoryUserRepository<TestUser>();
        _tokenRepository = new InMemoryTokenRepository();
        _refreshTokenRepository = new InMemoryRefreshTokenRepository();
        _emailSender = new InMemoryEmailSender();
        _templateProvider = new TestEmailTemplateProvider();

        _options = new PawthorizeOptions
        {
            RequireEmailVerification = true,
            TokenDelivery = TokenDeliveryStrategy.ResponseBody,
            Jwt = new JwtSettings
            {
                Secret = "integration-test-secret-key-must-be-at-least-32-characters-long",
                Issuer = "pawthorize-integration-tests",
                Audience = "pawthorize-integration-tests",
                AccessTokenLifetimeMinutes = 15,
                RefreshTokenLifetimeDaysRemembered = 30,
                RefreshTokenLifetimeHoursDefault = 24
            },
            EmailVerification = new EmailVerificationOptions
            {
                TokenLifetime = TimeSpan.FromHours(24),
                BaseUrl = "https://test-app.com",
                VerificationPath = "/verify-email",
                ApplicationName = "Test App"
            },
            PasswordReset = new PasswordResetOptions
            {
                TokenLifetime = TimeSpan.FromHours(1),
                BaseUrl = "https://test-app.com",
                ResetPath = "/reset-password",
                ApplicationName = "Test App"
            }
        };

        var mockOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockOptions.Setup(o => o.Value).Returns(_options);

        var mockJwtOptions = new Mock<IOptions<JwtSettings>>();
        mockJwtOptions.Setup(o => o.Value).Returns(_options.Jwt);

        _passwordHasher = new PasswordHasher();
        _jwtService = new JwtService<TestUser>(mockJwtOptions.Object);
        _authService = new AuthenticationService<TestUser>(
            _jwtService,
            _refreshTokenRepository,
            mockOptions.Object,
            Mock.Of<ILogger<AuthenticationService<TestUser>>>()
        );
        _emailVerificationService = new EmailVerificationService(
            _tokenRepository,
            _emailSender,
            _templateProvider,
            mockOptions.Object
        );
        _passwordResetService = new PasswordResetService(
            _tokenRepository,
            _emailSender,
            _templateProvider,
            mockOptions.Object
        );
    }

    public void Dispose()
    {
        _userRepository.Clear();
        _tokenRepository.Clear();
        _refreshTokenRepository.Clear();
        _emailSender.Clear();
    }

    #region Registration → Email Verification → Login Flow

    [Fact]
    public async Task CompleteAuthFlow_RegisterVerifyLogin_ShouldSucceed()
    {
        var user = new TestUser
        {
            Email = "newuser@test.com",
            Name = "Test User",
            PasswordHash = _passwordHasher.HashPassword("SecurePass123!"),
            IsEmailVerified = false
        };

        await _userRepository.CreateAsync(user);

        var verificationToken = await _emailVerificationService.SendVerificationEmailAsync(
            user.Id,
            user.Email
        );

        _emailSender.SentEmails.Should().HaveCount(1);
        _emailSender.SentEmails[0].To.Should().Be("newuser@test.com");

        var verifiedUserId = await _emailVerificationService.VerifyEmailAsync(verificationToken);
        verifiedUserId.Should().Be(user.Id);

        user.IsEmailVerified = true;
        await _userRepository.UpdateAsync(user);

        _authService.ValidateAccountStatus(user); // Should not throw
        var authResult = await _authService.GenerateTokensAsync(user);

        authResult.AccessToken.Should().NotBeNullOrEmpty();
        authResult.RefreshToken.Should().NotBeNullOrEmpty();

        var principal = _jwtService.ValidateToken(authResult.AccessToken);
        principal.Should().NotBeNull();
        principal!.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value.Should().Be("newuser@test.com");
    }

    [Fact]
    public async Task EmailVerification_WithExpiredToken_ShouldFail()
    {
        _options.EmailVerification.TokenLifetime = TimeSpan.FromMilliseconds(1);

        var user = new TestUser
        {
            Email = "user@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass123!"),
            IsEmailVerified = false
        };

        await _userRepository.CreateAsync(user);

        var verificationToken = await _emailVerificationService.SendVerificationEmailAsync(
            user.Id,
            user.Email
        );

        await Task.Delay(100);

        var result = await _emailVerificationService.VerifyEmailAsync(verificationToken);

        result.Should().BeNull("token should be expired");
    }

    #endregion

    #region Password Reset Flow

    [Fact]
    public async Task CompletePasswordResetFlow_ShouldSucceed()
    {
        var oldPasswordHash = _passwordHasher.HashPassword("OldPassword123!");
        var user = new TestUser
        {
            Email = "resetuser@test.com",
            PasswordHash = oldPasswordHash,
            IsEmailVerified = true
        };

        await _userRepository.CreateAsync(user);

        var resetToken = await _passwordResetService.SendPasswordResetEmailAsync(
            user.Id,
            user.Email
        );

        _emailSender.SentEmails.Should().HaveCount(1);
        _emailSender.SentEmails[0].Subject.Should().Contain("Reset");

        var validatedUserId = await _passwordResetService.ValidateResetTokenAsync(resetToken);
        validatedUserId.Should().Be(user.Id);

        var newPasswordHash = _passwordHasher.HashPassword("NewPassword456!");
        await _userRepository.UpdatePasswordAsync(user.Id, newPasswordHash);

        // Step 5: Invalidate reset token
        await _passwordResetService.InvalidateResetTokenAsync(resetToken);

        var revalidatedUserId = await _passwordResetService.ValidateResetTokenAsync(resetToken);
        revalidatedUserId.Should().BeNull("token should be invalidated");

        var updatedUser = await _userRepository.FindByIdAsync(user.Id);
        var oldPasswordWorks = _passwordHasher.VerifyPassword("OldPassword123!", updatedUser!.PasswordHash);
        oldPasswordWorks.Should().BeFalse();

        var newPasswordWorks = _passwordHasher.VerifyPassword("NewPassword456!", updatedUser.PasswordHash);
        newPasswordWorks.Should().BeTrue();
    }

    [Fact]
    public async Task PasswordReset_WithExpiredToken_ShouldFail()
    {
        _options.PasswordReset.TokenLifetime = TimeSpan.FromMilliseconds(1);

        var user = new TestUser
        {
            Email = "user@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass123!"),
            IsEmailVerified = true
        };

        await _userRepository.CreateAsync(user);

        var resetToken = await _passwordResetService.SendPasswordResetEmailAsync(
            user.Id,
            user.Email
        );

        await Task.Delay(100);

        var result = await _passwordResetService.ValidateResetTokenAsync(resetToken);

        result.Should().BeNull("token should be expired");
    }

    #endregion

    #region Token Refresh Flow

    [Fact]
    public async Task TokenRefresh_WithValidRefreshToken_ShouldSucceed()
    {
        var user = new TestUser
        {
            Email = "refreshuser@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass123!"),
            IsEmailVerified = true
        };

        await _userRepository.CreateAsync(user);

        var initialAuthResult = await _authService.GenerateTokensAsync(user);
        var initialRefreshTokenHash = TokenHasher.HashToken(initialAuthResult.RefreshToken!);

        var tokenInfo = await _refreshTokenRepository.ValidateAsync(initialRefreshTokenHash);
        tokenInfo.Should().NotBeNull();
        tokenInfo!.UserId.Should().Be(user.Id);
        tokenInfo.IsRevoked.Should().BeFalse();
        tokenInfo.IsExpired.Should().BeFalse();

        await _refreshTokenRepository.RevokeAsync(initialRefreshTokenHash);

        var newAuthResult = await _authService.GenerateTokensAsync(user);

        newAuthResult.AccessToken.Should().NotBe(initialAuthResult.AccessToken);
        newAuthResult.RefreshToken.Should().NotBe(initialAuthResult.RefreshToken);

        var oldTokenInfo = await _refreshTokenRepository.ValidateAsync(initialRefreshTokenHash);
        oldTokenInfo!.IsRevoked.Should().BeTrue();
    }

    [Fact]
    public async Task TokenRevocation_RevokeAllForUser_ShouldRevokeAllTokens()
    {
        var user = new TestUser
        {
            Email = "multitoken@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass123!"),
            IsEmailVerified = true
        };

        await _userRepository.CreateAsync(user);

        var token1 = await _authService.GenerateTokensAsync(user);
        var token2 = await _authService.GenerateTokensAsync(user);
        var token3 = await _authService.GenerateTokensAsync(user);

        await _refreshTokenRepository.RevokeAllForUserAsync(user.Id);

        var token1Hash = TokenHasher.HashToken(token1.RefreshToken!);
        var token2Hash = TokenHasher.HashToken(token2.RefreshToken!);
        var token3Hash = TokenHasher.HashToken(token3.RefreshToken!);

        var token1Info = await _refreshTokenRepository.ValidateAsync(token1Hash);
        var token2Info = await _refreshTokenRepository.ValidateAsync(token2Hash);
        var token3Info = await _refreshTokenRepository.ValidateAsync(token3Hash);

        token1Info!.IsRevoked.Should().BeTrue();
        token2Info!.IsRevoked.Should().BeTrue();
        token3Info!.IsRevoked.Should().BeTrue();
    }

    #endregion

    #region Password Verification

    [Fact]
    public void PasswordHasher_Integration_ShouldHashAndVerifyCorrectly()
    {
        var password = "MySecurePassword123!";

        var hash = _passwordHasher.HashPassword(password);

        _passwordHasher.VerifyPassword(password, hash).Should().BeTrue();
        _passwordHasher.VerifyPassword("WrongPassword", hash).Should().BeFalse();

        var hash2 = _passwordHasher.HashPassword(password);
        hash2.Should().NotBe(hash, "BCrypt should generate unique salts");
    }

    #endregion

    #region Multi-User Scenarios

    [Fact]
    public async Task MultipleUsers_IndependentFlows_ShouldNotInterfere()
    {
        var user1 = new TestUser
        {
            Email = "user1@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass1!"),
            IsEmailVerified = true
        };
        await _userRepository.CreateAsync(user1);

        var user2 = new TestUser
        {
            Email = "user2@test.com",
            PasswordHash = _passwordHasher.HashPassword("Pass2!"),
            IsEmailVerified = true
        };
        await _userRepository.CreateAsync(user2);

        var auth1 = await _authService.GenerateTokensAsync(user1);
        var auth2 = await _authService.GenerateTokensAsync(user2);

        auth1.AccessToken.Should().NotBe(auth2.AccessToken);
        auth1.RefreshToken.Should().NotBe(auth2.RefreshToken);

        var principal1 = _jwtService.ValidateToken(auth1.AccessToken);
        var principal2 = _jwtService.ValidateToken(auth2.AccessToken);

        principal1!.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value.Should().Be("user1@test.com");
        principal2!.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value.Should().Be("user2@test.com");

        await _refreshTokenRepository.RevokeAllForUserAsync(user1.Id);

        var auth1Hash = TokenHasher.HashToken(auth1.RefreshToken!);
        var auth2Hash = TokenHasher.HashToken(auth2.RefreshToken!);

        var token1Info = await _refreshTokenRepository.ValidateAsync(auth1Hash);
        var token2Info = await _refreshTokenRepository.ValidateAsync(auth2Hash);

        token1Info!.IsRevoked.Should().BeTrue();
        token2Info!.IsRevoked.Should().BeFalse();
    }

    #endregion
}
