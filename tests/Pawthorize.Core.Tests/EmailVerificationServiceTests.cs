using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;
using Pawthorize.Core.Services;
using Xunit;

namespace Pawthorize.Core.Tests;

public class EmailVerificationServiceTests
{
    private readonly Mock<ITokenRepository> _mockTokenRepository;
    private readonly Mock<IEmailSender> _mockEmailSender;
    private readonly Mock<IEmailTemplateProvider> _mockTemplateProvider;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly PawthorizeOptions _options;
    private readonly EmailVerificationService _service;

    public EmailVerificationServiceTests()
    {
        _mockTokenRepository = new Mock<ITokenRepository>();
        _mockEmailSender = new Mock<IEmailSender>();
        _mockTemplateProvider = new Mock<IEmailTemplateProvider>();
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();

        _options = new PawthorizeOptions
        {
            EmailVerification = new EmailVerificationOptions
            {
                TokenLifetime = TimeSpan.FromHours(24),
                BaseUrl = "https://myapp.com",
                VerificationPath = "/verify-email",
                ApplicationName = "MyApp"
            }
        };

        _mockOptions.Setup(o => o.Value).Returns(_options);

        _service = new EmailVerificationService(
            _mockTokenRepository.Object,
            _mockEmailSender.Object,
            _mockTemplateProvider.Object,
            _mockOptions.Object
        );
    }

    #region SendVerificationEmailAsync Tests

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldGenerateTokenAndStoreIt()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        var token = await _service.SendVerificationEmailAsync(userId, email, cancellationToken);

        token.Should().NotBeNullOrEmpty();

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                token,
                TokenType.EmailVerification,
                It.Is<DateTime>(dt => dt > DateTime.UtcNow && dt <= DateTime.UtcNow.AddHours(25)),
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldSendEmailWithCorrectParameters()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        var expectedHtml = "<html>Verification email</html>";

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns(expectedHtml);

        await _service.SendVerificationEmailAsync(userId, email, cancellationToken);

        _mockEmailSender.Verify(
            s => s.SendEmailAsync(
                email,
                "Verify your email for MyApp",
                expectedHtml,
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldBuildVerificationUrlCorrectly()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Verification email</html>");

        var token = await _service.SendVerificationEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/verify-email?token=");
        capturedUrl.Should().Contain(token);
    }

    [Fact]
    public async Task SendVerificationEmailAsync_WithTrailingSlashInBaseUrl_ShouldBuildCorrectUrl()
    {
        _options.EmailVerification.BaseUrl = "https://myapp.com/";
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Verification email</html>");

        await _service.SendVerificationEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/verify-email?token=");
        capturedUrl.Should().NotContain("//verify-email");
    }

    [Fact]
    public async Task SendVerificationEmailAsync_WithLeadingSlashInVerificationPath_ShouldBuildCorrectUrl()
    {
        _options.EmailVerification.VerificationPath = "/verify-email";
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Verification email</html>");

        await _service.SendVerificationEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/verify-email?token=");
    }

    [Fact]
    public async Task SendVerificationEmailAsync_WithoutBaseUrl_ShouldThrowInvalidOperationException()
    {
        _options.EmailVerification.BaseUrl = string.Empty;
        var userId = "user123";
        var email = "test@example.com";

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        var act = async () => await _service.SendVerificationEmailAsync(userId, email);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*EmailVerification.BaseUrl is not configured*");
    }

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldReturnGeneratedToken()
    {
        var userId = "user123";
        var email = "test@example.com";

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        var token = await _service.SendVerificationEmailAsync(userId, email);

        token.Should().NotBeNullOrEmpty();
        token.Should().HaveLength(43); // URL-safe base64 encoded 32 bytes (without padding)
    }

    #endregion

    #region VerifyEmailAsync Tests

    [Fact]
    public async Task VerifyEmailAsync_WithValidToken_ShouldReturnUserId()
    {
        var token = "valid-token";
        var userId = "user123";
        var tokenInfo = new TokenInfo
        {
            UserId = userId,
            CreatedAt = DateTime.UtcNow.AddHours(-1),
            ExpiresAt = DateTime.UtcNow.AddHours(23)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        var result = await _service.VerifyEmailAsync(token);

        result.Should().Be(userId);
    }

    [Fact]
    public async Task VerifyEmailAsync_WithValidToken_ShouldInvalidateToken()
    {
        var token = "valid-token";
        var userId = "user123";
        var cancellationToken = CancellationToken.None;
        var tokenInfo = new TokenInfo
        {
            UserId = userId,
            CreatedAt = DateTime.UtcNow.AddHours(-1),
            ExpiresAt = DateTime.UtcNow.AddHours(23)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, cancellationToken))
            .ReturnsAsync(tokenInfo);

        await _service.VerifyEmailAsync(token, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(token, TokenType.EmailVerification, cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task VerifyEmailAsync_WithExpiredToken_ShouldReturnNull()
    {
        var token = "expired-token";
        var tokenInfo = new TokenInfo
        {
            UserId = "user123",
            CreatedAt = DateTime.UtcNow.AddHours(-25),
            ExpiresAt = DateTime.UtcNow.AddHours(-1)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        var result = await _service.VerifyEmailAsync(token);

        result.Should().BeNull();
    }

    [Fact]
    public async Task VerifyEmailAsync_WithExpiredToken_ShouldNotInvalidateToken()
    {
        var token = "expired-token";
        var tokenInfo = new TokenInfo
        {
            UserId = "user123",
            CreatedAt = DateTime.UtcNow.AddHours(-25),
            ExpiresAt = DateTime.UtcNow.AddHours(-1)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        await _service.VerifyEmailAsync(token);

        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(It.IsAny<string>(), It.IsAny<TokenType>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    [Fact]
    public async Task VerifyEmailAsync_WithInvalidToken_ShouldReturnNull()
    {
        var token = "invalid-token";

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TokenInfo?)null);

        var result = await _service.VerifyEmailAsync(token);

        result.Should().BeNull();
    }

    [Fact]
    public async Task VerifyEmailAsync_WithInvalidToken_ShouldNotInvalidateToken()
    {
        var token = "invalid-token";

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TokenInfo?)null);

        await _service.VerifyEmailAsync(token);

        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(It.IsAny<string>(), It.IsAny<TokenType>(), It.IsAny<CancellationToken>()),
            Times.Never);
    }

    #endregion

    #region ResendVerificationEmailAsync Tests

    [Fact]
    public async Task ResendVerificationEmailAsync_ShouldInvalidateAllExistingTokens()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        await _service.ResendVerificationEmailAsync(userId, email, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.InvalidateAllTokensForUserAsync(userId, TokenType.EmailVerification, cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task ResendVerificationEmailAsync_ShouldGenerateAndSendNewVerificationEmail()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        await _service.ResendVerificationEmailAsync(userId, email, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                It.IsAny<string>(),
                TokenType.EmailVerification,
                It.IsAny<DateTime>(),
                cancellationToken),
            Times.Once);

        _mockEmailSender.Verify(
            s => s.SendEmailAsync(
                email,
                It.IsAny<string>(),
                It.IsAny<string>(),
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task ResendVerificationEmailAsync_ShouldInvalidateTokensBeforeSendingNewEmail()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        var callOrder = new List<string>();

        _mockTokenRepository
            .Setup(r => r.InvalidateAllTokensForUserAsync(userId, TokenType.EmailVerification, cancellationToken))
            .Callback(() => callOrder.Add("invalidate"))
            .Returns(Task.CompletedTask);

        _mockTokenRepository
            .Setup(r => r.StoreTokenAsync(
                userId,
                It.IsAny<string>(),
                TokenType.EmailVerification,
                It.IsAny<DateTime>(),
                cancellationToken))
            .Callback(() => callOrder.Add("store"))
            .Returns(Task.CompletedTask);

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        await _service.ResendVerificationEmailAsync(userId, email, cancellationToken);

        callOrder.Should().HaveCount(2);
        callOrder[0].Should().Be("invalidate");
        callOrder[1].Should().Be("store");
    }

    #endregion

    #region Token Lifetime Tests

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldUseConfiguredTokenLifetime()
    {
        _options.EmailVerification.TokenLifetime = TimeSpan.FromHours(48);
        var userId = "user123";
        var email = "test@example.com";
        var beforeSend = DateTime.UtcNow;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        await _service.SendVerificationEmailAsync(userId, email);

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                It.IsAny<string>(),
                TokenType.EmailVerification,
                It.Is<DateTime>(dt => dt >= beforeSend.AddHours(48) && dt <= DateTime.UtcNow.AddHours(49)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    #endregion

    #region Email Template Tests

    [Fact]
    public async Task SendVerificationEmailAsync_ShouldCallTemplateProviderWithCorrectParameters()
    {
        var userId = "user123";
        var email = "test@example.com";
        string? capturedUrl = null;
        string? capturedEmail = null;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), It.IsAny<string>()))
            .Callback<string, string>((url, e) =>
            {
                capturedUrl = url;
                capturedEmail = e;
            })
            .Returns("<html>Verification email</html>");

        var token = await _service.SendVerificationEmailAsync(userId, email);

        capturedEmail.Should().Be(email);
        capturedUrl.Should().Contain(token);
        capturedUrl.Should().StartWith("https://myapp.com/verify-email?token=");
    }

    #endregion

    #region Integration Flow Tests

    [Fact]
    public async Task CompleteVerificationFlow_ShouldWorkEndToEnd()
    {
        var userId = "user123";
        var email = "test@example.com";
        string? generatedToken = null;

        _mockTemplateProvider
            .Setup(t => t.GetEmailVerificationTemplate(It.IsAny<string>(), email))
            .Returns("<html>Verification email</html>");

        _mockTokenRepository
            .Setup(r => r.StoreTokenAsync(
                It.IsAny<string>(),
                It.IsAny<string>(),
                It.IsAny<TokenType>(),
                It.IsAny<DateTime>(),
                It.IsAny<CancellationToken>()))
            .Callback<string, string, TokenType, DateTime, CancellationToken>((_, token, _, _, _) =>
            {
                generatedToken = token;
            })
            .Returns(Task.CompletedTask);

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(It.IsAny<string>(), TokenType.EmailVerification, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string token, TokenType type, CancellationToken ct) =>
            {
                if (token == generatedToken)
                {
                    return new TokenInfo
                    {
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow.AddHours(-1),
                        ExpiresAt = DateTime.UtcNow.AddHours(23)
                    };
                }
                return null;
            });

        // Act - Send verification email
        var token = await _service.SendVerificationEmailAsync(userId, email);

        // Act - Verify email with the token
        var verifiedUserId = await _service.VerifyEmailAsync(token);

        verifiedUserId.Should().Be(userId);
        _mockEmailSender.Verify(
            s => s.SendEmailAsync(email, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(token, TokenType.EmailVerification, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    #endregion
}
