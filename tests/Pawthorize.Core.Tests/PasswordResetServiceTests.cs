using FluentAssertions;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.Models;
using Pawthorize.Services;
using Xunit;

namespace Pawthorize.Core.Tests;

public class PasswordResetServiceTests
{
    private readonly Mock<ITokenRepository> _mockTokenRepository;
    private readonly Mock<IEmailSender> _mockEmailSender;
    private readonly Mock<IEmailTemplateProvider> _mockTemplateProvider;
    private readonly Mock<IOptions<PawthorizeOptions>> _mockOptions;
    private readonly PawthorizeOptions _options;
    private readonly PasswordResetService _service;

    public PasswordResetServiceTests()
    {
        _mockTokenRepository = new Mock<ITokenRepository>();
        _mockEmailSender = new Mock<IEmailSender>();
        _mockTemplateProvider = new Mock<IEmailTemplateProvider>();
        _mockOptions = new Mock<IOptions<PawthorizeOptions>>();

        _options = new PawthorizeOptions
        {
            PasswordReset = new PasswordResetOptions
            {
                TokenLifetime = TimeSpan.FromHours(1),
                BaseUrl = "https://myapp.com",
                ResetPath = "/reset-password",
                ApplicationName = "MyApp"
            }
        };

        _mockOptions.Setup(o => o.Value).Returns(_options);

        _service = new PasswordResetService(
            _mockTokenRepository.Object,
            _mockEmailSender.Object,
            _mockTemplateProvider.Object,
            _mockOptions.Object
        );
    }

    #region SendPasswordResetEmailAsync Tests

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldGenerateTokenAndStoreIt()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

        var token = await _service.SendPasswordResetEmailAsync(userId, email, cancellationToken);

        token.Should().NotBeNullOrEmpty();

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                token,
                TokenType.PasswordReset,
                It.Is<DateTime>(dt => dt > DateTime.UtcNow && dt <= DateTime.UtcNow.AddHours(2)),
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldSendEmailWithCorrectParameters()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        var expectedHtml = "<html>Password reset email</html>";

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns(expectedHtml);

        await _service.SendPasswordResetEmailAsync(userId, email, cancellationToken);

        _mockEmailSender.Verify(
            s => s.SendEmailAsync(
                email,
                "Reset your password for MyApp",
                expectedHtml,
                cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldBuildResetUrlCorrectly()
    {
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Password reset email</html>");

        var token = await _service.SendPasswordResetEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/reset-password?token=");
        capturedUrl.Should().Contain(token);
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_WithTrailingSlashInBaseUrl_ShouldBuildCorrectUrl()
    {
        _options.PasswordReset.BaseUrl = "https://myapp.com/";
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Password reset email</html>");

        await _service.SendPasswordResetEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/reset-password?token=");
        capturedUrl.Should().NotContain("//reset-password");
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_WithLeadingSlashInResetPath_ShouldBuildCorrectUrl()
    {
        _options.PasswordReset.ResetPath = "/reset-password";
        var userId = "user123";
        var email = "test@example.com";
        var cancellationToken = CancellationToken.None;
        string? capturedUrl = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Callback<string, string>((url, _) => capturedUrl = url)
            .Returns("<html>Password reset email</html>");

        await _service.SendPasswordResetEmailAsync(userId, email, cancellationToken);

        capturedUrl.Should().NotBeNull();
        capturedUrl.Should().StartWith("https://myapp.com/reset-password?token=");
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_WithoutBaseUrl_ShouldThrowInvalidOperationException()
    {
        _options.PasswordReset.BaseUrl = string.Empty;
        var userId = "user123";
        var email = "test@example.com";

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

        var act = async () => await _service.SendPasswordResetEmailAsync(userId, email);

        await act.Should().ThrowAsync<InvalidOperationException>()
            .WithMessage("*PasswordReset.BaseUrl is not configured*");
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldReturnGeneratedToken()
    {
        var userId = "user123";
        var email = "test@example.com";

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

        var token = await _service.SendPasswordResetEmailAsync(userId, email);

        token.Should().NotBeNullOrEmpty();
        token.Should().HaveLength(43); // URL-safe base64 encoded 32 bytes (without padding)
    }

    #endregion

    #region ValidateResetTokenAsync Tests

    [Fact]
    public async Task ValidateResetTokenAsync_WithValidToken_ShouldReturnUserId()
    {
        var token = "valid-token";
        var userId = "user123";
        var tokenInfo = new TokenInfo
        {
            UserId = userId,
            CreatedAt = DateTime.UtcNow.AddMinutes(-30),
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.PasswordReset, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        var result = await _service.ValidateResetTokenAsync(token);

        result.Should().Be(userId);
    }

    [Fact]
    public async Task ValidateResetTokenAsync_WithExpiredToken_ShouldReturnNull()
    {
        var token = "expired-token";
        var tokenInfo = new TokenInfo
        {
            UserId = "user123",
            CreatedAt = DateTime.UtcNow.AddHours(-2),
            ExpiresAt = DateTime.UtcNow.AddHours(-1)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.PasswordReset, It.IsAny<CancellationToken>()))
            .ReturnsAsync(tokenInfo);

        var result = await _service.ValidateResetTokenAsync(token);

        result.Should().BeNull();
    }

    [Fact]
    public async Task ValidateResetTokenAsync_WithInvalidToken_ShouldReturnNull()
    {
        var token = "invalid-token";

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.PasswordReset, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TokenInfo?)null);

        var result = await _service.ValidateResetTokenAsync(token);

        result.Should().BeNull();
    }

    [Fact]
    public async Task ValidateResetTokenAsync_WithCancellationToken_ShouldPassItToRepository()
    {
        var token = "valid-token";
        var cancellationToken = new CancellationToken();
        var tokenInfo = new TokenInfo
        {
            UserId = "user123",
            CreatedAt = DateTime.UtcNow.AddMinutes(-30),
            ExpiresAt = DateTime.UtcNow.AddMinutes(30)
        };

        _mockTokenRepository
            .Setup(r => r.ValidateTokenAsync(token, TokenType.PasswordReset, cancellationToken))
            .ReturnsAsync(tokenInfo);

        await _service.ValidateResetTokenAsync(token, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.ValidateTokenAsync(token, TokenType.PasswordReset, cancellationToken),
            Times.Once);
    }

    #endregion

    #region InvalidateResetTokenAsync Tests

    [Fact]
    public async Task InvalidateResetTokenAsync_ShouldCallRepositoryInvalidate()
    {
        var token = "token-to-invalidate";
        var cancellationToken = CancellationToken.None;

        await _service.InvalidateResetTokenAsync(token, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(token, TokenType.PasswordReset, cancellationToken),
            Times.Once);
    }

    [Fact]
    public async Task InvalidateResetTokenAsync_WithCancellationToken_ShouldPassItToRepository()
    {
        var token = "token-to-invalidate";
        var cancellationToken = new CancellationToken();

        await _service.InvalidateResetTokenAsync(token, cancellationToken);

        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(token, TokenType.PasswordReset, cancellationToken),
            Times.Once);
    }

    #endregion

    #region Token Lifetime Tests

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldUseConfiguredTokenLifetime()
    {
        _options.PasswordReset.TokenLifetime = TimeSpan.FromHours(2);
        var userId = "user123";
        var email = "test@example.com";
        var beforeSend = DateTime.UtcNow;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

        await _service.SendPasswordResetEmailAsync(userId, email);

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                It.IsAny<string>(),
                TokenType.PasswordReset,
                It.Is<DateTime>(dt => dt >= beforeSend.AddHours(2) && dt <= DateTime.UtcNow.AddHours(3)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task SendPasswordResetEmailAsync_WithDefaultOptions_ShouldUseOneHourLifetime()
    {
        var userId = "user123";
        var email = "test@example.com";
        var beforeSend = DateTime.UtcNow;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

        await _service.SendPasswordResetEmailAsync(userId, email);

        _mockTokenRepository.Verify(
            r => r.StoreTokenAsync(
                userId,
                It.IsAny<string>(),
                TokenType.PasswordReset,
                It.Is<DateTime>(dt => dt >= beforeSend.AddMinutes(59) && dt <= DateTime.UtcNow.AddHours(2)),
                It.IsAny<CancellationToken>()),
            Times.Once);
    }

    #endregion

    #region Email Template Tests

    [Fact]
    public async Task SendPasswordResetEmailAsync_ShouldCallTemplateProviderWithCorrectParameters()
    {
        var userId = "user123";
        var email = "test@example.com";
        string? capturedUrl = null;
        string? capturedEmail = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), It.IsAny<string>()))
            .Callback<string, string>((url, e) =>
            {
                capturedUrl = url;
                capturedEmail = e;
            })
            .Returns("<html>Password reset email</html>");

        var token = await _service.SendPasswordResetEmailAsync(userId, email);

        capturedEmail.Should().Be(email);
        capturedUrl.Should().Contain(token);
        capturedUrl.Should().StartWith("https://myapp.com/reset-password?token=");
    }

    #endregion

    #region Integration Flow Tests

    [Fact]
    public async Task CompletePasswordResetFlow_ShouldWorkEndToEnd()
    {
        var userId = "user123";
        var email = "test@example.com";
        string? generatedToken = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

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
            .Setup(r => r.ValidateTokenAsync(It.IsAny<string>(), TokenType.PasswordReset, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string token, TokenType type, CancellationToken ct) =>
            {
                if (token == generatedToken)
                {
                    return new TokenInfo
                    {
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow.AddMinutes(-30),
                        ExpiresAt = DateTime.UtcNow.AddMinutes(30)
                    };
                }
                return null;
            });

        var token = await _service.SendPasswordResetEmailAsync(userId, email);
        var validatedUserId = await _service.ValidateResetTokenAsync(token);
        await _service.InvalidateResetTokenAsync(token);

        validatedUserId.Should().Be(userId);
        _mockEmailSender.Verify(
            s => s.SendEmailAsync(email, It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()),
            Times.Once);
        _mockTokenRepository.Verify(
            r => r.InvalidateTokenAsync(token, TokenType.PasswordReset, It.IsAny<CancellationToken>()),
            Times.Once);
    }

    [Fact]
    public async Task ValidateResetTokenAsync_AfterTokenExpires_ShouldReturnNull()
    {
        var userId = "user123";
        var email = "test@example.com";
        string? generatedToken = null;

        _mockTemplateProvider
            .Setup(t => t.GetPasswordResetTemplate(It.IsAny<string>(), email))
            .Returns("<html>Password reset email</html>");

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
            .Setup(r => r.ValidateTokenAsync(It.IsAny<string>(), TokenType.PasswordReset, It.IsAny<CancellationToken>()))
            .ReturnsAsync((string token, TokenType type, CancellationToken ct) =>
            {
                if (token == generatedToken)
                {
                    return new TokenInfo
                    {
                        UserId = userId,
                        CreatedAt = DateTime.UtcNow.AddHours(-2),
                        ExpiresAt = DateTime.UtcNow.AddHours(-1)
                    };
                }
                return null;
            });

        var token = await _service.SendPasswordResetEmailAsync(userId, email);
        var validatedUserId = await _service.ValidateResetTokenAsync(token);

        validatedUserId.Should().BeNull();
    }

    #endregion
}
