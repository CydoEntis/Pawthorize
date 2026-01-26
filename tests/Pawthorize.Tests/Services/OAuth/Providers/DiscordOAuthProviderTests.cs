using System.Net;
using System.Text.Json;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using Pawthorize.Configuration;
using Pawthorize.Services.OAuth.Providers;
using Xunit;

namespace Pawthorize.Tests.Services.OAuth.Providers;

public class DiscordOAuthProviderTests
{
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;
    private readonly Mock<IOptions<OAuthOptions>> _mockOptions;
    private readonly Mock<ILogger<DiscordOAuthProvider>> _mockLogger;
    private readonly OAuthOptions _oauthOptions;

    public DiscordOAuthProviderTests()
    {
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        _mockOptions = new Mock<IOptions<OAuthOptions>>();
        _mockLogger = new Mock<ILogger<DiscordOAuthProvider>>();

        _oauthOptions = new OAuthOptions
        {
            Providers = new Dictionary<string, OAuthProviderConfig>
            {
                ["discord"] = new OAuthProviderConfig
                {
                    ClientId = "test-client-id",
                    ClientSecret = "test-client-secret",
                    RedirectUri = "https://localhost:5001/oauth/discord/callback",
                    RequireVerifiedEmail = false
                }
            }
        };

        _mockOptions.Setup(o => o.Value).Returns(_oauthOptions);
    }

    [Fact]
    public async Task GetUserInfoAsync_WithCompleteUserData_ShouldExtractAllFieldsWithNullStructuredNames()
    {
        var userData = new
        {
            id = "discord-user-123",
            username = "johndoe",
            discriminator = "1234",
            email = "user@discord.com",
            verified = true,
            global_name = "John Doe",
            avatar = "abc123def456"
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("discord-user-123");
        result.Email.Should().Be("user@discord.com");
        result.EmailVerified.Should().BeTrue();
        result.Name.Should().Be("John Doe");
        result.GivenName.Should().BeNull("Discord doesn't provide structured names");
        result.FamilyName.Should().BeNull("Discord doesn't provide structured names");
        result.Username.Should().Be("johndoe#1234");
        result.ProfilePictureUrl.Should().Be("https://cdn.discordapp.com/avatars/discord-user-123/abc123def456.png");
    }

    [Fact]
    public async Task GetUserInfoAsync_WithNewDiscordUsername_ShouldNotIncludeDiscriminator()
    {
        var userData = new
        {
            id = "discord-user-456",
            username = "newusername",
            discriminator = "0",
            email = "newuser@discord.com",
            verified = true,
            global_name = "New User"
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.Username.Should().Be("newusername", "new Discord usernames don't have discriminators");
        result.GivenName.Should().BeNull();
        result.FamilyName.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithoutGlobalName_ShouldUseUsernameAsName()
    {
        var userData = new
        {
            id = "discord-user-789",
            username = "olduser",
            discriminator = "5678",
            email = "old@discord.com",
            verified = true
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.Name.Should().Be("olduser#5678");
        result.GivenName.Should().BeNull();
        result.FamilyName.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithoutAvatar_ShouldHaveNullProfilePicture()
    {
        var userData = new
        {
            id = "discord-user-noavatar",
            username = "noavatar",
            discriminator = "0",
            email = "noavatar@discord.com",
            verified = true
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProfilePictureUrl.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithUnverifiedEmail_ShouldIndicateCorrectly()
    {
        var userData = new
        {
            id = "discord-user-unverified",
            username = "unverified",
            discriminator = "0",
            email = "unverified@discord.com",
            verified = false
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.EmailVerified.Should().BeFalse();
        result.GivenName.Should().BeNull();
        result.FamilyName.Should().BeNull();
    }

    [Fact]
    public void ProviderName_ShouldReturnDiscord()
    {
        var provider = new DiscordOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        provider.ProviderName.Should().Be("discord");
    }
}
