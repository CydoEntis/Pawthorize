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

public class GitHubOAuthProviderTests
{
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;
    private readonly Mock<IOptions<OAuthOptions>> _mockOptions;
    private readonly Mock<ILogger<GitHubOAuthProvider>> _mockLogger;
    private readonly OAuthOptions _oauthOptions;

    public GitHubOAuthProviderTests()
    {
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        _mockOptions = new Mock<IOptions<OAuthOptions>>();
        _mockLogger = new Mock<ILogger<GitHubOAuthProvider>>();

        _oauthOptions = new OAuthOptions
        {
            Providers = new Dictionary<string, OAuthProviderConfig>
            {
                ["github"] = new OAuthProviderConfig
                {
                    ClientId = "test-client-id",
                    ClientSecret = "test-client-secret",
                    RedirectUri = "https://localhost:5001/oauth/github/callback",
                    RequireVerifiedEmail = false
                }
            }
        };

        _mockOptions.Setup(o => o.Value).Returns(_oauthOptions);
    }

    [Fact]
    public async Task GetUserInfoAsync_WithCompleteUserData_ShouldExtractAllFields()
    {
        var userData = new
        {
            id = 12345678,
            login = "octocat",
            email = "octocat@github.com",
            name = "The Octocat",
            avatar_url = "https://avatars.githubusercontent.com/u/12345678"
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

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("12345678");
        result.Email.Should().Be("octocat@github.com");
        result.EmailVerified.Should().BeTrue(); // Email in user response is considered verified
        result.Name.Should().Be("The Octocat");
        result.Username.Should().Be("octocat");
        result.ProfilePictureUrl.Should().Be("https://avatars.githubusercontent.com/u/12345678");
        result.GivenName.Should().BeNull(); // GitHub doesn't provide structured names
        result.FamilyName.Should().BeNull(); // GitHub doesn't provide structured names
    }

    [Fact]
    public async Task GetUserInfoAsync_WithoutEmail_ShouldFetchFromEmailsEndpoint()
    {
        var userData = new
        {
            id = 87654321,
            login = "developer",
            name = "Jane Developer",
            avatar_url = "https://avatars.githubusercontent.com/u/87654321"
        };

        var emailsData = new[]
        {
            new
            {
                email = "jane@example.com",
                primary = true,
                verified = true,
                visibility = "public"
            }
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user") && !req.RequestUri.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(emailsData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("87654321");
        result.Email.Should().Be("jane@example.com");
        result.EmailVerified.Should().BeTrue();
        result.Name.Should().Be("Jane Developer");
        result.Username.Should().Be("developer");
    }

    [Fact]
    public async Task GetUserInfoAsync_WithMultipleEmails_ShouldSelectPrimaryEmail()
    {
        var userData = new
        {
            id = 11111111,
            login = "multiemailuser",
            name = "Multi Email User"
        };

        var emailsData = new[]
        {
            new
            {
                email = "secondary@example.com",
                primary = false,
                verified = true,
                visibility = "private"
            },
            new
            {
                email = "primary@example.com",
                primary = true,
                verified = true,
                visibility = "public"
            },
            new
            {
                email = "unverified@example.com",
                primary = false,
                verified = false,
                visibility = "private"
            }
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user") && !req.RequestUri.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(emailsData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.Email.Should().Be("primary@example.com");
        result.EmailVerified.Should().BeTrue();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithoutPrimaryEmail_ShouldSelectFirstVerifiedEmail()
    {
        var userData = new
        {
            id = 22222222,
            login = "noprimaryuser"
        };

        var emailsData = new[]
        {
            new
            {
                email = "unverified@example.com",
                primary = false,
                verified = false,
                visibility = "private"
            },
            new
            {
                email = "verified@example.com",
                primary = false,
                verified = true,
                visibility = "public"
            }
        };

        var httpMessageHandler = new Mock<HttpMessageHandler>();
        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user") && !req.RequestUri.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(userData))
            });

        httpMessageHandler.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.RequestUri!.ToString().Contains("/user/emails")),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(emailsData))
            });

        var httpClient = new HttpClient(httpMessageHandler.Object);
        _mockHttpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.Email.Should().Be("verified@example.com");
        result.EmailVerified.Should().BeTrue();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithMissingOptionalFields_ShouldHandleGracefully()
    {
        var userData = new
        {
            id = 99999999,
            login = "minimaluser",
            email = "minimal@github.com"
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

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("99999999");
        result.Email.Should().Be("minimal@github.com");
        result.Username.Should().Be("minimaluser");
        result.Name.Should().Be("minimaluser"); // Falls back to username when name is null
        result.ProfilePictureUrl.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithNoNameButUsername_ShouldUseUsernameAsName()
    {
        var userData = new
        {
            id = 55555555,
            login = "coolcoder",
            email = "cool@github.com"
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

        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.Name.Should().Be("coolcoder");
        result.Username.Should().Be("coolcoder");
    }

    [Fact]
    public void ProviderName_ShouldReturnGitHub()
    {
        var provider = new GitHubOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        provider.ProviderName.Should().Be("github");
    }
}
