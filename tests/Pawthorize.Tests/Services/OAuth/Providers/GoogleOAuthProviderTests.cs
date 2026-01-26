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

public class GoogleOAuthProviderTests
{
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;
    private readonly Mock<IOptions<OAuthOptions>> _mockOptions;
    private readonly Mock<ILogger<GoogleOAuthProvider>> _mockLogger;
    private readonly OAuthOptions _oauthOptions;

    public GoogleOAuthProviderTests()
    {
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
        _mockOptions = new Mock<IOptions<OAuthOptions>>();
        _mockLogger = new Mock<ILogger<GoogleOAuthProvider>>();

        _oauthOptions = new OAuthOptions
        {
            Providers = new Dictionary<string, OAuthProviderConfig>
            {
                ["google"] = new OAuthProviderConfig
                {
                    ClientId = "test-client-id",
                    ClientSecret = "test-client-secret",
                    RedirectUri = "https://localhost:5001/oauth/google/callback",
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
            id = "google-user-123",
            email = "user@gmail.com",
            verified_email = true,
            name = "John Doe",
            given_name = "John",
            family_name = "Doe",
            picture = "https://example.com/photo.jpg"
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

        var provider = new GoogleOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("google-user-123");
        result.Email.Should().Be("user@gmail.com");
        result.EmailVerified.Should().BeTrue();
        result.Name.Should().Be("John Doe");
        result.GivenName.Should().Be("John");
        result.FamilyName.Should().Be("Doe");
        result.ProfilePictureUrl.Should().Be("https://example.com/photo.jpg");
        result.Username.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithUnverifiedEmail_ShouldExtractCorrectly()
    {
        var userData = new
        {
            id = "google-user-456",
            email = "unverified@gmail.com",
            verified_email = false,
            name = "Jane Smith",
            given_name = "Jane",
            family_name = "Smith"
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

        var provider = new GoogleOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.EmailVerified.Should().BeFalse();
        result.GivenName.Should().Be("Jane");
        result.FamilyName.Should().Be("Smith");
    }

    [Fact]
    public async Task GetUserInfoAsync_WithMissingOptionalFields_ShouldHandleGracefully()
    {
        var userData = new
        {
            id = "google-user-789",
            email = "minimal@gmail.com",
            verified_email = true
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

        var provider = new GoogleOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.ProviderId.Should().Be("google-user-789");
        result.Email.Should().Be("minimal@gmail.com");
        result.Name.Should().BeNull();
        result.GivenName.Should().BeNull();
        result.FamilyName.Should().BeNull();
        result.ProfilePictureUrl.Should().BeNull();
    }

    [Fact]
    public async Task GetUserInfoAsync_WithOnlyGivenName_ShouldExtractCorrectly()
    {
        var userData = new
        {
            id = "google-user-single",
            email = "single@gmail.com",
            verified_email = true,
            given_name = "Madonna",
            name = "Madonna"
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

        var provider = new GoogleOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        var result = await provider.GetUserInfoAsync("test-access-token");

        result.Should().NotBeNull();
        result.GivenName.Should().Be("Madonna");
        result.FamilyName.Should().BeNull();
    }

    [Fact]
    public void ProviderName_ShouldReturnGoogle()
    {
        var provider = new GoogleOAuthProvider(_mockHttpClientFactory.Object, _mockOptions.Object, _mockLogger.Object);

        provider.ProviderName.Should().Be("google");
    }
}
