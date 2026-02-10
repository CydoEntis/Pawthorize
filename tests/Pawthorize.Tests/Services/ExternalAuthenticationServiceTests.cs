using FluentAssertions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Endpoints.Register;
using Pawthorize.Errors;
using Pawthorize.Services;
using Pawthorize.Services.Models;
using Pawthorize.Services.OAuth.Models;
using Pawthorize.Tests.Helpers;
using Xunit;

namespace Pawthorize.Tests.Services;

public class ExternalAuthenticationServiceTests
{
    private readonly Mock<IExternalAuthRepository<TestUser>> _mockExternalAuthRepository;
    private readonly Mock<IUserRepository<TestUser>> _mockUserRepository;
    private readonly Mock<AuthenticationService<TestUser>> _mockAuthenticationService;
    private readonly Mock<IServiceProvider> _mockServiceProvider;
    private readonly Mock<IUserFactory<TestUser, RegisterRequest>> _mockUserFactory;
    private readonly Mock<IOptions<OAuthOptions>> _mockOptions;
    private readonly Mock<ILogger<ExternalAuthenticationService<TestUser>>> _mockLogger;
    private readonly ExternalAuthenticationService<TestUser> _service;
    private readonly OAuthOptions _oauthOptions;

    public ExternalAuthenticationServiceTests()
    {
        _mockExternalAuthRepository = new Mock<IExternalAuthRepository<TestUser>>();
        _mockUserRepository = new Mock<IUserRepository<TestUser>>();

        // Create proper mocks for AuthenticationService dependencies
        var mockJwtService = new Mock<JwtService<TestUser>>(
            MockBehavior.Loose,
            Mock.Of<IOptions<JwtSettings>>(),
            null!
        );
        var mockRefreshTokenRepository = new Mock<IRefreshTokenRepository>();
        var mockPawthorizeOptions = new Mock<IOptions<PawthorizeOptions>>();
        mockPawthorizeOptions.Setup(o => o.Value).Returns(new PawthorizeOptions());
        var mockAuthLogger = new Mock<ILogger<AuthenticationService<TestUser>>>();

        _mockAuthenticationService = new Mock<AuthenticationService<TestUser>>(
            mockJwtService.Object,
            mockRefreshTokenRepository.Object,
            mockPawthorizeOptions.Object,
            mockAuthLogger.Object
        );

        _mockServiceProvider = new Mock<IServiceProvider>();
        _mockUserFactory = new Mock<IUserFactory<TestUser, RegisterRequest>>();
        _mockOptions = new Mock<IOptions<OAuthOptions>>();
        _mockLogger = new Mock<ILogger<ExternalAuthenticationService<TestUser>>>();

        _oauthOptions = new OAuthOptions
        {
            AllowAutoRegistration = true
        };

        _mockOptions.Setup(o => o.Value).Returns(_oauthOptions);

        _service = new ExternalAuthenticationService<TestUser>(
            _mockExternalAuthRepository.Object,
            _mockUserRepository.Object,
            _mockAuthenticationService.Object,
            _mockServiceProvider.Object,
            _mockOptions.Object,
            _mockLogger.Object
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithStructuredNames_ShouldCreateUserWithFirstNameLastName()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "google-123",
            Email = "user@gmail.com",
            EmailVerified = true,
            Name = "John Doe",
            GivenName = "John",
            FamilyName = "Doe",
            Username = null,
            ProfilePictureUrl = "https://example.com/photo.jpg"
        };

        var createdUser = new TestUser
        {
            Id = "user123",
            Email = "user@gmail.com",
            FirstName = "John",
            LastName = "Doe",
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("google", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(userInfo.Email!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockServiceProvider
            .Setup(sp => sp.GetService(It.IsAny<Type>()))
            .Returns(_mockUserFactory.Object);

        _mockUserFactory
            .Setup(f => f.CreateUser(It.IsAny<RegisterRequest>(), string.Empty))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        // Since provider has EmailVerified = true, user should be auto-verified
        _mockUserRepository
            .Setup(r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(createdUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("google", userInfo);

        result.Should().NotBeNull();
        _mockUserFactory.Verify(
            f => f.CreateUser(
                It.Is<RegisterRequest>(r =>
                    r.Email == "user@gmail.com" &&
                    r.FirstName == "John" &&
                    r.LastName == "Doe"),
                string.Empty
            ),
            Times.Once
        );

        // Verify that UpdateAsync was called to set IsEmailVerified = true
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithFullNameOnly_ShouldSplitName()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "discord-456",
            Email = "user@discord.com",
            EmailVerified = true,
            Name = "Jane Smith",
            GivenName = null,
            FamilyName = null,
            Username = "janesmith#1234",
            ProfilePictureUrl = null
        };

        var createdUser = new TestUser
        {
            Id = "user456",
            Email = "user@discord.com",
            FirstName = "Jane",
            LastName = "Smith",
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("discord", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(userInfo.Email!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockServiceProvider
            .Setup(sp => sp.GetService(It.IsAny<Type>()))
            .Returns(_mockUserFactory.Object);

        _mockUserFactory
            .Setup(f => f.CreateUser(It.IsAny<RegisterRequest>(), string.Empty))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        // Since provider has EmailVerified = true, user should be auto-verified
        _mockUserRepository
            .Setup(r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(createdUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("discord", userInfo);

        result.Should().NotBeNull();
        _mockUserFactory.Verify(
            f => f.CreateUser(
                It.Is<RegisterRequest>(r =>
                    r.Email == "user@discord.com" &&
                    r.FirstName == "Jane" &&
                    r.LastName == "Smith"),
                string.Empty
            ),
            Times.Once
        );

        // Verify that UpdateAsync was called to set IsEmailVerified = true
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithSingleName_ShouldSetFirstNameOnly()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "discord-789",
            Email = "madonna@discord.com",
            EmailVerified = true,
            Name = "Madonna",
            GivenName = null,
            FamilyName = null,
            Username = "madonna#5678",
            ProfilePictureUrl = null
        };

        var createdUser = new TestUser
        {
            Id = "user789",
            Email = "madonna@discord.com",
            FirstName = "Madonna",
            LastName = string.Empty,
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("discord", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(userInfo.Email!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockServiceProvider
            .Setup(sp => sp.GetService(It.IsAny<Type>()))
            .Returns(_mockUserFactory.Object);

        _mockUserFactory
            .Setup(f => f.CreateUser(It.IsAny<RegisterRequest>(), string.Empty))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        // Since provider has EmailVerified = true, user should be auto-verified
        _mockUserRepository
            .Setup(r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(createdUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("discord", userInfo);

        result.Should().NotBeNull();
        _mockUserFactory.Verify(
            f => f.CreateUser(
                It.Is<RegisterRequest>(r =>
                    r.Email == "madonna@discord.com" &&
                    r.FirstName == "Madonna" &&
                    r.LastName == string.Empty),
                string.Empty
            ),
            Times.Once
        );

        // Verify that UpdateAsync was called to set IsEmailVerified = true
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithNoNames_ShouldSetEmptyStrings()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "provider-noname",
            Email = "noname@example.com",
            EmailVerified = true,
            Name = null,
            GivenName = null,
            FamilyName = null,
            Username = null,
            ProfilePictureUrl = null
        };

        var createdUser = new TestUser
        {
            Id = "user-noname",
            Email = "noname@example.com",
            FirstName = string.Empty,
            LastName = string.Empty,
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("someprovider", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(userInfo.Email!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockServiceProvider
            .Setup(sp => sp.GetService(It.IsAny<Type>()))
            .Returns(_mockUserFactory.Object);

        _mockUserFactory
            .Setup(f => f.CreateUser(It.IsAny<RegisterRequest>(), string.Empty))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        // Since provider has EmailVerified = true, user should be auto-verified
        _mockUserRepository
            .Setup(r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(createdUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("someprovider", userInfo);

        result.Should().NotBeNull();
        _mockUserFactory.Verify(
            f => f.CreateUser(
                It.Is<RegisterRequest>(r =>
                    r.Email == "noname@example.com" &&
                    r.FirstName == string.Empty &&
                    r.LastName == string.Empty),
                string.Empty
            ),
            Times.Once
        );

        // Verify that UpdateAsync was called to set IsEmailVerified = true
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.Is<TestUser>(u => u.IsEmailVerified), It.IsAny<CancellationToken>()),
            Times.Once
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithUnverifiedEmail_ShouldNotAutoVerify()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "unverified-123",
            Email = "unverified@example.com",
            EmailVerified = false,  // Provider did NOT verify email
            Name = "Unverified User",
            GivenName = "Unverified",
            FamilyName = "User"
        };

        var createdUser = new TestUser
        {
            Id = "user-unverified",
            Email = "unverified@example.com",
            FirstName = "Unverified",
            LastName = "User",
            IsEmailVerified = false
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("someprovider", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockUserRepository
            .Setup(r => r.FindByEmailAsync(userInfo.Email!, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        _mockServiceProvider
            .Setup(sp => sp.GetService(It.IsAny<Type>()))
            .Returns(_mockUserFactory.Object);

        _mockUserFactory
            .Setup(f => f.CreateUser(It.IsAny<RegisterRequest>(), string.Empty))
            .Returns(createdUser);

        _mockUserRepository
            .Setup(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(createdUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(createdUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("someprovider", userInfo);

        result.Should().NotBeNull();

        // Verify that UpdateAsync was NOT called since email was not verified by provider
        _mockUserRepository.Verify(
            r => r.UpdateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()),
            Times.Never
        );
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithExistingUser_ShouldNotCreateNew()
    {
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "existing-123",
            Email = "existing@example.com",
            EmailVerified = true,
            Name = "Existing User",
            GivenName = "Existing",
            FamilyName = "User"
        };

        var existingUser = new TestUser
        {
            Id = "existing-user",
            Email = "existing@example.com",
            FirstName = "Existing",
            LastName = "User",
            IsEmailVerified = true
        };

        var authResult = new AuthResult
        {
            AccessToken = "access_token",
            RefreshToken = "refresh_token",
            AccessTokenExpiresAt = DateTime.UtcNow.AddMinutes(15),
            RefreshTokenExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("google", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(existingUser);

        _mockAuthenticationService
            .Setup(s => s.GenerateTokensAsync(existingUser, false, null, null, It.IsAny<CancellationToken>()))
            .ReturnsAsync(authResult);

        var result = await _service.AuthenticateWithProviderAsync("google", userInfo);

        result.Should().NotBeNull();
        _mockUserRepository.Verify(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task AuthenticateWithProviderAsync_WithAutoRegistrationDisabled_ShouldThrowError()
    {
        _oauthOptions.AllowAutoRegistration = false;

        var userInfo = new ExternalUserInfo
        {
            ProviderId = "new-user-123",
            Email = "new@example.com",
            EmailVerified = true,
            Name = "New User",
            GivenName = "New",
            FamilyName = "User"
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("google", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        Func<Task> act = async () => await _service.AuthenticateWithProviderAsync("google", userInfo);

        await act.Should().ThrowAsync<UserNotFoundError>();
        _mockUserRepository.Verify(r => r.CreateAsync(It.IsAny<TestUser>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task LinkProviderToUserAsync_ShouldStoreStructuredNames()
    {
        var userId = "user123";
        var userInfo = new ExternalUserInfo
        {
            ProviderId = "google-link-123",
            Email = "link@gmail.com",
            EmailVerified = true,
            Name = "Link User",
            GivenName = "Link",
            FamilyName = "User",
            ProfilePictureUrl = "https://example.com/photo.jpg"
        };

        _mockExternalAuthRepository
            .Setup(r => r.FindByExternalProviderAsync("google", userInfo.ProviderId, It.IsAny<CancellationToken>()))
            .ReturnsAsync((TestUser?)null);

        await _service.LinkProviderToUserAsync(userId, "google", userInfo);

        _mockExternalAuthRepository.Verify(
            r => r.LinkExternalProviderAsync(
                userId,
                It.Is<IExternalIdentity>(ei =>
                    ei.Provider == "google" &&
                    ei.ProviderId == "google-link-123" &&
                    ei.Metadata!["givenName"] == "Link" &&
                    ei.Metadata["familyName"] == "User"),
                It.IsAny<CancellationToken>()
            ),
            Times.Once
        );
    }
}
