using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Models;

namespace Pawthorize.Services;

/// <summary>
/// Service for authenticating users via external OAuth providers.
/// </summary>
public class ExternalAuthenticationService<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly IExternalAuthRepository<TUser> _externalAuthRepository;
    private readonly IUserRepository<TUser> _userRepository;
    private readonly AuthenticationService<TUser> _authenticationService;
    private readonly IServiceProvider _serviceProvider;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger<ExternalAuthenticationService<TUser>> _logger;

    public ExternalAuthenticationService(
        IExternalAuthRepository<TUser> externalAuthRepository,
        IUserRepository<TUser> userRepository,
        AuthenticationService<TUser> authenticationService,
        IServiceProvider serviceProvider,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<ExternalAuthenticationService<TUser>> logger)
    {
        _externalAuthRepository = externalAuthRepository;
        _userRepository = userRepository;
        _authenticationService = authenticationService;
        _serviceProvider = serviceProvider;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Authenticates a user with an external OAuth provider.
    /// If user doesn't exist and auto-registration is enabled, creates a new account.
    /// </summary>
    public async Task<AuthResult> AuthenticateWithProviderAsync(
        string provider,
        ExternalUserInfo userInfo,
        string? deviceInfo = null,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Authenticating user with provider {Provider}, ProviderId: {ProviderId}",
            provider, userInfo.ProviderId);

        var user = await _externalAuthRepository.FindByExternalProviderAsync(
            provider, userInfo.ProviderId, cancellationToken);

        if (user == null)
        {
            if (!_oauthOptions.AllowAutoRegistration)
            {
                _logger.LogWarning("User not found and auto-registration is disabled for provider {Provider}, ProviderId: {ProviderId}",
                    provider, userInfo.ProviderId);
                throw new UserNotFoundError("No account found. Please register first or link this provider to your existing account.");
            }

            if (string.IsNullOrWhiteSpace(userInfo.Email))
            {
                _logger.LogWarning("Cannot auto-register user: email is required but not provided by {Provider}",
                    provider);
                throw new OAuthProviderError(provider, "email_required",
                    "Email is required for account creation but was not provided by the provider");
            }

            var existingUser = await _userRepository.FindByEmailAsync(userInfo.Email, cancellationToken);
            if (existingUser != null)
            {
                _logger.LogWarning("Cannot auto-register: email {Email} already exists", userInfo.Email);
                throw new DuplicateEmailError(userInfo.Email);
            }

            _logger.LogInformation("Auto-registering new user for provider {Provider}, email: {Email}",
                provider, userInfo.Email);

            user = await CreateUserFromExternalInfoAsync(userInfo, cancellationToken);

            await LinkProviderToUserInternalAsync(user.Id, provider, userInfo, cancellationToken);

            _logger.LogInformation("Successfully created and linked account for user {UserId} with provider {Provider}",
                user.Id, provider);
        }
        else
        {
            _logger.LogDebug("Found existing user {UserId} for provider {Provider}", user.Id, provider);
        }

        _authenticationService.ValidateAccountStatus(user);

        var authResult = await _authenticationService.GenerateTokensAsync(user, deviceInfo, ipAddress, cancellationToken);

        _logger.LogInformation("Successfully authenticated user {UserId} via provider {Provider}",
            user.Id, provider);

        return authResult;
    }

    /// <summary>
    /// Links an external provider to an existing authenticated user.
    /// </summary>
    public async Task LinkProviderToUserAsync(
        string userId,
        string provider,
        ExternalUserInfo userInfo,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Linking provider {Provider} to user {UserId}", provider, userId);

        var existingLinkedUser = await _externalAuthRepository.FindByExternalProviderAsync(
            provider, userInfo.ProviderId, cancellationToken);

        if (existingLinkedUser != null)
        {
            if (existingLinkedUser.Id == userId)
            {
                _logger.LogWarning("Provider {Provider} is already linked to user {UserId}",
                    provider, userId);
                throw OAuthAccountLinkingError.ProviderAlreadyLinkedToCurrentUser(provider);
            }
            else
            {
                _logger.LogWarning("Provider {Provider} is already linked to different user", provider);
                throw OAuthAccountLinkingError.ProviderAlreadyLinked(provider);
            }
        }

        await LinkProviderToUserInternalAsync(userId, provider, userInfo, cancellationToken);

        _logger.LogInformation("Successfully linked provider {Provider} to user {UserId}",
            provider, userId);
    }

    /// <summary>
    /// Unlinks an external provider from a user account.
    /// </summary>
    public async Task UnlinkProviderAsync(
        string userId,
        string provider,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Unlinking provider {Provider} from user {UserId}", provider, userId);

        var linkedProviders = await _externalAuthRepository.GetLinkedProvidersAsync(
            userId, cancellationToken);
        var linkedProvidersList = linkedProviders.ToList();

        var user = await _userRepository.FindByIdAsync(userId, cancellationToken);
        if (user == null)
        {
            throw new UserNotFoundError();
        }

        var hasPassword = !string.IsNullOrWhiteSpace(user.PasswordHash);
        var providerCount = linkedProvidersList.Count;

        if (!hasPassword && providerCount <= 1)
        {
            _logger.LogWarning("Cannot unlink last authentication method for user {UserId}", userId);
            throw OAuthAccountLinkingError.CannotUnlinkLastMethod();
        }

        await _externalAuthRepository.UnlinkExternalProviderAsync(userId, provider, cancellationToken);

        _logger.LogInformation("Successfully unlinked provider {Provider} from user {UserId}",
            provider, userId);
    }

    /// <summary>
    /// Gets all linked providers for a user.
    /// </summary>
    public async Task<IEnumerable<IExternalIdentity>> GetLinkedProvidersAsync(
        string userId,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Fetching linked providers for user {UserId}", userId);

        return await _externalAuthRepository.GetLinkedProvidersAsync(userId, cancellationToken);
    }

    private async Task<TUser> CreateUserFromExternalInfoAsync(
        ExternalUserInfo userInfo,
        CancellationToken cancellationToken)
    {
        // Try to get user factory from DI container
        // We try RegisterRequest factory first, as it's the most common
        var userFactoryType = typeof(IUserFactory<,>).MakeGenericType(typeof(TUser), typeof(DTOs.RegisterRequest));
        var userFactory = _serviceProvider.GetService(userFactoryType);

        if (userFactory == null)
        {
            throw new InvalidOperationException(
                "OAuth auto-registration requires an IUserFactory<TUser, RegisterRequest> implementation to be registered in DI. " +
                "Either register IUserFactory<TUser, RegisterRequest> or disable auto-registration in OAuth settings (set AllowAutoRegistration = false).");
        }

        // Create register request from OAuth user info
        var registerRequest = new DTOs.RegisterRequest
        {
            Email = userInfo.Email!,
            Password = string.Empty, // OAuth users don't have passwords initially
            Name = userInfo.Name
        };

        // Use dynamic to call CreateUser method
        dynamic factory = userFactory;
        var user = factory.CreateUser(registerRequest, string.Empty) as TUser;

        if (user == null)
        {
            throw new InvalidOperationException("Failed to create user from external provider info");
        }

        await _userRepository.CreateAsync(user, cancellationToken);

        _logger.LogInformation("Created new user {UserId} from external provider info", user.Id);

        return user;
    }

    private async Task LinkProviderToUserInternalAsync(
        string userId,
        string provider,
        ExternalUserInfo userInfo,
        CancellationToken cancellationToken)
    {
        var externalIdentity = new ExternalIdentity
        {
            Provider = provider,
            ProviderId = userInfo.ProviderId,
            ProviderEmail = userInfo.Email,
            ProviderUsername = userInfo.Username,
            LinkedAt = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["name"] = userInfo.Name ?? string.Empty,
                ["profilePictureUrl"] = userInfo.ProfilePictureUrl ?? string.Empty,
                ["emailVerified"] = userInfo.EmailVerified.ToString()
            }
        };

        await _externalAuthRepository.LinkExternalProviderAsync(
            userId, externalIdentity, cancellationToken);
    }
}
