using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Services;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for linking an OAuth provider to an existing authenticated user.
/// </summary>
public class LinkProviderHandler<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly IOAuthProviderFactory _providerFactory;
    private readonly IStateTokenService _stateTokenService;
    private readonly ExternalAuthenticationService<TUser> _externalAuthService;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger<LinkProviderHandler<TUser>> _logger;

    public LinkProviderHandler(
        IOAuthProviderFactory providerFactory,
        IStateTokenService stateTokenService,
        ExternalAuthenticationService<TUser> externalAuthService,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<LinkProviderHandler<TUser>> logger)
    {
        _providerFactory = providerFactory;
        _stateTokenService = stateTokenService;
        _externalAuthService = externalAuthService;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Handle link provider request.
    /// </summary>
    /// <param name="provider">Provider name</param>
    /// <param name="code">Authorization code</param>
    /// <param name="state">State token</param>
    /// <param name="context">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        string provider,
        string code,
        string state,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Linking provider {Provider} to authenticated user", provider);

        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Link provider attempt without authentication");
            throw new InvalidCredentialsError("You must be logged in to link a provider");
        }

        var stateData = await _stateTokenService.ValidateAndConsumeStateTokenAsync(state, cancellationToken);

        var oauthProvider = _providerFactory.GetProvider(provider);
        var config = _oauthOptions.Providers[provider.ToLowerInvariant()];
        var redirectUri = config.RedirectUri;

        var tokenResponse = await oauthProvider.ExchangeCodeForTokenAsync(
            code, redirectUri, stateData.CodeVerifier, cancellationToken);

        var userInfo = await oauthProvider.GetUserInfoAsync(
            tokenResponse.AccessToken, cancellationToken);

        await _externalAuthService.LinkProviderToUserAsync(
            userId, provider, userInfo, cancellationToken);

        _logger.LogInformation("Successfully linked provider {Provider} to user {UserId}",
            provider, userId);

        return Results.Ok(new
        {
            success = true,
            provider,
            linkedAt = DateTime.UtcNow
        });
    }
}
