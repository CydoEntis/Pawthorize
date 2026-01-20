using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Utilities;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for initiating OAuth flow to link a provider to an existing authenticated user.
/// </summary>
public class LinkProviderHandler<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly IOAuthProviderFactory _providerFactory;
    private readonly IStateTokenService _stateTokenService;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger<LinkProviderHandler<TUser>> _logger;

    public LinkProviderHandler(
        IOAuthProviderFactory providerFactory,
        IStateTokenService stateTokenService,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<LinkProviderHandler<TUser>> logger)
    {
        _providerFactory = providerFactory;
        _stateTokenService = stateTokenService;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Handle link provider initiation request.
    /// Returns an authorization URL for the frontend to redirect to.
    /// </summary>
    /// <param name="provider">Provider name</param>
    /// <param name="returnUrl">Optional URL to redirect to after OAuth</param>
    /// <param name="context">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        string provider,
        string? returnUrl,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initiating OAuth link flow for provider: {Provider}", provider);

        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Link provider attempt without authentication");
            throw new InvalidCredentialsError("You must be logged in to link a provider");
        }

        var oauthProvider = _providerFactory.GetProvider(provider);

        var config = _oauthOptions.Providers[provider.ToLowerInvariant()];
        var redirectUri = config.RedirectUri;

        string? codeVerifier = null;
        string? codeChallenge = null;

        if (_oauthOptions.UsePkce)
        {
            codeVerifier = PkceHelper.GenerateCodeVerifier();
            codeChallenge = PkceHelper.GenerateCodeChallenge(codeVerifier);
            _logger.LogDebug("Generated PKCE code verifier and challenge for link flow");
        }

        // Generate state token with "link" action and user ID
        var stateToken = await _stateTokenService.GenerateStateTokenAsync(
            returnUrl,
            codeVerifier,
            action: "link",
            userId: userId,
            cancellationToken);

        var authorizationUrl = await oauthProvider.GetAuthorizationUrlAsync(
            stateToken, redirectUri, codeChallenge, cancellationToken);

        _logger.LogInformation("Generated link authorization URL for provider: {Provider}, UserId: {UserId}",
            provider, userId);

        return Results.Ok(new
        {
            AuthUrl = authorizationUrl
        });
    }
}
