using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Internal;
using Pawthorize.Services;

namespace Pawthorize.Endpoints.OAuth;

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
    /// Generates an OAuth authorization URL for linking a provider to the authenticated user's account.
    /// </summary>
    /// <param name="provider">OAuth provider name (e.g. "google", "discord").</param>
    /// <param name="returnUrl">Optional URL to redirect to after the OAuth flow completes.</param>
    /// <param name="context">HTTP context.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <exception cref="NotAuthenticatedError">User is not authenticated.</exception>
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
            throw new NotAuthenticatedError();
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
