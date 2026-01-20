using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Utilities;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for initiating OAuth flow.
/// Generates state token and redirects user to OAuth provider.
/// </summary>
public class OAuthInitiateHandler
{
    private readonly IOAuthProviderFactory _providerFactory;
    private readonly IStateTokenService _stateTokenService;
    private readonly OAuthOptions _oauthOptions;
    private readonly ILogger<OAuthInitiateHandler> _logger;

    public OAuthInitiateHandler(
        IOAuthProviderFactory providerFactory,
        IStateTokenService stateTokenService,
        IOptions<OAuthOptions> oauthOptions,
        ILogger<OAuthInitiateHandler> logger)
    {
        _providerFactory = providerFactory;
        _stateTokenService = stateTokenService;
        _oauthOptions = oauthOptions.Value;
        _logger = logger;
    }

    /// <summary>
    /// Handle OAuth initiation request.
    /// </summary>
    /// <param name="provider">Provider name (e.g., "google", "discord")</param>
    /// <param name="returnUrl">Optional URL to redirect to after OAuth</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        string provider,
        string? returnUrl,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Initiating OAuth flow for provider: {Provider}", provider);

        var oauthProvider = _providerFactory.GetProvider(provider);

        var config = _oauthOptions.Providers[provider.ToLowerInvariant()];
        var redirectUri = config.RedirectUri;

        string? codeVerifier = null;
        string? codeChallenge = null;

        if (_oauthOptions.UsePkce)
        {
            codeVerifier = PkceHelper.GenerateCodeVerifier();
            codeChallenge = PkceHelper.GenerateCodeChallenge(codeVerifier);
            _logger.LogDebug("Generated PKCE code verifier and challenge for OAuth flow");
        }

        var stateToken = await _stateTokenService.GenerateStateTokenAsync(
            returnUrl, codeVerifier, cancellationToken: cancellationToken);

        var authorizationUrl = await oauthProvider.GetAuthorizationUrlAsync(
            stateToken, redirectUri, codeChallenge, cancellationToken);

        _logger.LogInformation("Redirecting to OAuth provider: {Provider}, URL: {Url}",
            provider, authorizationUrl);

        return Results.Redirect(authorizationUrl);
    }
}
