using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Services;
using Pawthorize.Utilities;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for OAuth provider callback.
/// Validates state, exchanges code for token, creates or authenticates user.
/// </summary>
public class OAuthCallbackHandler<TUser> where TUser : class, IAuthenticatedUser
{
    private readonly IOAuthProviderFactory _providerFactory;
    private readonly IStateTokenService _stateTokenService;
    private readonly ExternalAuthenticationService<TUser> _externalAuthService;
    private readonly OAuthOptions _oauthOptions;
    private readonly PawthorizeOptions _pawthorizeOptions;
    private readonly CsrfTokenService _csrfService;
    private readonly ILogger<OAuthCallbackHandler<TUser>> _logger;

    public OAuthCallbackHandler(
        IOAuthProviderFactory providerFactory,
        IStateTokenService stateTokenService,
        ExternalAuthenticationService<TUser> externalAuthService,
        IOptions<OAuthOptions> oauthOptions,
        IOptions<PawthorizeOptions> pawthorizeOptions,
        CsrfTokenService csrfService,
        ILogger<OAuthCallbackHandler<TUser>> logger)
    {
        _providerFactory = providerFactory;
        _stateTokenService = stateTokenService;
        _externalAuthService = externalAuthService;
        _oauthOptions = oauthOptions.Value;
        _pawthorizeOptions = pawthorizeOptions.Value;
        _csrfService = csrfService;
        _logger = logger;
    }

    /// <summary>
    /// Handle OAuth callback from provider.
    /// </summary>
    /// <param name="provider">Provider name</param>
    /// <param name="code">Authorization code</param>
    /// <param name="state">State token</param>
    /// <param name="error">Error from provider (if any)</param>
    /// <param name="errorDescription">Error description from provider</param>
    /// <param name="context">HTTP context</param>
    /// <param name="cancellationToken">Cancellation token</param>
    public async Task<IResult> HandleAsync(
        string provider,
        string? code,
        string? state,
        string? error,
        string? errorDescription,
        HttpContext context,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("Received OAuth callback from provider: {Provider}", provider);

        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("OAuth provider {Provider} returned error: {Error}, Description: {Description}",
                provider, error, errorDescription);
            throw new OAuthProviderError(provider, error, errorDescription);
        }

        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
        {
            _logger.LogWarning("OAuth callback missing required parameters: code={Code}, state={State}",
                string.IsNullOrEmpty(code) ? "missing" : "present",
                string.IsNullOrEmpty(state) ? "missing" : "present");
            throw new OAuthStateValidationError("Invalid OAuth callback: missing code or state parameter");
        }

        var stateData = await _stateTokenService.ValidateAndConsumeStateTokenAsync(state, cancellationToken);

        var oauthProvider = _providerFactory.GetProvider(provider);
        var config = _oauthOptions.Providers[provider.ToLowerInvariant()];
        var redirectUri = config.RedirectUri;

        var tokenResponse = await oauthProvider.ExchangeCodeForTokenAsync(
            code, redirectUri, stateData.CodeVerifier, cancellationToken);

        var userInfo = await oauthProvider.GetUserInfoAsync(
            tokenResponse.AccessToken, cancellationToken);

        var authResult = await _externalAuthService.AuthenticateWithProviderAsync(
            provider, userInfo, cancellationToken);

        var csrfToken = _csrfService.GenerateToken();

        var returnUrl = stateData.ReturnUrl ?? "/";

        _logger.LogInformation("Successfully authenticated user via OAuth provider: {Provider}", provider);

        // For OAuth callback, we redirect to returnUrl after setting tokens
        if (_pawthorizeOptions.TokenDelivery == TokenDeliveryStrategy.ResponseBody)
        {
            // Return tokens in response body
            return TokenDeliveryHelper.DeliverTokens(
                authResult,
                context,
                _pawthorizeOptions.TokenDelivery,
                _pawthorizeOptions,
                _csrfService,
                _logger);
        }
        else
        {
            // Set tokens in cookies and redirect
            TokenDeliveryHelper.DeliverTokens(
                authResult,
                context,
                _pawthorizeOptions.TokenDelivery,
                _pawthorizeOptions,
                _csrfService,
                _logger);

            return Results.Redirect(returnUrl);
        }
    }
}
