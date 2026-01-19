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

        try
        {
            // Handle errors from OAuth provider
            if (!string.IsNullOrEmpty(error))
            {
                _logger.LogWarning("OAuth provider {Provider} returned error: {Error}, Description: {Description}",
                    provider, error, errorDescription);
                return RedirectWithError("oauth_denied", "Authentication was cancelled or denied.");
            }

            // Validate required parameters
            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                _logger.LogWarning("OAuth callback missing required parameters: code={Code}, state={State}",
                    string.IsNullOrEmpty(code) ? "missing" : "present",
                    string.IsNullOrEmpty(state) ? "missing" : "present");
                return RedirectWithError("oauth_failed", "Invalid authentication request. Please try again.");
            }

            var stateData = await _stateTokenService.ValidateAndConsumeStateTokenAsync(state, cancellationToken);

            var oauthProvider = _providerFactory.GetProvider(provider);
            var config = _oauthOptions.Providers[provider.ToLowerInvariant()];
            var redirectUri = config.RedirectUri;

            var tokenResponse = await oauthProvider.ExchangeCodeForTokenAsync(
                code, redirectUri, stateData.CodeVerifier, cancellationToken);

            var userInfo = await oauthProvider.GetUserInfoAsync(
                tokenResponse.AccessToken, cancellationToken);

            // Extract device and IP information for session tracking
            var deviceInfo = context.Request.Headers.UserAgent.ToString();
            var ipAddress = context.Connection.RemoteIpAddress?.ToString();

            var authResult = await _externalAuthService.AuthenticateWithProviderAsync(
                provider, userInfo, deviceInfo, ipAddress, cancellationToken);

            var csrfToken = _csrfService.GenerateToken();

            var returnUrl = stateData.ReturnUrl ?? "/";

            _logger.LogInformation("Successfully authenticated user via OAuth provider: {Provider}", provider);

            // Set tokens in cookies (for Hybrid/HttpOnlyCookies modes)
            if (_pawthorizeOptions.TokenDelivery != TokenDeliveryStrategy.ResponseBody)
            {
                TokenDeliveryHelper.DeliverTokens(
                    authResult,
                    context,
                    _pawthorizeOptions.TokenDelivery,
                    _pawthorizeOptions,
                    _csrfService,
                    _logger);
            }

            // Build redirect URL for frontend
            var redirectUrl = BuildFrontendRedirectUrl(authResult, returnUrl);

            _logger.LogInformation("Redirecting to frontend callback: {RedirectUrl}", redirectUrl);

            return Results.Redirect(redirectUrl);
        }
        catch (DuplicateEmailError ex)
        {
            // Don't expose that the email exists - use generic message
            _logger.LogWarning(ex, "OAuth failed: duplicate email for provider {Provider}", provider);
            return RedirectWithError("oauth_failed", "Unable to complete sign in. Try logging in with your password instead.");
        }
        catch (OAuthStateValidationError ex)
        {
            _logger.LogWarning(ex, "OAuth state validation failed for provider {Provider}", provider);
            return RedirectWithError("oauth_failed", "Authentication session expired. Please try again.");
        }
        catch (OAuthError ex)
        {
            _logger.LogWarning(ex, "OAuth error for provider {Provider}: {Message}", provider, ex.Message);
            return RedirectWithError("oauth_failed", "Authentication failed. Please try again.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during OAuth callback for provider {Provider}", provider);
            return RedirectWithError("oauth_failed", "An unexpected error occurred. Please try again.");
        }
    }

    private IResult RedirectWithError(string error, string description)
    {
        var baseUrl = _oauthOptions.FrontendCallbackUrl ?? "/";
        var separator = baseUrl.Contains('?') ? "&" : "?";
        var redirectUrl = $"{baseUrl}{separator}error={Uri.EscapeDataString(error)}&error_description={Uri.EscapeDataString(description)}";

        _logger.LogInformation("Redirecting to frontend with error: {RedirectUrl}", redirectUrl);

        return Results.Redirect(redirectUrl);
    }

    private string BuildFrontendRedirectUrl(AuthResult authResult, string returnUrl)
    {
        // Use FrontendCallbackUrl if configured, otherwise fall back to returnUrl
        var baseUrl = _oauthOptions.FrontendCallbackUrl ?? returnUrl;

        // For ResponseBody or Hybrid mode, include access token in URL for SPA consumption
        if (_pawthorizeOptions.TokenDelivery == TokenDeliveryStrategy.ResponseBody ||
            _pawthorizeOptions.TokenDelivery == TokenDeliveryStrategy.Hybrid)
        {
            var separator = baseUrl.Contains('?') ? "&" : "?";
            var redirectUrl = $"{baseUrl}{separator}accessToken={Uri.EscapeDataString(authResult.AccessToken)}";

            // Include returnUrl if FrontendCallbackUrl is used and returnUrl was provided
            if (!string.IsNullOrEmpty(_oauthOptions.FrontendCallbackUrl) &&
                !string.IsNullOrEmpty(returnUrl) && returnUrl != "/")
            {
                redirectUrl += $"&returnUrl={Uri.EscapeDataString(returnUrl)}";
            }

            return redirectUrl;
        }

        // For HttpOnlyCookies mode, just redirect (tokens are in cookies)
        return baseUrl;
    }
}
