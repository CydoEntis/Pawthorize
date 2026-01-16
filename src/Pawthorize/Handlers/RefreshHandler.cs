using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.DTOs;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Services;
using Pawthorize.Utilities;

namespace Pawthorize.Handlers;

/// <summary>
/// Handler for refreshing access tokens.
/// Validates refresh token and issues new access token (and optionally rotates refresh token).
/// </summary>
public class RefreshHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IUserRepository<TUser> _userRepository;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly AuthenticationService<TUser> _authService;
    private readonly IValidator<RefreshTokenRequest> _validator;
    private readonly PawthorizeOptions _options;
    private readonly CsrfTokenService _csrfService;
    private readonly ILogger<RefreshHandler<TUser>> _logger;

    public RefreshHandler(
        IUserRepository<TUser> userRepository,
        IRefreshTokenRepository refreshTokenRepository,
        AuthenticationService<TUser> authService,
        IValidator<RefreshTokenRequest> validator,
        IOptions<PawthorizeOptions> options,
        CsrfTokenService csrfService,
        ILogger<RefreshHandler<TUser>> logger)
    {
        _userRepository = userRepository;
        _refreshTokenRepository = refreshTokenRepository;
        _authService = authService;
        _validator = validator;
        _options = options.Value;
        _csrfService = csrfService;
        _logger = logger;
    }

    /// <summary>
    /// Handle refresh token request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        RefreshTokenRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Token refresh attempt initiated");

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Refresh token request validation passed");

            var refreshToken = ExtractRefreshToken(request, httpContext);
            _logger.LogDebug("Refresh token extracted from request");

            var refreshTokenHash = TokenHasher.HashToken(refreshToken);
            var tokenInfo = await _refreshTokenRepository.ValidateAsync(refreshTokenHash, cancellationToken);

            if (tokenInfo == null)
            {
                _logger.LogWarning("Token refresh failed: Invalid or non-existent refresh token");
                throw new InvalidRefreshTokenError(
                    "Refresh token not found or has been revoked",
                    _options.TokenDelivery.ToString());
            }

            if (tokenInfo.IsExpired)
            {
                _logger.LogWarning("Token refresh failed: Refresh token expired for UserId: {UserId}",
                    tokenInfo.UserId);
                throw new InvalidRefreshTokenError(
                    $"Refresh token expired on {tokenInfo.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC",
                    _options.TokenDelivery.ToString());
            }

            _logger.LogDebug("Refresh token validated successfully for UserId: {UserId}", tokenInfo.UserId);

            var user = await _userRepository.FindByIdAsync(tokenInfo.UserId, cancellationToken);

            if (user == null)
            {
                _logger.LogError("Token refresh failed: User not found for UserId: {UserId}", tokenInfo.UserId);
                throw new InvalidRefreshTokenError(
                    $"User not found for token. UserId: {tokenInfo.UserId}",
                    _options.TokenDelivery.ToString());
            }

            _logger.LogDebug("User found for refresh token, UserId: {UserId}", user.Id);

            _authService.ValidateAccountStatus(user);
            _logger.LogDebug("Account status validation passed for UserId: {UserId}", user.Id);

            // Preserve the "Remember Me" setting from the original session
            var rememberMe = tokenInfo.IsRememberedSession;
            _logger.LogDebug("Preserving RememberMe setting from original session: {RememberMe}, UserId: {UserId}", rememberMe, user.Id);

            // Update last activity time for this session before revoking
            await _refreshTokenRepository.UpdateLastActivityAsync(refreshTokenHash, DateTime.UtcNow, cancellationToken);
            _logger.LogDebug("Updated last activity time for session, UserId: {UserId}", user.Id);

            await _refreshTokenRepository.RevokeAsync(refreshTokenHash, cancellationToken);
            _logger.LogDebug("Old refresh token revoked for UserId: {UserId}", user.Id);

            // Extract device and IP information for the new session
            var deviceInfo = httpContext.Request.Headers.UserAgent.ToString();
            var ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();

            var authResult = await _authService.GenerateTokensAsync(user, rememberMe, deviceInfo, ipAddress, cancellationToken);
            _logger.LogDebug("New tokens generated successfully for UserId: {UserId}, RememberMe: {RememberMe}", user.Id, rememberMe);

            var result = TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery, _options, _csrfService, _logger);

            _logger.LogInformation("Token refresh completed successfully for UserId: {UserId}", user.Id);

            return result;
        }
        catch (InvalidRefreshTokenError)
        {
            _logger.LogError("Token refresh failed: Invalid refresh token");
            throw;
        }
        catch (EmailNotVerifiedError)
        {
            _logger.LogWarning("Token refresh failed: Email not verified");
            throw;
        }
        catch (AccountLockedError)
        {
            _logger.LogWarning("Token refresh failed: Account locked");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token refresh");
            throw;
        }
    }

    /// <summary>
    /// Extract refresh token from request body or cookie.
    /// Cookie takes precedence (if using HttpOnlyCookies or Hybrid strategy).
    /// </summary>
    private string ExtractRefreshToken(RefreshTokenRequest request, HttpContext httpContext)
    {
        if (_options.TokenDelivery != TokenDeliveryStrategy.ResponseBody)
        {
            var cookieToken = httpContext.Request.Cookies["refresh_token"];
            if (!string.IsNullOrEmpty(cookieToken))
            {
                _logger.LogDebug("Refresh token extracted from cookie");
                return cookieToken;
            }
            _logger.LogDebug("No refresh token found in cookie, checking request body");
        }

        if (!string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogDebug("Refresh token extracted from request body");
            return request.RefreshToken;
        }

        _logger.LogWarning("No refresh token found in cookie or request body");
        throw new InvalidRefreshTokenError(
            "Refresh token not provided in request",
            _options.TokenDelivery.ToString());
    }
}