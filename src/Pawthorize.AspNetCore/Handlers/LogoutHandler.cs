using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for user logout.
/// Revokes refresh token and clears authentication cookies.
/// </summary>
public class LogoutHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly IValidator<LogoutRequest> _validator;
    private readonly PawthorizeOptions _options;
    private readonly ILogger<LogoutHandler<TUser>> _logger;

    public LogoutHandler(
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<LogoutRequest> validator,
        IOptions<PawthorizeOptions> options,
        ILogger<LogoutHandler<TUser>> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Handle logout request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        LogoutRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Logout attempt initiated");

        try
        {
            await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken, _logger);
            _logger.LogDebug("Logout request validation passed");

            var refreshToken = ExtractRefreshToken(request, httpContext);
            _logger.LogDebug("Refresh token extracted from request");

            await _refreshTokenRepository.RevokeAsync(refreshToken, cancellationToken);
            _logger.LogDebug("Refresh token revoked successfully");

            TokenDeliveryHelper.ClearAuthCookies(httpContext, _options.TokenDelivery, _logger);
            _logger.LogDebug("Authentication cookies cleared");

            _logger.LogInformation("Logout completed successfully");

            return new { Message = "Logged out successfully" }.Ok(httpContext);
        }
        catch (InvalidRefreshTokenError)
        {
            _logger.LogWarning("Logout failed: Invalid refresh token");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during logout");
            throw;
        }
    }

    /// <summary>
    /// Extract refresh token from request body or cookie.
    /// Cookie takes precedence (if using HttpOnlyCookies or Hybrid strategy).
    /// </summary>
    private string ExtractRefreshToken(LogoutRequest request, HttpContext httpContext)
    {
        if (_options.TokenDelivery != TokenDeliveryStrategy.ResponseBody)
        {
            var cookieToken = httpContext.Request.Cookies["refresh_token"];
            if (!string.IsNullOrEmpty(cookieToken))
            {
                _logger.LogDebug("Refresh token extracted from cookie for logout");
                return cookieToken;
            }
            _logger.LogDebug("No refresh token found in cookie, checking request body");
        }

        if (!string.IsNullOrEmpty(request.RefreshToken))
        {
            _logger.LogDebug("Refresh token extracted from request body for logout");
            return request.RefreshToken;
        }

        _logger.LogWarning("No refresh token found in cookie or request body for logout");
        throw new InvalidRefreshTokenError();
    }
}