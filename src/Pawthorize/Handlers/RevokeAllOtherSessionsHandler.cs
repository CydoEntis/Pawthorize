using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.Configuration;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;
using SuccessHound.AspNetExtensions;

namespace Pawthorize.AspNetCore.Handlers;

/// <summary>
/// Handler for revoking all sessions (refresh tokens) except the current one.
/// This allows users to logout all other devices while keeping the current session active.
/// </summary>
public class RevokeAllOtherSessionsHandler<TUser> where TUser : IAuthenticatedUser
{
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly PawthorizeOptions _options;
    private readonly ILogger<RevokeAllOtherSessionsHandler<TUser>> _logger;

    public RevokeAllOtherSessionsHandler(
        IRefreshTokenRepository refreshTokenRepository,
        IOptions<PawthorizeOptions> options,
        ILogger<RevokeAllOtherSessionsHandler<TUser>> logger)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Revoke all refresh tokens (sessions) except the current one for the authenticated user.
    /// </summary>
    public async Task<IResult> HandleAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("Revoke all other sessions failed: UserId claim not found in token");
            return Results.Unauthorized();
        }

        _logger.LogInformation("Revoking all other sessions for UserId: {UserId}", userId);

        try
        {
            var currentRefreshToken = ExtractRefreshToken(httpContext);

            if (string.IsNullOrEmpty(currentRefreshToken))
            {
                _logger.LogWarning("Revoke all other sessions failed: Current refresh token not found");
                throw new InvalidRefreshTokenError();
            }

            await _refreshTokenRepository.RevokeAllExceptAsync(userId, currentRefreshToken, cancellationToken);

            _logger.LogInformation("All other sessions revoked successfully for UserId: {UserId}", userId);

            var response = new
            {
                message = "All other sessions have been revoked successfully."
            };

            return response.Ok(httpContext);
        }
        catch (InvalidRefreshTokenError)
        {
            _logger.LogWarning("Revoke all other sessions failed: Invalid or missing refresh token for UserId: {UserId}", userId);
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error revoking other sessions for UserId: {UserId}", userId);
            throw;
        }
    }

    /// <summary>
    /// Extract refresh token from cookie or request.
    /// Cookie takes precedence if using HttpOnlyCookies or Hybrid strategy.
    /// </summary>
    private string? ExtractRefreshToken(HttpContext httpContext)
    {
        if (_options.TokenDelivery != TokenDeliveryStrategy.ResponseBody)
        {
            var cookieToken = httpContext.Request.Cookies["refresh_token"];
            if (!string.IsNullOrEmpty(cookieToken))
            {
                _logger.LogDebug("Refresh token extracted from cookie");
                return cookieToken;
            }
            _logger.LogDebug("No refresh token found in cookie");
        }

        _logger.LogWarning("No refresh token found for revoke all other sessions");
        return null;
    }
}
