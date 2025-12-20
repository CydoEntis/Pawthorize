using FluentValidation;
using Microsoft.AspNetCore.Http;
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

    public LogoutHandler(
        IRefreshTokenRepository refreshTokenRepository,
        IValidator<LogoutRequest> validator,
        IOptions<PawthorizeOptions> options)
    {
        _refreshTokenRepository = refreshTokenRepository;
        _validator = validator;
        _options = options.Value;
    }

    /// <summary>
    /// Handle logout request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        LogoutRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken);

        var refreshToken = ExtractRefreshToken(request, httpContext);

        await _refreshTokenRepository.RevokeAsync(refreshToken, cancellationToken);

        TokenDeliveryHelper.ClearAuthCookies(httpContext, _options.TokenDelivery);

        return new { Message = "Logged out successfully" }.Ok();
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
                return cookieToken;
            }
        }

        if (!string.IsNullOrEmpty(request.RefreshToken))
        {
            return request.RefreshToken;
        }

        throw new InvalidRefreshTokenError();
    }
}