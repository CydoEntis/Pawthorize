using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Pawthorize.AspNetCore.DTOs;
using Pawthorize.AspNetCore.Services;
using Pawthorize.AspNetCore.Utilities;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;

namespace Pawthorize.AspNetCore.Handlers;

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

    public RefreshHandler(
        IUserRepository<TUser> userRepository,
        IRefreshTokenRepository refreshTokenRepository,
        AuthenticationService<TUser> authService,
        IValidator<RefreshTokenRequest> validator,
        IOptions<PawthorizeOptions> options)
    {
        _userRepository = userRepository;
        _refreshTokenRepository = refreshTokenRepository;
        _authService = authService;
        _validator = validator;
        _options = options.Value;
    }

    /// <summary>
    /// Handle refresh token request.
    /// </summary>
    public async Task<IResult> HandleAsync(
        RefreshTokenRequest request,
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        await ValidationHelper.ValidateAndThrowAsync(request, _validator, cancellationToken);

        var refreshToken = ExtractRefreshToken(request, httpContext);

        var tokenInfo = await _refreshTokenRepository.ValidateAsync(refreshToken, cancellationToken);

        if (tokenInfo == null || tokenInfo.IsExpired)
        {
            throw new InvalidRefreshTokenError();
        }

        var user = await _userRepository.FindByIdAsync(tokenInfo.UserId, cancellationToken);

        if (user == null)
        {
            throw new InvalidRefreshTokenError();
        }

        _authService.ValidateAccountStatus(user);

        await _refreshTokenRepository.RevokeAsync(refreshToken, cancellationToken);

        var authResult = await _authService.GenerateTokensAsync(user, cancellationToken);

        return TokenDeliveryHelper.DeliverTokens(authResult, httpContext, _options.TokenDelivery);
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