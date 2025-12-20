using Microsoft.Extensions.Options;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Errors;
using Pawthorize.Core.Models;
using Pawthorize.Jwt.Services;

namespace Pawthorize.AspNetCore.Services;

/// <summary>
/// Core authentication service with reusable operations.
/// Used by all auth handlers (Login, Register, OAuth, MagicLink, etc.)
/// </summary>
public class AuthenticationService<TUser> where TUser : IAuthenticatedUser
{
    private readonly JwtService<TUser> _jwtService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly PawthorizeOptions _options;

    public AuthenticationService(
        JwtService<TUser> jwtService,
        IRefreshTokenRepository refreshTokenRepository,
        IOptions<PawthorizeOptions> options)
    {
        _jwtService = jwtService;
        _refreshTokenRepository = refreshTokenRepository;
        _options = options.Value;
    }

    /// <summary>
    /// Generate access and refresh tokens for a user.
    /// Stores refresh token in database.
    /// </summary>
    public async Task<AuthResult> GenerateTokensAsync(
        TUser user,
        CancellationToken cancellationToken = default)
    {
        var accessToken = _jwtService.GenerateAccessToken(user);
        var accessTokenExpiresAt = DateTime.UtcNow.Add(_options.Jwt.AccessTokenLifetime);

        var refreshToken = _jwtService.GenerateRefreshToken();
        var refreshTokenExpiresAt = DateTime.UtcNow.Add(_options.Jwt.RefreshTokenLifetime);

        await _refreshTokenRepository.StoreAsync(
            refreshToken,
            user.Id,
            refreshTokenExpiresAt,
            cancellationToken);

        return new AuthResult
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshTokenExpiresAt = refreshTokenExpiresAt,
            TokenType = "Bearer"
        };
    }

    /// <summary>
    /// Validate user account status (locked, email verified).
    /// Throws appropriate errors if account cannot be accessed.
    /// </summary>
    public void ValidateAccountStatus(TUser user)
    {
        if (user.IsLocked)
        {
            if (user.LockedUntil == null)
            {
                throw new AccountLockedError("Account locked indefinitely", null);
            }
            else if (user.LockedUntil > DateTime.UtcNow)
            {
                throw new AccountLockedError(user.LockedUntil.Value);
            }
        }

        if (_options.RequireEmailVerification && !user.IsEmailVerified)
        {
            throw new EmailNotVerifiedError(user.Email);
        }
    }
}