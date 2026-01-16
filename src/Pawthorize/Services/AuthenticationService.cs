using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pawthorize.Abstractions;
using Pawthorize.Errors;
using Pawthorize.Models;
using Pawthorize.Utilities;

namespace Pawthorize.Services;

/// <summary>
/// Core authentication service with reusable operations.
/// Used by all auth handlers (Login, Register, OAuth, MagicLink, etc.)
/// </summary>
public class AuthenticationService<TUser> where TUser : IAuthenticatedUser
{
    private readonly JwtService<TUser> _jwtService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly PawthorizeOptions _options;
    private readonly ILogger<AuthenticationService<TUser>> _logger;

    public AuthenticationService(
        JwtService<TUser> jwtService,
        IRefreshTokenRepository refreshTokenRepository,
        IOptions<PawthorizeOptions> options,
        ILogger<AuthenticationService<TUser>> logger)
    {
        _jwtService = jwtService;
        _refreshTokenRepository = refreshTokenRepository;
        _options = options.Value;
        _logger = logger;
    }

    /// <summary>
    /// Generate access and refresh tokens for a user.
    /// Stores refresh token in database with session metadata.
    /// </summary>
    /// <param name="user">The user to generate tokens for.</param>
    /// <param name="rememberMe">Whether to create a long-lived "Remember Me" session.</param>
    /// <param name="deviceInfo">Optional device/browser information (User-Agent).</param>
    /// <param name="ipAddress">Optional IP address of the client.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Authentication result containing tokens and expiry information.</returns>
    public virtual async Task<AuthResult> GenerateTokensAsync(
        TUser user,
        bool rememberMe = false,
        string? deviceInfo = null,
        string? ipAddress = null,
        CancellationToken cancellationToken = default)
    {
        _logger.LogDebug("Generating tokens for UserId: {UserId}, RememberMe: {RememberMe}", user.Id, rememberMe);

        try
        {
            var accessToken = _jwtService.GenerateAccessToken(user);
            var accessTokenExpiresAt = DateTime.UtcNow.Add(_options.Jwt.AccessTokenLifetime);
            _logger.LogDebug("Access token generated for UserId: {UserId}, ExpiresAt: {ExpiresAt}",
                user.Id, accessTokenExpiresAt);

            var refreshToken = _jwtService.GenerateRefreshToken();
            var refreshTokenHash = TokenHasher.HashToken(refreshToken);
            var refreshTokenLifetime = _options.Jwt.GetRefreshTokenLifetime(rememberMe);
            var refreshTokenExpiresAt = DateTime.UtcNow.Add(refreshTokenLifetime);
            _logger.LogDebug("Refresh token generated for UserId: {UserId}, ExpiresAt: {ExpiresAt}, RememberMe: {RememberMe}",
                user.Id, refreshTokenExpiresAt, rememberMe);

            await _refreshTokenRepository.StoreAsync(
                refreshTokenHash,
                user.Id,
                refreshTokenExpiresAt,
                deviceInfo,
                ipAddress,
                rememberMe,
                cancellationToken);
            _logger.LogDebug("Refresh token stored in repository for UserId: {UserId} with DeviceInfo: {DeviceInfo}, IpAddress: {IpAddress}, RememberMe: {RememberMe}",
                user.Id, deviceInfo ?? "N/A", ipAddress ?? "N/A", rememberMe);

            _logger.LogInformation("Token pair generated successfully for UserId: {UserId}, RememberMe: {RememberMe}", user.Id, rememberMe);

            return new AuthResult
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                AccessTokenExpiresAt = accessTokenExpiresAt,
                RefreshTokenExpiresAt = refreshTokenExpiresAt,
                TokenType = "Bearer",
                IsRememberedSession = rememberMe
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to generate tokens for UserId: {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Validate user account status (locked, email verified).
    /// Throws appropriate errors if account cannot be accessed.
    /// </summary>
    public virtual void ValidateAccountStatus(TUser user)
    {
        _logger.LogDebug("Validating account status for UserId: {UserId}", user.Id);

        if (user.IsLocked)
        {
            if (user.LockedUntil == null)
            {
                _logger.LogWarning("Account validation failed: Account locked indefinitely for UserId: {UserId}",
                    user.Id);
                throw new AccountLockedError("Account locked indefinitely", null);
            }
            else if (user.LockedUntil > DateTime.UtcNow)
            {
                _logger.LogWarning("Account validation failed: Account locked until {LockedUntil} for UserId: {UserId}",
                    user.LockedUntil.Value, user.Id);
                throw new AccountLockedError(user.LockedUntil.Value);
            }
            else
            {
                _logger.LogDebug("Account lock expired for UserId: {UserId}, allowing access", user.Id);
            }
        }

        if (_options.RequireEmailVerification && !user.IsEmailVerified)
        {
            _logger.LogWarning("Account validation failed: Email not verified for UserId: {UserId}, Email: {Email}",
                user.Id, user.Email);
            throw new EmailNotVerifiedError(user.Email);
        }

        _logger.LogDebug("Account status validation passed for UserId: {UserId}", user.Id);
    }
}