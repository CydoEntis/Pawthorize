using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pawthorize.Abstractions;
using Pawthorize.Configuration;
using Pawthorize.Services.Models;

namespace Pawthorize.Services;

/// <summary>
/// Service for generating and validating JWT access and refresh tokens.
/// Handles token signing, expiration, and claim extraction from user data.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class JwtService<TUser> where TUser : IAuthenticatedUser
{
    private readonly JwtSettings _settings;
    private readonly ILogger<JwtService<TUser>>? _logger;

    public JwtService(IOptions<JwtSettings> settings)
        : this(settings, null)
    {
    }

    public JwtService(
        IOptions<JwtSettings> settings,
        ILogger<JwtService<TUser>>? logger)
    {
        _settings = settings.Value;
        _logger = logger;
    }

    /// <summary>
    /// Generate a JWT access token for the given user.
    /// </summary>
    public string GenerateAccessToken(TUser user)
    {
        _logger?.LogDebug("Generating access token for UserId: {UserId}", user.Id);

        try
        {
            var claims = BuildClaims(user);
            _logger?.LogDebug("Built {ClaimCount} claims for access token for UserId: {UserId}",
                claims.Count, user.Id);

            var secret = GetSecret();

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiresAt = DateTime.UtcNow.AddMinutes(_settings.AccessTokenLifetimeMinutes);
            var token = new JwtSecurityToken(
                issuer: _settings.Issuer,
                audience: _settings.Audience,
                claims: claims,
                expires: expiresAt,
                signingCredentials: credentials
            );

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            _logger?.LogInformation("Access token generated successfully for UserId: {UserId}, ExpiresAt: {ExpiresAt}",
                user.Id, expiresAt);

            return tokenString;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate access token for UserId: {UserId}", user.Id);
            throw;
        }
    }

    /// <summary>
    /// Generate a cryptographically secure refresh token.
    /// </summary>
    public string GenerateRefreshToken()
    {
        _logger?.LogDebug("Generating cryptographically secure refresh token");

        try
        {
            var randomBytes = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            var token = Convert.ToBase64String(randomBytes);

            _logger?.LogDebug("Refresh token generated successfully");

            return token;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to generate refresh token");
            throw;
        }
    }

    /// <summary>
    /// Validate and decode a JWT access token.
    /// </summary>
    public ClaimsPrincipal? ValidateToken(string token)
    {
        _logger?.LogDebug("Validating JWT access token");

        try
        {
            var secret = GetSecret();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _settings.Issuer,
                ValidAudience = _settings.Audience,
                IssuerSigningKey = key,
                ClockSkew = TimeSpan.Zero
            };

            var principal = tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            _logger?.LogInformation("JWT token validated successfully for UserId: {UserId}", userId ?? "Unknown");

            return principal;
        }
        catch (SecurityTokenExpiredException ex)
        {
            _logger?.LogWarning("Token validation failed: Token expired - {Message}", ex.Message);
            return null;
        }
        catch (SecurityTokenInvalidSignatureException ex)
        {
            _logger?.LogWarning("Token validation failed: Invalid signature - {Message}", ex.Message);
            return null;
        }
        catch (SecurityTokenException ex)
        {
            _logger?.LogWarning("Token validation failed: {Message}", ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during token validation");
            return null;
        }
    }

    /// <summary>
    /// Get the expiration time for a newly generated access token.
    /// </summary>
    public DateTime GetAccessTokenExpiration() => 
        DateTime.UtcNow.AddMinutes(_settings.AccessTokenLifetimeMinutes);

    /// <summary>
    /// Get the expiration time for a newly generated refresh token.
    /// </summary>
    /// <param name="rememberMe">Whether this is a "Remember Me" session with extended expiry.</param>
    /// <returns>The expiration DateTime for the refresh token.</returns>
    public DateTime GetRefreshTokenExpiration(bool rememberMe = false) =>
        DateTime.UtcNow.Add(_settings.GetRefreshTokenLifetime(rememberMe));

    private List<Claim> BuildClaims(TUser user)
    {
        _logger?.LogDebug("Building claims for UserId: {UserId}", user.Id);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (!string.IsNullOrEmpty(user.FirstName) || !string.IsNullOrEmpty(user.LastName))
        {
            claims.Add(new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}".Trim()));
        }

        var rolesList = user.Roles.ToList();
        if (rolesList.Count > 0)
        {
            foreach (var role in rolesList)
                claims.Add(new Claim(ClaimTypes.Role, role));
            _logger?.LogDebug("Added {RoleCount} role claims for UserId: {UserId}", rolesList.Count, user.Id);
        }

        if (user.AdditionalClaims != null && user.AdditionalClaims.Count > 0)
        {
            foreach (var (key, value) in user.AdditionalClaims)
                claims.Add(new Claim(key, value));
            _logger?.LogDebug("Added {AdditionalClaimCount} additional claims for UserId: {UserId}",
                user.AdditionalClaims.Count, user.Id);
        }

        _logger?.LogDebug("Built {TotalClaimCount} total claims for UserId: {UserId}", claims.Count, user.Id);

        return claims;
    }

    private string GetSecret()
    {
        _logger?.LogDebug("Retrieving JWT signing secret");

        if (string.IsNullOrEmpty(_settings.Secret))
        {
            _logger?.LogError("JWT Secret is not configured in settings");
            throw new InvalidOperationException(
                "JWT Secret is not configured. Set 'Jwt:Secret' in appsettings.json.");
        }

        if (_settings.Secret.Length < 32)
        {
            _logger?.LogError("JWT Secret length is insufficient: {Length} characters (minimum 32 required)",
                _settings.Secret.Length);
            throw new InvalidOperationException(
                $"JWT Secret must be at least 32 characters. Current length: {_settings.Secret.Length}");
        }

        _logger?.LogDebug("Using JWT secret from settings (length: {Length} characters)",
            _settings.Secret.Length);

        return _settings.Secret;
    }
}
