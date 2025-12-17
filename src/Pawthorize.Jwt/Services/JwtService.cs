using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Pawthorize.Core.Abstractions;
using Pawthorize.Core.Models;

namespace Pawthorize.Jwt.Services;

/// <summary>
/// Service for generating and validating JWT tokens.
/// Supports both single-tenant (default) and multi-tenant modes.
/// </summary>
/// <typeparam name="TUser">User type implementing IAuthenticatedUser</typeparam>
public class JwtService<TUser> where TUser : IAuthenticatedUser
{
    private readonly JwtSettings _settings;
    private readonly ITenantProvider? _tenantProvider;

    public JwtService(IOptions<JwtSettings> settings)
        : this(settings, null)
    {
    }

    public JwtService(
        IOptions<JwtSettings> settings,
        ITenantProvider? tenantProvider)
    {
        _settings = settings.Value;
        _tenantProvider = tenantProvider;
    }

    /// <summary>
    /// Generate a JWT access token for the given user.
    /// </summary>
    public string GenerateAccessToken(TUser user)
    {
        var claims = BuildClaims(user);
        var secret = GetSecret();
        
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _settings.Issuer,
            audience: _settings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(_settings.AccessTokenLifetimeMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Generate a cryptographically secure refresh token.
    /// </summary>
    public string GenerateRefreshToken()
    {
        var randomBytes = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return Convert.ToBase64String(randomBytes);
    }

    /// <summary>
    /// Validate and decode a JWT access token.
    /// </summary>
    public ClaimsPrincipal? ValidateToken(string token)
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

        try
        {
            var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return principal;
        }
        catch
        {
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
    public DateTime GetRefreshTokenExpiration() => 
        DateTime.UtcNow.AddDays(_settings.RefreshTokenLifetimeDays);

    private List<Claim> BuildClaims(TUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        if (!string.IsNullOrEmpty(user.Name))
            claims.Add(new Claim(ClaimTypes.Name, user.Name));

        foreach (var role in user.Roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        if (user.AdditionalClaims != null)
        {
            foreach (var (key, value) in user.AdditionalClaims)
                claims.Add(new Claim(key, value));
        }

        if (_tenantProvider != null)
        {
            var tenantId = _tenantProvider.GetCurrentTenantId();
            if (!string.IsNullOrEmpty(tenantId))
                claims.Add(new Claim("tenant_id", tenantId));
        }

        return claims;
    }

    private string GetSecret()
    {
        if (_tenantProvider != null)
        {
            var tenantSecret = _tenantProvider.GetTenantSecret();
            if (!string.IsNullOrEmpty(tenantSecret))
                return tenantSecret;
        }

        if (string.IsNullOrEmpty(_settings.Secret))
        {
            throw new InvalidOperationException(
                "JWT Secret is not configured. " +
                "Set 'Jwt:Secret' in appsettings.json or provide ITenantProvider for multi-tenant.");
        }

        if (_settings.Secret.Length < 32)
        {
            throw new InvalidOperationException(
                $"JWT Secret must be at least 32 characters. Current length: {_settings.Secret.Length}");
        }

        return _settings.Secret;
    }
}