using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Pawthorize.Services;

/// <summary>
/// Service for generating and validating CSRF tokens.
/// Uses cryptographically secure random token generation.
/// </summary>
public class CsrfTokenService
{
    private readonly ILogger<CsrfTokenService> _logger;

    public CsrfTokenService(ILogger<CsrfTokenService> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Generate a cryptographically secure CSRF token.
    /// </summary>
    /// <returns>Base64-encoded CSRF token</returns>
    public string GenerateToken()
    {
        _logger.LogDebug("Generating new CSRF token");

        var tokenBytes = new byte[32]; // 256 bits
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(tokenBytes);
        }

        var token = Convert.ToBase64String(tokenBytes);

        _logger.LogDebug("CSRF token generated successfully");
        return token;
    }

    /// <summary>
    /// Validate that the CSRF token from the header matches the token from the cookie.
    /// Uses constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="cookieToken">Token from cookie</param>
    /// <param name="headerToken">Token from header</param>
    /// <returns>True if tokens match, false otherwise</returns>
    public bool ValidateToken(string? cookieToken, string? headerToken)
    {
        if (string.IsNullOrEmpty(cookieToken) || string.IsNullOrEmpty(headerToken))
        {
            _logger.LogWarning("CSRF validation failed: Missing token (cookie: {HasCookie}, header: {HasHeader})",
                !string.IsNullOrEmpty(cookieToken), !string.IsNullOrEmpty(headerToken));
            return false;
        }

        // Constant-time comparison to prevent timing attacks
        var isValid = CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(cookieToken),
            System.Text.Encoding.UTF8.GetBytes(headerToken)
        );

        if (!isValid)
        {
            _logger.LogWarning("CSRF validation failed: Token mismatch");
        }
        else
        {
            _logger.LogDebug("CSRF validation successful");
        }

        return isValid;
    }
}
