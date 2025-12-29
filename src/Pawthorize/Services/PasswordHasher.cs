using BCrypt.Net;
using Microsoft.Extensions.Logging;
using Pawthorize.Abstractions;

namespace Pawthorize.Services;

/// <summary>
/// BCrypt-based password hasher.
/// Uses adaptive hashing with configurable work factor.
/// </summary>
public class PasswordHasher : IPasswordHasher
{
    private readonly int _workFactor;
    private readonly ILogger<PasswordHasher>? _logger;

    /// <summary>
    /// Create a password hasher with specified work factor.
    /// </summary>
    /// <param name="workFactor">BCrypt work factor (10-14 recommended, default: 12)</param>
    /// <param name="logger">Optional logger for debugging and monitoring</param>
    public PasswordHasher(int workFactor = 12, ILogger<PasswordHasher>? logger = null)
    {
        if (workFactor < 10 || workFactor > 14)
        {
            logger?.LogError("Invalid work factor provided: {WorkFactor}. Must be between 10 and 14", workFactor);
            throw new ArgumentOutOfRangeException(
                nameof(workFactor),
                "Work factor must be between 10 and 14 for production use.");
        }

        _workFactor = workFactor;
        _logger = logger;

        _logger?.LogInformation("PasswordHasher initialized with work factor: {WorkFactor}", _workFactor);
    }

    /// <summary>
    /// Hash a plaintext password using BCrypt.
    /// </summary>
    /// <param name="password">Plaintext password to hash</param>
    /// <returns>BCrypt hash (includes salt and work factor)</returns>
    public string HashPassword(string password)
    {
        _logger?.LogDebug("Hashing password with BCrypt (work factor: {WorkFactor})", _workFactor);

        if (string.IsNullOrEmpty(password))
        {
            _logger?.LogError("Password hashing failed: Password is null or empty");
            throw new ArgumentNullException(nameof(password), "Password cannot be null or empty.");
        }

        try
        {
            var hash = BCrypt.Net.BCrypt.HashPassword(password, _workFactor);
            _logger?.LogDebug("Password hashed successfully");
            return hash;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during password hashing");
            throw;
        }
    }

    /// <summary>
    /// Verify a password against a BCrypt hash.
    /// </summary>
    /// <param name="password">Plaintext password to verify</param>
    /// <param name="hash">BCrypt hash to verify against</param>
    /// <returns>True if password matches hash, false otherwise</returns>
    public bool VerifyPassword(string password, string hash)
    {
        _logger?.LogDebug("Verifying password against BCrypt hash");

        if (string.IsNullOrEmpty(password))
        {
            _logger?.LogWarning("Password verification failed: Password is null or empty");
            return false;
        }

        if (string.IsNullOrEmpty(hash))
        {
            _logger?.LogWarning("Password verification failed: Hash is null or empty");
            return false;
        }

        try
        {
            var isValid = BCrypt.Net.BCrypt.Verify(password, hash);

            if (isValid)
            {
                _logger?.LogDebug("Password verification successful");
            }
            else
            {
                _logger?.LogDebug("Password verification failed: Password does not match hash");
            }

            return isValid;
        }
        catch (SaltParseException ex)
        {
            _logger?.LogWarning("Password verification failed: Invalid BCrypt hash format - {Message}", ex.Message);
            return false;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during password verification");
            throw;
        }
    }
}